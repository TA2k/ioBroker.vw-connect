"""Handles authorization to the MySkoda API."""

import base64
import hashlib
import logging
from abc import ABC, abstractmethod
from asyncio import Lock
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlparse

import jwt
from aiohttp import ClientSession, FormData, InvalidUrlClientError
from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin

from myskoda.auth.csrf_parser import CSRFParser, CSRFState
from myskoda.auth.utils import generate_nonce
from myskoda.const import BASE_URL_IDENT, MAX_RETRIES

_LOGGER = logging.getLogger(__name__)


refresh_token_lock = Lock()


@dataclass
class IDKSession(DataClassORJSONMixin):
    """Stores the JWT tokens relevant for a session at the IDK server.

    Can be used to authorized and refresh the authorization token.
    """

    access_token: str = field(metadata=field_options(alias="accessToken"))
    refresh_token: str = field(metadata=field_options(alias="refreshToken"))
    id_token: str = field(metadata=field_options(alias="idToken"))


class Authorization(ABC):
    """Class that holds Authorization information and authorization state of the session."""

    # TODO @dvx75: I think this should be much more abstract and void of most concrete
    # implementations. At least not have dependencies on ClientSession.
    # Maybe also move to Protocol instead of ABC.

    session: ClientSession
    testsuite: bool
    idk_session: IDKSession | None = None

    def __init__(
        self,
        session: ClientSession,
        generate_nonce: Callable[[], str] = generate_nonce,
        testsuite: bool = False,
    ) -> None:
        self.session = session
        self.generate_nonce = generate_nonce
        self.testsuite = testsuite

    def _extract_csrf(self, html: str) -> CSRFState:
        parser = CSRFParser()
        parser.feed(html)

        if parser.csrf_state is None:
            raise CSRFError

        return parser.csrf_state

    @property
    @abstractmethod
    def client_id(self) -> str | None:
        """The client ID used for this authorization.

        Must be implemented by the per-brand subclass.
        """

    @property
    @abstractmethod
    def redirect_uri(self) -> str | None:
        """The redirect URI used for this authorization.

        Must be implemented by the per-brand subclass.
        """

    @property
    @abstractmethod
    def base_url(self) -> str | None:
        """The base URL used for all API requests after authorization.

        Must be implemented by the per-brand subclass.
        """

    @property
    def app_prefix(self) -> str:
        """Calculate the app prefix."""
        if not self.redirect_uri:
            raise BrandError
        split_str = "://"
        if split_str not in self.redirect_uri:
            raise ValueError

        return self.redirect_uri.split(split_str)[0]

    async def authorize(self, email: str, password: str) -> None:
        """Authorize on the VW IDK servers."""
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        self.email = email
        self.password = password

        try:
            self.idk_session = await self._get_idk_session()
        except (InvalidUrlClientError, KeyError) as ex:
            raise AuthorizationFailedError from ex

        if self.idk_session is None:
            raise AuthorizationFailedError

    async def authorize_refresh_token(self, refresh_token: str) -> None:
        """Authorize by exchanging an existing OpenID refresh token.

        This bypasses the username/password flow and initializes `idk_session`
        by calling the refresh endpoint with the provided refresh token.
        """
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        if self.is_refresh_token_expired(refresh_token) and not self.testsuite:
            log_str = "Refresh token has expired. Please authorize using username/password."
            _LOGGER.error(log_str)
            raise TokenExpiredError

        async with refresh_token_lock:
            response = await self.session.post(
                f"{self.base_url}/api/v1/authentication/refresh-token?tokenType=CONNECT",
                json={"token": refresh_token},
            )
            if not response.ok:
                _LOGGER.error("Refresh token authorization failed with status %s", response.status)
                raise AuthorizationFailedError
            try:
                self.idk_session = IDKSession.from_json(await response.text())
            except Exception as ex:
                _LOGGER.exception("Failed to parse tokens from refresh endpoint.")
                raise AuthorizationFailedError from ex

    async def _initial_oidc_authorize(self, verifier: str) -> CSRFState:
        """First step of the login process.

        This calls the route for initial authorization,
        which will contain the initial SSO information such as the CSRF or the HMAC.
        """
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        # A SHA256 hash of the random "verifier" string will be transmitted as a challenge.
        # This is part of the OAUTH2 PKCE process. It is described here in detail:
        # https://www.oauth.com/oauth2-servers/pkce/authorization-request/
        verifier_hash = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = (
            base64.b64encode(verifier_hash)
            .decode("utf-8")
            .replace("+", "-")
            .replace("/", "_")
            .rstrip("=")
        )

        params = {
            "client_id": self.client_id,
            "nonce": self.generate_nonce(),
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            # OpenID scopes. Can be found here: https://identity.vwgroup.io/.well-known/openid-configuration
            "scope": "address badge birthdate cars driversLicense dealers email mileage mbb nationalIdentifier openid phone profession profile vin",  # noqa: E501
            "code_challenge": challenge,
            "code_challenge_method": "s256",
            "prompt": "login",
        }

        async with self.session.get(
            f"{BASE_URL_IDENT}/oidc/v1/authorize", params=params
        ) as response:
            return self._extract_csrf(await response.text())

    async def _enter_email_address(self, csrf: CSRFState) -> CSRFState:
        """Second step in the login process.

        Will post only the email address to the backend.
        The password will follow in a later request.
        """
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        form_data = FormData()
        form_data.add_field("relayState", csrf.template_model.relay_state)
        form_data.add_field("email", self.email)
        form_data.add_field("hmac", csrf.template_model.hmac)
        form_data.add_field("_csrf", csrf.csrf)

        async with self.session.post(
            f"{BASE_URL_IDENT}/signin-service/v1/{self.client_id}/login/identifier",
            data=form_data(),
        ) as response:
            return self._extract_csrf(await response.text())

    async def _enter_password(self, csrf: CSRFState) -> str:
        """Third step in the login process.

        Post both the email address and the password to the backend.
        This will return a token which can then be used in the skoda services to authenticate.
        """
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        form_data = FormData()
        form_data.add_field("relayState", csrf.template_model.relay_state)
        form_data.add_field("email", self.email)
        form_data.add_field("password", self.password)
        form_data.add_field("hmac", csrf.template_model.hmac)
        form_data.add_field("_csrf", csrf.csrf)

        # The following is a bit hacky:
        # The backend will redirect multiple times after the login was successful.
        # The last redirect will redirect back to the `MySkoda` app in Android,
        # using the `myskoda://` URL prefix.
        # The following loop will follow all redirects until the last redirect to `myskoda://` is
        # encountered. This last URL will contain the authentication code token.
        try:
            async with self.session.post(
                f"{BASE_URL_IDENT}/signin-service/v1/{self.client_id}/login/authenticate",
                data=form_data(),
                allow_redirects=False,
                raise_for_status=True,
            ) as auth_response:
                location = auth_response.headers["Location"]
                while not location.startswith(self.app_prefix):
                    if "terms-and-conditions" in location:
                        raise TermsAndConditionsError(location)
                    if "consent/marketing" in location:
                        raise MarketingConsentError(location)
                    async with self.session.get(location, allow_redirects=False) as response:
                        location = response.headers["Location"]
        except InvalidUrlClientError:
            _LOGGER.exception("Error occurred while sending password. Password may be incorrect.")
            raise

        # The last redirection starting with `myskoda://` was encountered.
        # The URI will contain the code as a query parameter.
        try:
            query_params = dict(parse_qsl(urlparse(location).query))
            return query_params["code"]
        except (KeyError, TypeError) as err:
            message = f"Failed to extract authorization code from {location}"
            raise AuthorizationError(message) from err

    async def _exchange_auth_code_for_idk_session(self, code: str, verifier: str) -> IDKSession:
        """Exchange the ident login code for an auth token from Skoda.

        This will return multiple tokens, such as an access token and a refresh token.
        """
        if not self.redirect_uri or not self.base_url:
            raise BrandError

        json_data = {
            "code": code,
            "redirectUri": self.redirect_uri,
            "verifier": verifier,
        }

        async with self.session.post(
            f"{self.base_url}/api/v1/authentication/exchange-authorization-code?tokenType=CONNECT",
            json=json_data,
            allow_redirects=False,
        ) as response:
            return IDKSession.from_json(await response.text())

    async def _get_idk_session(self) -> IDKSession:
        """Perform the full login process.

        Must be called before any other methods on the class can be called.
        """
        # Generate a random string for the OAUTH2 PKCE challenge.
        # (https://www.oauth.com/oauth2-servers/pkce/authorization-request/)
        verifier = self.generate_nonce()

        # Call the initial OIDC (OpenID Connect) authorization,
        # giving us the initial SSO information.
        # The full flow is explain a little bit here:
        # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
        login_meta = await self._initial_oidc_authorize(verifier)

        # Use the information to login with the email address,
        # which is an extra step before the actual login.
        login_meta = await self._enter_email_address(login_meta)

        # Perform the actual login which will result in a token that can be exchanged for
        # an access token at the Skoda server.
        authentication_code = await self._enter_password(login_meta)

        # Exchange the token for access and refresh tokens (JWT format).
        return await self._exchange_auth_code_for_idk_session(authentication_code, verifier)

    def is_token_expired(self) -> bool:
        """Check whether the login token is expired."""
        if not self.idk_session:
            raise NotAuthorizedError

        meta = jwt.decode(self.idk_session.access_token, options={"verify_signature": False})
        expiry = datetime.fromtimestamp(float(meta.get("exp", "0")), tz=UTC)
        return datetime.now(tz=UTC) + timedelta(minutes=10) > expiry

    def is_refresh_token_expired(self, refresh_token: str | None = None) -> bool:
        """Check whether the refresh token is expired."""
        if refresh_token:
            meta = jwt.decode(refresh_token, options={"verify_signature": False})

        elif not self.idk_session:
            raise NotAuthorizedError
        else:
            meta = jwt.decode(self.idk_session.refresh_token, options={"verify_signature": False})

        expiry = datetime.fromtimestamp(float(meta.get("exp", "0")), tz=UTC)
        return datetime.now(tz=UTC) + timedelta(minutes=1) > expiry

    async def _perform_refresh_token(self) -> bool:
        if not self.client_id or not self.redirect_uri or not self.base_url:
            raise BrandError

        if not self.idk_session:
            raise NotAuthorizedError

        if not self.is_token_expired():
            return True

        async with self.session.post(
            f"{self.base_url}/api/v1/authentication/refresh-token?tokenType=CONNECT",
            json={"token": self.idk_session.refresh_token},
        ) as response:
            if not response.ok:
                return False
            try:
                self.idk_session = IDKSession.from_json(await response.text())
            except Exception:
                _LOGGER.exception("Failed to parse tokens from refresh endpoint.")
                return False
            else:
                return True

    async def refresh_token(self) -> None:
        """Refresh the authorization token.

        This will consume the `refresh_token` and exchange it for a new set of tokens.
        """
        async with refresh_token_lock:
            for attempt in range(MAX_RETRIES):
                if await self._perform_refresh_token():
                    return
                _LOGGER.warning(
                    "Retrying failed request to refresh token (%d/%d). Retrying...",
                    attempt,
                    MAX_RETRIES,
                )

            _LOGGER.error("Refreshing token failed after %d attempts.", MAX_RETRIES)
            _LOGGER.info("Trying to recover by logging in again...")

            try:
                idk_session = await self._get_idk_session()
            except Exception:
                _LOGGER.exception("Failed to login.")
            else:
                self.idk_session = idk_session
                _LOGGER.info("Successfully recovered by logging in.")
                return

    async def get_access_token(self) -> str:
        """Get the access token.

        Use this method instead of using `access_token` directly. It will automatically
        check if the JWT token is about to expire and refresh it using the `refresh_token`.
        """
        if self.idk_session is None:
            raise NotAuthorizedError

        if self.is_token_expired():
            _LOGGER.info("Token expired. Refreshing IDK access token")
            await self.refresh_token()
        return self.idk_session.access_token

    async def get_refresh_token(self) -> str:
        """Get the refresh token.

        Use this method instead of using `refresh_token` directly. In future releases it will
        check if the JWT token is about to expire and refresh it.
        """
        if self.idk_session is None:
            raise NotAuthorizedError

        return self.idk_session.refresh_token


class AuthorizationError(Exception):
    """Error to indicate that something unexpected happened during authorization."""


class InvalidStatusError(Exception):
    """An invalid HTTP status code was received."""

    def __init__(self, status: int) -> None:
        super().__init__(f"Received invalid HTTP status code {status}.")


class CSRFError(Exception):
    """Failed to parse the CSRF information from the website."""


class NotAuthorizedError(Exception):
    """Not authorized.

    Did you forget to call Authorization.authorize()?
    """


class AuthorizationFailedError(Exception):
    """Failed to authorize."""


class TermsAndConditionsError(Exception):
    """Redirect to Terms and Conditions was encountered."""


class MarketingConsentError(Exception):
    """Redirect to Marketing Consent encountered."""


class BrandError(Exception):
    """No valid brand configuration found."""


class TokenExpiredError(Exception):
    """Presented token has expired."""
