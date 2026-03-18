"""Unit tests for myskoda.auth."""

from json import dumps
from pathlib import Path

import aiohttp
import pytest
from aioresponses import aioresponses

from myskoda.anonymize import USER_ID
from myskoda.const import BASE_URL_IDENT, BASE_URL_SKODA, CLIENT_ID
from myskoda.myskoda import MySkodaAuthorization

FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures")


def fixture(filename: str) -> str:
    with FIXTURES_DIR.joinpath(filename).open() as file:
        return file.read()


def redirect_loop(responses: aioresponses, urls: list[str]) -> None:
    responses.post(
        url=urls[0],
        status=301,
        headers={
            "Location": urls[1],
        },
    )
    for index in range(1, len(urls) - 1):
        responses.get(
            url=urls[index],
            status=301,
            headers={
                "Location": urls[index + 1],
            },
        )


@pytest.mark.asyncio
async def test_get_tokens(responses: aioresponses) -> None:
    nonce = "abcdefghabcdefgh"
    relay_state = "d865b506bd6759b20e832c8c692c5ca2669ebd27"
    user_id = USER_ID
    hmac = "575452461e126b1873f4655918e14d0ba1a40622b768438fe4dd6d9579bc170c"

    def generate_nonce() -> str:
        return nonce

    responses.get(
        url="https://identity.vwgroup.io/oidc/v1/authorize?client_id=7f045eee-7003-4379-9968-9355ed2adb06%2540apps_vw-dilab_com&code_challenge=GB77VCZkQqwqOPgKuV1f4TxM4_OxLWfBxprenr3kfE0&code_challenge_method=s256&nonce=abcdefghabcdefgh&prompt=login&redirect_uri=myskoda%253A%252F%252Fredirect%252Flogin%252F&response_type=code&scope=address+badge+birthdate+cars+driversLicense+dealers+email+mileage+mbb+nationalIdentifier+openid+phone+profession+profile+vin",
        status=200,
        body=fixture("auth/signin.html"),
    )

    responses.post(
        url="https://identity.vwgroup.io/signin-service/v1/7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com/login/identifier",
        status=200,
        body=fixture("auth/identifier.html"),
    )

    jwt_login = "eyJ0eXAiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiOGJjMTI2Yy1lZTM2LTQwMmItODcyMy0yYzFjM2RmZjhkZWMiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiZXhwIjoxNzI4NTc2NDEwLCJpYXQiOjE3Mjg1NzYxMTAsIm5vbmNlIjoiYXNkZmdoYXNkZmdoIiwianRpIjoiOTdkODRiN2YtYzRhOC00NDcyLTllZjEtMzkyZWU4MTkwMzUwIn0.RllwxrkQTm8Z-2tIA4fGiBEP-b77QHLWzHAROhYBKVRne4s-aQdWtHFadIp0ikX6yyExeYYOVzcKBZf5FFnlaFjZB7hf5fVhfcp_TIbgs0Do_4cVz8wEFgYLFtBImeg9QhMfv11kYFEwkDBAtCeVsc6wdefIhzZrdszygW83wHN2hYuuyQYK0TWBC9yDsyQmEUuzqMkRgg0O_FdVYavJlL-orydiXn1DZiyCBfB4OHOQmbiCQr5CqMpgXV6dkE2WYi0w9NnxhtkWe-RXNpO4QzJkuMIJ1hOILIto5LM50GvO61M9hAcbp8fdx_WrTnZ1ENlsLBCojOHrvSdY4RMelA"  # noqa: E501

    redirect_loop(
        responses,
        [
            f"{BASE_URL_IDENT}/signin-service/v1/{CLIENT_ID}/login/authenticate",
            f"{BASE_URL_IDENT}/oidc/v1/oauth/sso?HMAC={hmac}&clientId=7f045eee-7003-4379-9968-9355ed2adb06%2540apps_vw-dilab_com&relayState={relay_state}&userId={user_id}",
            f"{BASE_URL_IDENT}/signin-service/v1/consent/users/{user_id}/{CLIENT_ID}?scopes=address%20badge%20birthdate%20cars%20driversLicense%20dealers%20email%20mileage%20mbb%20nationalIdentifier%20openid%20phone%20profession%20profile%20vin&relayState={relay_state}&callback={BASE_URL_IDENT}/oidc/v1/oauth/client/callback&hmac={hmac}",
            f"{BASE_URL_IDENT}/oidc/v1/oauth/client/callback/success?user_id={user_id}&client_id={CLIENT_ID}&scopes=address%20badge%20birthdate%20cars%20driversLicense%20dealers%20email%20mileage%20mbb%20nationalIdentifier%20openid%20phone%20profession%20profile%20vin&consentedScopes=address%20badge%20birthdate%20cars%20driversLicense%20dealers%20email%20mileage%20mbb%20nationalIdentifier%20openid%20phone%20profession%20profile%20vin&relayState={relay_state}&hmac={hmac}",
            f"myskoda://redirect/login/?code={jwt_login}",
        ],
    )

    access_token = "eyJ0eXAiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiOGJjMTI2Yy1lZTM2LTQwMmItODcyMy0yYzFjM2RmZjhkZWMiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJzY3AiOiJhZGRyZXNzIGJhZGdlIGJpcnRoZGF0ZSBjYXJzIGRyaXZlcnNMaWNlbnNlIGRlYWxlcnMgZW1haWwgbWlsZWFnZSBtYmIgbmF0aW9uYWxJZGVudGlmaWVyIG9wZW5pZCBwaG9uZSBwcm9mZXNzaW9uIHByb2ZpbGUgdmluIiwiYWF0IjoiaWRlbnRpdHlraXQiLCJpc3MiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8iLCJqdHQiOiJhY2Nlc3NfdG9rZW4iLCJleHAiOjE3Mjg1OTkzMTUsImlhdCI6MTcyODU5NTcxNSwibGVlIjpbIlNLT0RBIl0sImp0aSI6IjA4ZDE0NmQ2LWUyMGItNDFkNS1hNmQ1LWUzNGY5NTBmZGUyZCJ9.WexOySWyj4caq7X731273RnB7HYmZ8sh5LdXRrl9w7gEGfOuwywkNaw66QUhImZTWv-bEO3c9dyxx7Gy2_qKK74bnwJCe9cW68G6UZCw5bUvbNl4Z7k2_xX9ko14r8m4vfIksq19qTrTCW5vELbp37EC1w0EZ1BdVVCyte-VdeiVTsPwZkrMjrBBGq_PWu-kQgyWwrh2CEhSN5BR9QybDe10_-ngHF4L9ulbgp01YT4mSvHBJXwNplb3YkM9MAFBuOGe1U9F05GvP7g3JLQeN7cLEODpjPDrsg4JhLldbsZcemS4X304bhpnbWkAzPohSrzRHjb7ny64eEnN16oAdg"  # noqa: E501, S105
    refresh_token = "eyJ0eXAiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiOGJjMTI2Yy1lZTM2LTQwMmItODcyMy0yYzFjM2RmZjhkZWMiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc0NDE0NzcxNSwiaWF0IjoxNzI4NTk1NzE1LCJqdGkiOiIwOGQxNDZkNi1lMjBiLTQxZDUtYTZkNS1lMzRmOTUwZmRlMmQifQ.HaGOdGak6Ce6jJikRM8czRzDjdCpkQjJgivE7kUgtdyCF4jh4KdwNuQ3VyOFgbzj86rkpbsVGhAmhgo3VzgHqg_R--iATRZ-7m0dufzThBeI69X_7XSjisUfNEvByX9ZIMXdH1Vo0yixKmQnTDqqgTNsA6BiwKskdKwOLeiYatwgt8uLTsMaZmc4BtR90db-dlLunvMy5_PlA7NxKBtQCeMET15FAgmIsWZWb8R7SYmap9gjnptgoWQMb4TPaS7A01E8UWpq6UqR3juaMFhqSarHFOiFT_fV1e_KTUqEch08iTkWJcyXEPeWSIiMqVLvKw0nn1z5JqlGK_-msreYPQ"  # noqa: E501, S105
    id_token = "eyJ0eXAiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiaFNDV0dtMDRjYVhrcGdSSkFvRVQzUSIsInN1YiI6ImI4YmMxMjZjLWVlMzYtNDAyYi04NzIzLTJjMWMzZGZmOGRlYyIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjb3IiOiJERSIsImlzcyI6Imh0dHBzOi8vaWRlbnRpdHkudndncm91cC5pbyIsImp0dCI6ImlkX3Rva2VuIiwidHlwZSI6ImlkZW50aXR5Iiwibm9uY2UiOiI2WUFHSTVVUkUwWThQN0xDIiwibGVlIjpbIlNLT0RBIl0sImF1ZCI6WyI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJodHRwczovL2FwaS52YXMuZXUuZHAxNS52d2ctY29ubmVjdC5jb20iLCJodHRwczovL2FwaS52YXMuZXUud2NhcmRwLmlvIiwiaHR0cHM6Ly9wcm9kLmVjZS5nYXV0aC12d2FjLmNvbSIsIlZXR01CQjAxQ05BUFAxIiwiVldHTUJCMDFERUxJVjEiXSwiYWNyIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvL2Fzc3VyYW5jZS9sb2EtMiIsInVwZGF0ZWRfYXQiOjE3MTY5NzI2NjY0ODYsImFhdCI6ImlkZW50aXR5a2l0IiwiZXhwIjoxNzI4NTk5MzE1LCJpYXQiOjE3Mjg1OTU3MTUsImp0aSI6IjA4ZDE0NmQ2LWUyMGItNDFkNS1hNmQ1LWUzNGY5NTBmZGUyZCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.zfCXYJJg9eJ3L_OKnjix7bODe1jCvOaMcW0hCfyVyv28aJl2PyxxtSF4l_4zs_vnn_XFoTUnpseZDNPmFnb1roT24A_Nav5TcE-9Aj0q0527W1c-UVMa9uhlJOmv8oQ4heaEgSIYr4g7UPY05aYZ59s4y5jjMVrbJ3-8RoGXngxYNx5vDkB2W1y48ShByqVNrbzWKzkM9QkxTTH6QTP4FtvV4Ltssq4DHvfRdqqYiDa0wlvknXGOUKo6BFj0WQD5-5G909zm2d9h3XLVctSUVY8PGtu1_cmGPm52SG5E9r0Kql00I7KaYUlWZt1NNiWVeAzIbqjAXKUNFVpHwQtKqw"  # noqa: E501, S105

    responses.post(
        url=f"{BASE_URL_SKODA}/api/v1/authentication/exchange-authorization-code?tokenType=CONNECT",
        body=dumps(
            {
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "idToken": id_token,
            }
        ),
    )

    session = aiohttp.ClientSession()
    auth = MySkodaAuthorization(session, generate_nonce)

    await auth.authorize("user@example.com", "example")

    assert auth.idk_session is not None
    assert auth.idk_session.access_token == access_token
    assert auth.idk_session.refresh_token == refresh_token
    assert auth.idk_session.id_token == id_token
