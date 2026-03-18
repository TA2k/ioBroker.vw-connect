"""Parse CSRF information from the website."""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from mashumaro import field_options
from mashumaro.mixins.orjson import DataClassORJSONMixin
from mashumaro.mixins.yaml import DataClassYAMLMixin

json_object = re.compile(r"window\._IDK\s=\s((?:\n|.)*?)$")


@dataclass
class TemplateModel(DataClassORJSONMixin):
    """Holds HMAC and RelayState for the authorization."""

    hmac: str
    relay_state: str = field(metadata=field_options(alias="relayState"))


@dataclass
class CSRFState(DataClassYAMLMixin):
    """Holds CSRF and embeds HMAC and RelayState for the authorization."""

    csrf: str = field(metadata=field_options(alias="csrf_token"))
    template_model: TemplateModel = field(metadata=field_options(alias="templateModel"))


class CSRFParser(HTMLParser):
    """Information such as the CSRF or the hmac will be available in the HTML.

    This will parse the information from a `<script>` tag in the HTML.
    """

    _is_script = False
    csrf_state: None | CSRFState = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],  # noqa: ARG002
    ) -> None:
        """Determine whether a script tag has been entered."""
        if tag != "script":
            return
        self._is_script = True

    def handle_endtag(self, tag: str) -> None:
        """Determine whether a script tag has been left."""
        if tag != "script":
            return
        self._is_script = False

    def handle_data(self, data: str) -> None:
        """Parse the contents of a script tag to extract csrf information."""
        if not self._is_script:
            return

        result = json_object.search(data)
        if result is None:
            return

        result = result.group(1)
        # Load the info using YAML, since the syntax used in the script is YAML compatible,
        # but not JSON compatible (missing quotes around field names, trailing commas).
        self.csrf_state = CSRFState.from_yaml(result)
