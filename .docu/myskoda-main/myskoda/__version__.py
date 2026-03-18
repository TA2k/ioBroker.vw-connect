"""The package version is automatically set by uv-dynamic-versioning."""

import importlib.metadata

__version__ = importlib.metadata.version(__name__.split(".")[0])
