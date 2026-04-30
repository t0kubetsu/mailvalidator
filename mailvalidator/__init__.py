"""mailvalidator – Mail server configuration assessment library."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mailvalidator")
except PackageNotFoundError:  # pragma: no cover – only when package not installed
    __version__ = "0.1.6"

__all__ = ["__version__"]
