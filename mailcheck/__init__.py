"""mailcheck – Mail server configuration assessment library."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mailcheck")
except PackageNotFoundError:  # pragma: no cover – only when package not installed
    __version__ = "0.1.0"

__all__ = ["__version__"]
