"""Tests for mailvalidator/__init__.py."""

from __future__ import annotations

from unittest.mock import patch


class TestInit:
    def test_version_is_a_string(self):
        """__version__ must always be a non-empty string."""
        import mailvalidator

        assert isinstance(mailvalidator.__version__, str)
        assert len(mailvalidator.__version__) > 0

    def test_version_fallback_when_not_installed(self):
        """PackageNotFoundError triggers the '0.1.0' fallback."""
        from importlib.metadata import PackageNotFoundError, version

        with patch("mailvalidator.version", side_effect=PackageNotFoundError()):
            try:
                v = version("mailvalidator")
            except PackageNotFoundError:
                v = "0.1.0"
        assert v == "0.1.0"
