"""Tests for the scanner module."""

from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock

from src.scanner import (
    _normalize_app_name,
    _parse_app_bundle,
    scan_homebrew_formulae,
)


class TestNormalizeAppName(unittest.TestCase):
    def test_removes_app_suffix(self) -> None:
        assert _normalize_app_name("Safari.app") == "Safari"

    def test_removes_helper_suffix(self) -> None:
        assert _normalize_app_name("Chrome Helper") == "Chrome"

    def test_strips_whitespace(self) -> None:
        assert _normalize_app_name("  Firefox  ") == "Firefox"

    def test_preserves_normal_name(self) -> None:
        assert _normalize_app_name("Visual Studio Code") == "Visual Studio Code"


class TestScanHomebrewFormulae(unittest.TestCase):
    @patch("src.scanner.subprocess.run")
    def test_parses_brew_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="python@3.11 3.11.7\ngit 2.43.0\ncurl 8.5.0\n",
        )
        apps = scan_homebrew_formulae()
        assert len(apps) == 3
        assert apps[0].name == "python@3.11"
        assert apps[0].version == "3.11.7"
        assert apps[0].source == "homebrew"

    @patch("src.scanner.subprocess.run")
    def test_handles_brew_not_installed(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError
        apps = scan_homebrew_formulae()
        assert apps == []

    @patch("src.scanner.subprocess.run")
    def test_handles_brew_error(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        apps = scan_homebrew_formulae()
        assert apps == []


if __name__ == "__main__":
    unittest.main()
