#!/usr/bin/env python3
"""OPNsense API helper. No args -> Textual TUI. Args -> direct CLI (no Textual needed)."""

import os
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
VENV_DIR = SCRIPT_DIR / ".venv"
FALLBACK_VENV_DIR = Path.home() / ".local" / "share" / "lazysense" / "venv"


def _venv_python(venv_dir):
    candidate = venv_dir / "bin" / "python3"
    return candidate if candidate.is_file() else None


def _bootstrap_tui():
    """Ensure textual is importable, creating/using a local venv if needed, then exec into it."""
    try:
        import textual  # noqa: F401
        return
    except ImportError:
        pass

    if os.environ.get("LAZYSENSE_REEXEC") == "1":
        print(
            "Error: textual still not importable after re-exec into venv. "
            f"Try installing manually: {VENV_DIR}/bin/pip install textual",
            file=sys.stderr,
        )
        sys.exit(1)

    venv_dir = VENV_DIR
    if not os.access(SCRIPT_DIR, os.W_OK):
        venv_dir = FALLBACK_VENV_DIR
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        print(f"Note: {SCRIPT_DIR} not writable, using {venv_dir} instead.", file=sys.stderr)

    python_bin = _venv_python(venv_dir)

    if python_bin is None:
        print(f"Setting up local environment in {venv_dir} (first run only)...", file=sys.stderr)
        import subprocess
        import venv as venv_module

        try:
            venv_module.create(str(venv_dir), with_pip=True)
        except Exception as exc:
            print(f"Error: failed to create venv at {venv_dir}: {exc}", file=sys.stderr)
            sys.exit(1)

        python_bin = _venv_python(venv_dir)
        if python_bin is None:
            print(f"Error: venv created but no python3 found at {venv_dir}/bin/python3", file=sys.stderr)
            sys.exit(1)

        pip_bin = venv_dir / "bin" / "pip"
        print("Installing textual...", file=sys.stderr)
        result = subprocess.run([str(pip_bin), "install", "-q", "textual"])
        if result.returncode != 0:
            print(
                "Error: failed to install textual (no internet?). "
                f"Use the CLI directly (lazysense.py <command>) or install manually: {pip_bin} install textual",
                file=sys.stderr,
            )
            sys.exit(1)

    os.environ["LAZYSENSE_REEXEC"] = "1"
    os.execv(str(python_bin), [str(python_bin), str(SCRIPT_PATH)] + sys.argv[1:])


def main():
    if sys.version_info < (3, 8):
        print("Error: lazysense.py requires Python 3.8+", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        from lazysense import cli
        cli.main(sys.argv[1:])
        return

    _bootstrap_tui()
    from lazysense import tui
    tui.run()


if __name__ == "__main__":
    main()
