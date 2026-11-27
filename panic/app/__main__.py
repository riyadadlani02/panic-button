"""The app: one window showing the page in web/, talking to Python only through pywebview's in-process API."""
import os
from pathlib import Path

import webview

from panic.app import api as api_module
from panic.app.api import Api
from panic.app.bridge import Runner
from panic.cli import DEFAULT_VAULT
from panic.cli_setup import DEFAULT_KEY

WEB = Path(api_module.__file__).resolve().parent / "web"  # a bundled entry script sits elsewhere


def _dock_reopens(show) -> None:
    """pywebview has no Dock-click event, so its app delegate gains the reopen handler."""
    from webview.platforms import cocoa

    class PanicAppDelegate(cocoa.BrowserView.AppDelegate):
        def applicationShouldHandleReopen_hasVisibleWindows_(self, app, visible):
            if not visible:
                show()
            return True

    cocoa.BrowserView.AppDelegate = PanicAppDelegate


def main() -> None:
    runner = Runner(os.environ.get("PANIC_VAULT", DEFAULT_VAULT), os.environ.get("PANIC_KEYFILE", DEFAULT_KEY))
    api = Api(runner)
    window = webview.create_window("panic button", (WEB / "index.html").as_uri(), js_api=api, width=780, height=560,
                                   min_size=(640, 480), background_color="#3a6ea5")
    api._window = window
    window.events.closing += api._closing
    _dock_reopens(api._show)
    webview.start(api._launch)  # file:// page: pywebview starts no HTTP server


if __name__ == "__main__":
    main()
