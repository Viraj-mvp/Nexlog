"""
interface/ â€” NexLog Layer 5: User Interfaces

Sub-packages:
    gui/    PySide6 desktop application (requires: pip install PySide6)
    web/    FastAPI REST API + stdlib http.server fallback

Quick launch:
    # GUI desktop app
    from interface.gui import launch
    launch()

    # FastAPI REST server
    from interface.web.api import create_app
    app = create_app("case.facase")

    # Stdlib server (no FastAPI required)
    from interface.web.api import run_stdlib_server
    run_stdlib_server(port=8000)
"""
