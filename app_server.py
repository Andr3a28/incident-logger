"""
app_server.py — Entry point for Incident Logger

- Imports the Flask `app` object from app.py
- Ensures the database tables exist and seeds default roles/privileges
- Runs under Waitress if available (production-friendly) or falls back to Flask dev server
- Respects HOST, PORT, DEBUG environment variables
"""

import os
import logging

try:
    # Import the application, db, and seeding helper from your existing app.py
    from app import app, db, ensure_privileges_and_roles  # type: ignore
except Exception as ex:
    raise RuntimeError("Could not import 'app' from app.py. Make sure app.py is in the same directory.") from ex


def _init_runtime():
    """Create tables and seed default roles/privileges idempotently."""
    with app.app_context():
        try:
            db.create_all()
        except Exception as ex:
            app.logger.exception("db.create_all() failed: %s", ex)
            raise
        try:
            ensure_privileges_and_roles()
        except Exception as ex:
            # Non-fatal: the app can still run, but log it so you can investigate
            app.logger.warning("ensure_privileges_and_roles() failed (will attempt later on first request): %s", ex)


def _run_server():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"

    # Structured, concise logging
    logging.basicConfig(level=logging.INFO if not debug else logging.DEBUG,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Prefer Waitress in production if available
    use_waitress = os.environ.get("USE_WAITRESS", "1") == "1"
    if use_waitress:
        try:
            from waitress import serve  # type: ignore
            app.logger.info("Starting Waitress on %s:%s (debug=%s)", host, port, debug)
            # Note: threads=8 is a decent default; tune as appropriate
            serve(app, host=host, port=port, threads=int(os.environ.get("THREADS", "8")))
            return
        except Exception as ex:
            app.logger.warning("Waitress not available or failed to start (%s). Falling back to Flask dev server.", ex)

    # Fallback: Flask development server (do not use in Internet-facing production)
    app.logger.info("Starting Flask dev server on %s:%s (debug=%s)", host, port, debug)
    app.run(host=host, port=port, debug=debug, use_reloader=debug)


if __name__ == "__main__":
    _init_runtime()
    _run_server()
