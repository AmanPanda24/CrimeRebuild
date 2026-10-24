# Created by: Aman Kumar Panda
"""CrimeRebuild - a digital crime scene reconstruction system (MCA minor project)."""
import os

from flask import Flask

import config
from . import constants as C
from .db import Store
from .timeline import basename, human_duration


def create_app(data_dir=None):
    app = Flask(__name__,
                template_folder=os.path.join(config.BASE_DIR, "templates"),
                static_folder=os.path.join(config.BASE_DIR, "static"))
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024
    app.extensions["store"] = Store(data_dir or config.DATA_DIR)

    @app.template_filter("dt")
    def _dt(value, fmt="%d %b %Y, %H:%M:%S"):
        try:
            return value.strftime(fmt)
        except AttributeError:
            return str(value or "")

    @app.template_filter("dur")
    def _dur(seconds):
        return human_duration(seconds)

    @app.template_filter("host")
    def _host(url):
        from urllib.parse import urlparse
        return urlparse(str(url or "")).hostname or str(url or "")

    @app.template_filter("short")
    def _short(text, n=70):
        text = str(text or "")
        return text if len(text) <= n else text[: n - 1] + "\u2026"

    app.jinja_env.globals.update(
        action_meta=C.action_meta, SOURCE_ICONS=C.SOURCE_ICONS, SOURCES=C.SOURCES, KIND_CHOICES=C.KIND_CHOICES,
        SEVERITIES=C.SEVERITIES, RULE_INFO=C.RULE_INFO, basename=basename, META=config.PROJECT_META)

    from .views import bp
    app.register_blueprint(bp)
    return app
