"""Flask application factory."""
from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from config import Config
from werkzeug.security import generate_password_hash

db = SQLAlchemy()
socketio = SocketIO(async_mode="threading")


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app, resources={r"/*": {"origins": "*"}})
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    with app.app_context():
        # Import models so SQLAlchemy is aware of them, then create tables.
        from app import models  # noqa: F401
        db.create_all()
        # Ensure at least one admin user exists.
        from app.models import User
        if User.query.count() == 0:
            default = User(
                username="mscodephish",
                password_hash=generate_password_hash("mscodephish"),
                must_change_password=True,
            )
            db.session.add(default)
            db.session.commit()

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    from app.scheduler import init_scheduler
    init_scheduler(app)

    return app