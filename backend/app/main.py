
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from app.routes.socket_events import register_socket_events
from app.config import Config

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins=Config.CORS_ORIGINS, async_mode="threading")


register_socket_events(socketio)