from app.main import app, socketio
from app.config import Config

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=Config.DEBUG)