"""Run the Flask+SocketIO app."""
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    # Show the login URL on startup.
    print('''
[*] Login URL: http://127.0.0.1:5000/mscodephish/login
    \n''')
    # Use SocketIO's development server so websockets work.
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
