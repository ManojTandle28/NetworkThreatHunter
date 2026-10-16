import os
import socket
from app import create_app

app = create_app()

def find_available_port(preferred_port=5000):
    """Return PORT environment variable if specified, or auto-detect first free port."""
    if 'PORT' in os.environ:
        return int(os.environ['PORT'])
    for port in [preferred_port, 5001, 5005, 8080, 8000]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return 5001

if __name__ == '__main__':
    port = find_available_port(5000)
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 'yes')
    print(f"[*] NetworkThreatHunter starting on http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=debug)
