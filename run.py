import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # host=0.0.0.0 so it's reachable inside a Docker container; keep this bound
    # to 127.0.0.1 (see docker-compose.yml port mapping) when running outside
    # a fully isolated lab network. PORT is overridable (e.g. macOS reserves
    # 5000 for AirPlay Receiver on some systems).
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
