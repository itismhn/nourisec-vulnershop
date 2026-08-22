from app import create_app

app = create_app()

if __name__ == "__main__":
    # host=0.0.0.0 so it's reachable inside a Docker container; keep this bound
    # to 127.0.0.1 (see docker-compose.yml port mapping) when running outside
    # a fully isolated lab network.
    app.run(host="0.0.0.0", port=5000, debug=True)
