from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>HAWKWAF Lab</title>
    </head>

    <body>
        <h1>HAWKWAF Protected Application</h1>

        <p>
            This is the backend application protected
            by HAWKWAF.
        </p>

        <p>
            WAF Proxy:
            http://127.0.0.1:8080
        </p>

        <p>
            Backend:
            http://127.0.0.1:5001
        </p>
    </body>
    </html>
    """


@app.route("/search")
def search():

    query = request.args.get("q", "")

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search</title>
    </head>

    <body>
        <h1>Search Results</h1>

        <p>
            Search query:
            {query}
        </p>
    </body>
    </html>
    """


@app.route("/login")
def login():

    username = request.args.get(
        "username",
        ""
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
    </head>

    <body>
        <h1>Login</h1>

        <p>
            Username:
            {username}
        </p>
    </body>
    </html>
    """


@app.route("/api/test")
def api_test():

    return {
        "status": "success",
        "message": "HAWKWAF backend is running"
    }


if __name__ == "__main__":

    print("=" * 60)
    print("HAWKWAF Backend Application")
    print("=" * 60)
    print("Backend: http://127.0.0.1:5001")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )
