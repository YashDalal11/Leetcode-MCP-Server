import os
import json
import time
import base64
import httpx
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse

class TokenManager:
    def __init__(self, filename=".tokens.json"):
        # Store tokens in the same directory as main.py/auth.py
        self.filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

    def save_tokens(self, access_token: str, refresh_token: str):
        data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "updated_at": time.time()
        }
        with open(self.filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load_tokens(self) -> dict:
        if not os.path.exists(self.filepath):
            return {}
        try:
            with open(self.filepath, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def logout(self):
        if os.path.exists(self.filepath):
            try:
                os.remove(self.filepath)
            except Exception:
                pass

    def get_jwt_payload(self, token: str) -> dict:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}
            payload_b64 = parts[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            return json.loads(payload_json)
        except Exception:
            return {}

    def is_token_expired(self, token: str) -> bool:
        payload = self.get_jwt_payload(token)
        exp = payload.get('exp', 0)
        # Token is considered expired if it expires in less than 60 seconds
        return exp < time.time() + 60

    async def get_access_token(self, backend_url: str) -> str:
        tokens = self.load_tokens()
        if not tokens:
            return None

        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        if not access_token:
            return None

        if not self.is_token_expired(access_token):
            return access_token

        # Access token is expired, try to refresh it using the refresh token
        if not refresh_token:
            return None

        new_access, new_refresh = await self.refresh_tokens(backend_url, refresh_token)
        if new_access:
            return new_access

        return None

    async def refresh_tokens(self, backend_url: str, refresh_token: str) -> tuple:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{backend_url}/auth/refresh",
                    json={"refresh_token": refresh_token},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    new_access = data.get("access_token")
                    new_refresh = data.get("refresh_token") or refresh_token
                    self.save_tokens(new_access, new_refresh)
                    return new_access, new_refresh
        except Exception as e:
            print(f"Error refreshing tokens: {e}")
        return None, None


token_manager = TokenManager()
oauth_server = None


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence HTTP logs to avoid cluttering the MCP stdio/stderr
        pass

    def do_GET(self):
        parsed_url = urlparse.urlparse(self.path)
        path = parsed_url.path
        query = urlparse.parse_qs(parsed_url.query)

        if path == "/callback":
            # The backend redirects here with hash parameters (#access_token=...&refresh_token=...)
            # Since the browser does not send hash fragments to the server, we return a small HTML page
            # containing JavaScript to read the hash parameters and redirect them to the /save endpoint.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Completing Authentication...</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f0f2f5; }
                    .container { text-align: center; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
                    .spinner { border: 4px solid rgba(0, 0, 0, 0.1); width: 36px; height: 36px; border-radius: 50%; border-left-color: #f39c12; animation: spin 1s linear infinite; display: inline-block; }
                    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                    h2 { color: #1a1a1a; margin-top: 20px; font-size: 20px; }
                    p { color: #666; font-size: 14px; }
                </style>
                <script>
                    window.onload = function() {
                        const hash = window.location.hash.substring(1);
                        if (hash) {
                            window.location.href = "/save?" + hash;
                        } else {
                            document.getElementById('status').innerText = 'Authentication Error';
                            document.getElementById('message').innerText = 'No tokens were found in the URL. Please try logging in again.';
                            document.getElementById('spinner').style.display = 'none';
                        }
                    };
                </script>
            </head>
            <body>
                <div class="container">
                    <div id="spinner" class="spinner"></div>
                    <h2 id="status">Authenticating...</h2>
                    <p id="message">Exchanging credentials with LeetCode MCP Server.</p>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        elif path == "/save":
            # Extract access_token and refresh_token from the query string
            access_token = query.get("access_token", [None])[0]
            refresh_token = query.get("refresh_token", [None])[0]

            if access_token and refresh_token:
                # Save the tokens
                token_manager.save_tokens(access_token, refresh_token)
                
                # Serve a success message to the browser
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Successful</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #e8f5e9; }
                        .container { text-align: center; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 420px; width: 100%; border-top: 5px solid #2e7d32; }
                        .icon { font-size: 54px; color: #2e7d32; margin-bottom: 10px; }
                        h2 { color: #1b5e20; margin: 10px 0; font-size: 22px; }
                        p { color: #4e4e4e; font-size: 14px; line-height: 1.6; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="icon">✓</div>
                        <h2>Login Successful!</h2>
                        <p>Your Google account has been successfully linked to LeetCode MCP Server.</p>
                        <p>You can close this tab and return to your IDE or Chat Assistant.</p>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(html.encode("utf-8"))
                
                # Notify completion and stop the server after a short delay
                global oauth_server
                if oauth_server:
                    oauth_server.set_completed()
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                html = """
                <!DOCTYPE html>
                <html>
                <head><title>Login Failed</title></head>
                <body>
                    <h2>Login Failed</h2>
                    <p>Missing access token or refresh token in URL parameters.</p>
                </body>
                </html>
                """
                self.wfile.write(html.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


class OAuthServer:
    def __init__(self, port=8555):
        self.port = port
        self.server = None
        self.thread = None
        self.completed_event = threading.Event()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        
        self.completed_event.clear()
        
        def run_server():
            try:
                self.server = HTTPServer(("localhost", self.port), CallbackHandler)
                self.server.serve_forever()
            except Exception as e:
                # Silently handle startup failures (e.g. port already in use)
                pass

        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        if self.thread:
            self.thread = None

    def set_completed(self):
        self.completed_event.set()
        # Automatically stop the server after a brief delay so the response finishes rendering
        def delayed_stop():
            time.sleep(2.0)
            self.stop()
        threading.Thread(target=delayed_stop, daemon=True).start()


def get_oauth_server(port=8555) -> OAuthServer:
    global oauth_server
    if oauth_server is None:
        oauth_server = OAuthServer(port)
    return oauth_server
