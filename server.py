"""
Server

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.10.5 (64-Bit)

Description:
A simple library for handling HTTP requests,
when the HTTP webserver starts.
"""

# Used for creating a HTTP Serer and socket
import http.server
import socketserver

# Default Localhost IP '127.0.0.1', default port 8080.
async def start_http_server(HOST="127.0.0.1", PORT=8080):
    """
    Creates an HTTP Webserver with the specified Localhost IP Address,
    and the port number.
    
    Defaults:
    HOST: 127.0.0.1
    PORT: 8080
    """

    # Makes the http server damon variable global, so when the user presses CTRL + C it will make it possible to shutdown the server.
    global httpd

    # Creates a simple HTTP request handleer, for handling requests.
    request_handler = http.server.SimpleHTTPRequestHandler

    # Binds the localhost ip and port to a socket server along with the HTTP request handler.
    with socketserver.TCPServer((HOST,PORT), request_handler) as httpd:

        # Shows the user that the server is up, and provides a link for the user to copy onto their web browser's URL bar.
        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

        # Serves HTTPS requests until the user presses CTRL + C on the console.
        await httpd.serve_forever()