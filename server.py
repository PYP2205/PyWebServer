"""
Server

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.10.5 (64-Bit)

Description:
A simple library for handling HTTP requests,
when the HTTP webserver starts.
"""

# Used for creating a HTTP Serer and socket for handeling user requests.
import http.server
import socketserver

# Used for opening the webpage when the webserver starts.
import webbrowser as browser

class ProtcolNotSpecified(BaseException):
    pass
class StopHTTPWebserver(BaseException):
    pass



# Default Localhost IP '127.0.0.1', default port 8080.
async def start_http_server(HOST="127.0.0.1", PORT=8080, auto_open=False):
    """
    Creates an HTTP Webserver with the specified Localhost IP Address,
    and the port number.
    
    Defaults:
    HOST: 127.0.0.1
    PORT: 8080
    PROTCOL: TCP
    """

    # Makes the http server damon variable global, so when the user presses CTRL + C it will make it possible to shutdown the server.
    global httpd
    try:
        
        # Binds the localhost ip and port to a TCP server along with the HTTP request handler.
        with socketserver.TCPServer((HOST,PORT), http.server.SimpleHTTPRequestHandler) as httpd:
            # If the user sets 'auto_open' to true, then it will automatically open the webpage.
            if auto_open:
                print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                browser.open(f"http://{HOST}:{PORT}/")

            # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
            else:
                print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

            # Serves HTTPS requests until the user presses CTRL + C on the console.
            await httpd.serve_forever()

            
    except KeyboardInterrupt:
        print(f"\n{HOST}:{PORT} stopped!\n")
        httpd.shutdown()

    except Exception as error:
        print(f"\n{HOST}:{PORT} stopped due to: {error}\n")
