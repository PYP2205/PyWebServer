"""
Server

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.10.6 (64-Bit)

Description:
A simple library for handling HTTP and HTTPS requests,
when the HTTP or HTTPS webserver is configured and running.
"""

# Used for creating a HTTP(S) Serer and socket
from http.server import SimpleHTTPRequestHandler as RequestHandler
from socketserver import TCPServer as INET_TCP_Server

# Used to allow HTTPS certificates to be used, for the webserver to support only HTTPS requests.
from ssl import wrap_socket as bind_certificate

# Used for allowing the use of IPv6 addresses.
from socket import AddressFamily

# Used to check if the path of the HTTPS certificates specified exist.
from os.path import isfile as file_exists

# Used to automatically open the webpage when the webserver is up and running.
import webbrowser as browser

class ProtcolNotSpecified(Exception):
    """
    A custom Exception that will be raised if
    no protcol for the web server is not specified.
    """
    pass

class InvalidProtocolSpecified(Exception):
    """
    A custom Exception that will be raised if 'HTTP' or 'HTTPS'
    is not specified for the web server's protocol.
    """    
    pass

class ertificateNotFound(Exception):
    """
    A custom exception that will be raised if an HTTPS certificate is not found.
    """
    
    pass

class InvalidAddressFamily(Exception):
    """
    A Custom exception that will be raised if the address family specified is invalid.
    """
    
    pass

class INET6_TCP_Server(INET_TCP_Server):
    """
    A class for allowing the use of IPv6 addresses to be binded onto the server.
    """
    # Sets the address family to IPv6 (or INET6).
    address_family = AddressFamily.AF_INET6

# An async function for listening and handling for HTTP requests.
async def start_http_server(HOST="127.0.0.1", PORT=8080, ADDRESS_FAMILY="INET", auto_open=True):
    """
    Creates an HTTP Webserver with the specified Localhost IP Address,
    and the port number.
    
    Defaults:
    HOST: 127.0.0.1
    PORT: 8080
    ADDRESS FAMILY: INET (or IPv4)
    auto_open: False
    """

    # Makes the http server damon variable global, so when the user presses CTRL + C it will make it possible to shutdown the server.
    global httpd
    
    try:
        # if the user secpifies 'INET' or 'IPV4' as the server's address family, then it will bind the IPv4 address the user specified.
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            # Binds the localhost ip and port to a TCP server along with the HTTP request handler.
            with INET_TCP_Server((HOST,PORT), RequestHandler) as httpd:

                # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                if auto_open:
                    print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                    browser.open(f"http://{HOST}:{PORT}/")


                # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                else:
                    print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")


                # Serves HTTPS requests until the user presses CTRL + C on the console.
                await httpd.serve_forever()
        
        # If the user specifies 'INET6' or 'IPV6' as the server's address family,
        # then it will bind the sevrer with the IPV6 address specified by the user.
        elif ADDRESS_FAMILY.upper() == "INET6" or ADDRESS_FAMILY.upper() == "IPV6":
            
            # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
            with INET6_TCP_Server((HOST,PORT), RequestHandler) as httpd:

                # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                if auto_open:
                    print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                    browser.open(f"http://[{HOST}]:{PORT}/")


                # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                else:
                    print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")

                # Serves HTTPS requests until the user presses CTRL + C on the console.
                await httpd.serve_forever()

        # If the user does not enter a valid address family, then it will raise an exception
        # letting the user know that they entered an invalid address fmaily,
        else:
            raise InvalidAddressFamily("Invalid address family specified")  
    except KeyboardInterrupt:
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            print(f"\n{HOST}:{PORT} stopped!\n")
            httpd.shutdown()
        else:
            print(f"[{HOST}]:{PORT} stopped!\n")
            httpd.shutdown()
        
    # If any unknown exception is raised then it will stop the web server and show what exception has been raised.
    except Exception as error:
        print(f"\n{HOST}:{PORT} stopped due to: {error}\n")

# An async function for listening and handling HTTPS requests.
async def start_https_server(HOST="127.0.0.1", PORT=8080, ADDRESS_FAMILY="INET", CERT_FILE=None, KEY_FILE=None, auto_open=True):
    """
    Creates an HTTP Webserver with the specified Localhost IP Address,
    and the port number.
    
    Defaults:
    HOST: 127.0.0.1
    PORT: 8080
    ADDRESS FAMILY: INET (or IPv4)
    CERT_FILE: https_crt.pem
    KEY_FILE: https_key.pem
    auto_open: False
    """

    # Makes the https server damon variable global, so when the user presses CTRL + C it will make it possible to shutdown the server.
    global httpsd
    try:
        # If the user sets 'INET' or 'IPV4' as the address family,
        # then it will bind the server with the IPv4 address specified by the user. 
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            
            # Binds the localhost ip and port to a TCP server along with the HTTP request handler.
            with INET_TCP_Server((HOST,PORT), RequestHandler) as httpsd:
                if CERT_FILE != None and KEY_FILE != None:
                    
                    # If the files specified by the user exists,
                    # then it will bind the certificate and key onto the server socket.
                    if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                        httpsd.socket = bind_certificate(httpsd.socket, keyfile=KEY_FILE, certfile=CERT_FILE,server_side=True)
                    
                    # If the HTTPS Certificate or Key does not exist,
                    # then it will raise an exception letting the user know that the files do not exist.
                    else:
                        raise CertificateNotFound("HTTPS Certificate not found!")
                    
                # If no HTTPS Certificate file or key file is not specified,
                # then it will raise an exception letting the user know that there was no file(s) specified.
                else:
                    raise CertificateNotFound("No HTTPS Certificate specified!")

                # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                if auto_open:
                    print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://{HOST}:{PORT}/'\n")
                    browser.open(f"https://{HOST}:{PORT}/")

                # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                else:
                    print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://{HOST}:{PORT}/'\n")

                # Serves HTTPS requests until the user presses CTRL + C on the console.
                await httpsd.serve_forever()
        
        # If the user specifies 'INET6' or 'IPV6' as the server's address family, then it will create an IPV6 HTTPS websever.
        elif ADDRESS_FAMILY.upper() == "INET6" or ADDRESS_FAMILY.upper() == "IPV6":
            
            # Binds the localhost ip and port to a TCP server along with the HTTPS request handler.
            with INET6_TCP_Server((HOST,PORT), RequestHandler) as httpsd:
                if CERT_FILE != None and KEY_FILE != None:
                    
                    # If the user specfies an existant path of the HTTPS certificate and key,
                    # then it will bind the HTTPS certificate onto the server socket.
                    if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                        httpsd.socket = bind_certificate(httpsd.socket, keyfile=KEY_FILE, certfile=CERT_FILE,server_side=True)
                    
                    # If the path of the HTTPS certificate or key does not exist, then it will let the user know that it does not exist.
                    else:
                        raise CertificateNotFound("HTTPS Certificate not found!")
                # if no HTTPS certificate or key is specified, then it will let the user know that it does no key or ceriticate was specified.
                else:
                    raise CertificateNotFound("No HTTPS Certificate specified!")

                # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                if auto_open:
                    print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                    browser.open(f"https://[{HOST}]:{PORT}/")

                # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                else:
                    print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                # Serves HTTPS requests until the user presses CTRL + C on the console.
                await httpsd.serve_forever()

        # If the user does not enter a valid address family, then it will raise an exception
        # letting the user know that they entered an invalid address fmaily,
        else:
            raise InvalidAddressFamily("Invalid address family specified")

    # If the user wishes to stop listening for requests, then by pressing CTRL + C it will shutdown the server.
    except KeyboardInterrupt:
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            print(f"\n{HOST}:{PORT} stopped!\n")
            httpsd.shutdown()
        else:
            print(f"[{HOST}]:{PORT} stoppped!\n")
            httpsd.shutdown()
        
    # If any unknown exception is raised then it will stop the web server and show what exception has been raised.
    except Exception as error:
        print(f"\n{HOST}:{PORT} stopped due to: {error}\n")
