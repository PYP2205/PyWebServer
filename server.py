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
from socketserver import TCPServer as INET_TCPServer

# Used to allow HTTPS certificates to be used, for the webserver to support only HTTPS requests.
from ssl import SSLContext

# Used for allowing the use of IPv6 addresses.
import socket

# Used to check if the path of the HTTPS certificates specified exist.
from os.path import isdir as path_exists
from os.path import isfile as file_exists
from os import chdir as change_working_directory

# Used to automatically open the webpage when the webserver is up and running.
import webbrowser as browser

# Used to get values for whitelisting, blacklisting, and prompting a remote client to login.
import json

# Used for denying, permiting, and authenticating remote users.
from authenticate import *
from log import *

with open("server_config.json", "r") as config_file:
        config_data = json.load(config_file)

class ProjectDirectoryNotFound(Exception):
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

class INET6_TCPServer(INET_TCPServer):
    """
    A class for allowing the use of IPv6 addresses to be binded onto the server.
    """
    # Sets the address family to IPv6 (or INET6).
    address_family = socket.AF_INET6

class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if config_data["main_html_file"] == "index.html" or config_data["main_html_file"] == "":
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            if file_exists(config_data["main_html_file"]):
                self.path = config_data["main_html_file"]
                SimpleHTTPRequestHandler.do_GET(self)
            
            else:
                raise FileNotFoundError(f"'{config_data['main_html_file']}' does not exist")

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
    print((HOST, PORT))

    # Makes the http server damon variable global, so when the user presses CTRL + C it will make it possible to shutdown the server.
    global httpd

    try:
        # if the user secpifies 'INET' or 'IPV4' as the server's address family, then it will bind the IPv4 address the user specified.
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":

            # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
            # Then it will prompt the user for a username and password, to access the webpage.
            if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"] and not config_data["enable_logging"]:
                with INET_TCPServer((HOST,PORT), AuthenticateRequestHandler) as httpd:

                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                        browser.open(f"http://{HOST}:{PORT}/")

                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
            # Then it will allow or deny access to the listed IP addresses in the configuration file.
            elif not config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                with INET_TCPServer((HOST,PORT), ListedIPSRequestHandler) as httpd:

                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                        browser.open(f"http://{HOST}:{PORT}/")

                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")
                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
            # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
            # And if access is permitted, then it will prompt the user to login with the username and password.
            elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                with INET_TCPServer((HOST,PORT), AuthenticateListedIPSRequestHandler) as httpd:

                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                        browser.open(f"http://{HOST}:{PORT}/")

                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")
                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            elif config_data["enable_logging"]:
                # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
                # Then it will prompt the user for a username and password, to access the webpage.
                if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
                    with INET_TCPServer((HOST,PORT), LogAuthenticateRequestHandler) as httpd:

                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                            browser.open(f"http://{HOST}:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

                # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
                # Then it will allow or deny access to the listed IP addresses in the configuration file.
                elif not config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    with INET_TCPServer((HOST,PORT), LogListedIPSRequestHandler) as httpd:

                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                            browser.open(f"http://{HOST}:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

                # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
                # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
                # And if access is permitted, then it will prompt the user to login with the username and password.
                elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    with INET_TCPServer((HOST,PORT), LogAuthenticateListedIPSRequestHandler) as httpd:

                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                            browser.open(f"http://{HOST}:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")

                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

                else:
                    with INET_TCPServer((HOST,PORT), LoggingRequestHandler) as httpd:
                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                            browser.open(f"http://{HOST}:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://{HOST}:{PORT}/'\n")
                        
                        await httpd.serve_forever()
                    
            # If the user does not want any blacklisting, whitelisting, or authentication.
            # Then it will not prompt the user to login, and will not permit or deny access to certian remote clients.
            else:
                with INET_TCPServer((HOST,PORT), RequestHandler) as httpd:

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

            # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
            # # Then it will prompt the user for a username and password, to access the webpage.
            if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST, PORT), AuthenticateRequestHandler) as httpd:
                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                        browser.open(f"http://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")

                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
            # Then it will allow or deny access to the listed IP addresses in the configuration file.
            elif not config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST, PORT), ListedIPSRequestHandler) as httpd:

                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                        browser.open(f"http://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")
                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
            # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
            # And if access is permitted, then it will prompt the user to login with the username and password.
            elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST, PORT), AuthenticateListedIPSRequestHandler) as httpd:

                    # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                    if auto_open:
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                        browser.open(f"http://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")
                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpd.serve_forever()

            elif config_data["enable_logging"]:
                # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
                # # Then it will prompt the user for a username and password, to access the webpage.
                if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST, PORT), LogAuthenticateRequestHandler) as httpd:
                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                            browser.open(f"http://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")

                        # Serves HTTP requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

                # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
                # Then it will allow or deny access to the listed IP addresses in the configuration file.
                elif not config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST, PORT), LogListedIPSRequestHandler) as httpd:

                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                            browser.open(f"http://[{HOST}]:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")
                        
                        # Serves HTTP requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

                # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
                # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
                # And if access is permitted, then it will prompt the user to login with the username and password.
                elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST, PORT), LogAuthenticateListedIPSRequestHandler) as httpd:

                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                            browser.open(f"http://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")
                        
                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()
                
                else:
                    with INET6_TCPServer((HOST, PORT), LoggingRequestHandler) as httpd:
                        # If the user sets 'auto_open' to true, then it will automatically open the webpage.
                        if auto_open:
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://[{HOST}]:{PORT}/'\n")
                            browser.open(f"http://[{HOST}]:{PORT}/")

                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'http://[{HOST}]:{PORT}/'\n")
                        
                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpd.serve_forever()

            # If the user does not want any blacklisting, whitelisting, or authentication.
            # Then it will not prompt the user to login, and will not permit or deny access to certian remote clients.
            else:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST, PORT), RequestHandler) as httpd:

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

    except InvalidAddressFamily:
        print(InvalidAddressFamily())

    # If any unknown exception is raised then it will stop the web server and show what exception has been raised.
    except Exception as error:
        httpd.shutdown()
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            print(f"\n{HOST}:{PORT} has stopped due to: {error}\n")
        else:
            print(f"\n[{HOST}]:{PORT} has stopped due to: {error}\n")

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
    ssl = SSLContext()
    try:
        # if the user secpifies 'INET' or 'IPV4' as the server's address family, then it will bind the IPv4 address the user specified.
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            # Binds the localhost ip and port to a TCP server along with the HTTP request handler.
            # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
            # Then it will prompt the user for a username and password, to access the webpage.
            if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"] and not config_data["enable_logging"]:

                with INET_TCPServer((HOST,PORT), AuthenticateRequestHandler) as httpsd:

                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                        browser.open(f"https://{HOST}:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://{HOST}:{PORT}/'\n")

                    

                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpsd.serve_forever()

            # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
            # Then it will allow or deny access to the listed IP addresses in the configuration file.
            elif config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["require_authentication"] and not config_data["enable_logging"]:
                with INET_TCPServer((HOST,PORT), ListedIPSRequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

            # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
            # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
            # And if access is permitted, then it will prompt the user to login with the username and password.
            elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                with INET_TCPServer((HOST,PORT), AuthenticateListedIPSRequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

            elif config_data["enable_logging"]:
                # Binds the localhost ip and port to a TCP server along with the HTTP request handler.
                # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
                # Then it will prompt the user for a username and password, to access the webpage.
                if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
                    with INET_TCPServer((HOST,PORT), LogAuthenticateRequestHandler) as httpsd:

                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'http://{HOST}:{PORT}/'\n")
                            browser.open(f"https://{HOST}:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://{HOST}:{PORT}/'\n")

                        

                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpsd.serve_forever()

                # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
                # Then it will allow or deny access to the listed IP addresses in the configuration file.
                elif config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["require_authentication"]:
                    with INET_TCPServer((HOST,PORT), LogListedIPSRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

                # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
                # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
                # And if access is permitted, then it will prompt the user to login with the username and password.
                elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    with INET_TCPServer((HOST,PORT), LogAuthenticateListedIPSRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                        
                        await httpsd.serve_forever()
                else:
                    with INET_TCPServer((HOST, PORT), LoggingRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

                # If the user does not want any blacklisting, whitelisting, or authentication.
                # Then it will not prompt the user to login, and will not permit or deny access to certian remote clients.
            
            else:
                with INET_TCPServer((HOST,PORT), RequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

        # If the user specifies 'INET6' or 'IPV6' as the server's address family,
        # then it will bind the sevrer with the IPV6 address specified by the user.
        elif ADDRESS_FAMILY.upper() == "INET6" or ADDRESS_FAMILY.upper() == "IPV6":

            # If the user want's to have username and password authnetication without blacklisted or whitelisted IPS.
            # Then it will prompt the user for a username and password, to access the webpage.
            if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST,PORT), AuthenticateRequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                        browser.open(f"https://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                    

                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpsd.serve_forever()

            # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
            # Then it will allow or deny access to the listed IP addresses in the configuration file.
            elif config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["require_authentication"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST,PORT), ListedIPSRequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                        browser.open(f"https://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpsd.serve_forever()
            # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
            # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
            # And if access is permitted, then it will prompt the user to login with the username and password. 
            elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["enable_logging"]:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST,PORT), AuthenticateListedIPSRequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                        print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                        browser.open(f"https://[{HOST}]:{PORT}/")


                    # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                    else:
                        print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                    
                    # Serves HTTPS requests until the user presses CTRL + C on the console.
                    await httpsd.serve_forever()

            elif config_data["enable_logging"]:
                if config_data["require_authentication"] and not config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST,PORT), LogAuthenticateRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                            browser.open(f"https://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                        

                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpsd.serve_forever()

                # If the user want's to have IP addresses to be blacklisted or whitelisted without username and password authentication.
                # Then it will allow or deny access to the listed IP addresses in the configuration file.
                elif config_data["blacklist_ips"] or config_data["whitelist_ips"] and not config_data["require_authentication"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST,PORT), LogListedIPSRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                            browser.open(f"https://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                        
                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpsd.serve_forever()
                # If the user wants username and password authentication along with blacklisting and whitelisting remote addresses.
                # Then it will allow or deny access to remote addresses depending on the mode specified in the configuration file,
                # And if access is permitted, then it will prompt the user to login with the username and password. 
                elif config_data["require_authentication"] and config_data["blacklist_ips"] or config_data["whitelist_ips"]:
                    # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                    with INET6_TCPServer((HOST,PORT), LogAuthenticateListedIPSRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                            browser.open(f"https://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")

                        
                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpsd.serve_forever()

                else:
                    with INET6_TCPServer((HOST,PORT), LoggingRequestHandler) as httpsd:
                        if CERT_FILE != None and KEY_FILE != None:

                            # If the files specified by the user exists,
                            # then it will bind the certificate and key onto the server socket.
                            if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                                ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                                httpsd.socket = ssl.wrap_socket(httpsd.socket)

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
                            print(f"\n'{HOST}' listening on: {PORT}\nOpening 'https://[{HOST}]:{PORT}/'\n")
                            browser.open(f"https://[{HOST}]:{PORT}/")


                        # If the user sets 'auto_open' to false, then it will not open the webpage when the server starts up.
                        else:
                            print(f"\n'{HOST}' listening on: {PORT}\nOn your web browser enter 'https://[{HOST}]:{PORT}/'\n")
                        
                        # Serves HTTPS requests until the user presses CTRL + C on the console.
                        await httpsd.serve_forever()

            # If the user does not want any blacklisting, whitelisting, or authentication.
            # Then it will not prompt the user to login, and will not permit or deny access to certian remote clients.
            else:
                # Binds the localhost ipv6 address and port to a TCP server along with the HTTP request handler.
                with INET6_TCPServer((HOST,PORT), RequestHandler) as httpsd:
                    if CERT_FILE != None and KEY_FILE != None:

                        # If the files specified by the user exists,
                        # then it will bind the certificate and key onto the server socket.
                        if file_exists(KEY_FILE) and file_exists(CERT_FILE):
                            ssl.load_cert_chain(CERT_FILE, KEY_FILE)
                            httpsd.socket = ssl.wrap_socket(httpsd.socket)

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

    except InvalidAddressFamily:
        print(InvalidAddressFamily())

    # If any unknown exception is raised then it will stop the web server and show what exception has been raised.
    except Exception as error:
        httpsd.shutdown()
        if ADDRESS_FAMILY.upper() == "INET" or ADDRESS_FAMILY.upper() == "IPV4":
            print(f"\n{HOST}:{PORT} has stopped due to: {error}\n")
        else:
            print(f"\n[{HOST}]:{PORT} has stopped due to: {error}\n")
