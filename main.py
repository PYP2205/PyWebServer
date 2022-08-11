"""
Python WebServer

Programmed by: Paramon Yevstigneyev 
Programmed in: Python 3.10.6 (64-Bit)

Description:
This is a Python Program that can locally host a website with localhost (ex. 127.0.0.1).
Whenever you're developing a website, you can easily just have the HTML, CSS, JavaScript,
and other contents of your website to be locally hosted on your device. Instead of having to
put the location of the main HTML file in your web browser
"""

# Used for making a HTTP(S) webserver, and handling HTTP(S) requests.
from server import *

# Used for checking if the configuration file and the main html file exists.
from os.path import isfile as file_exists

# Used for parsing the configuration file.
import json

# Used for running the asyncornous functions.
from asyncio import run as run_async

# Used for providing user input for specifying.
import argparse

# Used for binding the webserver IP Address with the user's ip address.
import socket

import sys

if __name__ == "__main__":

    try:
        # Creates an argument parser for parsing arguments.
        parser = argparse.ArgumentParser(description="A Python HTTP and HTTPS Webserver that will locally host a website.")

        # Creates an argument for storing the localhost address of the webserver.
        parser.add_argument("--ip-address", "--ip_address", help="Specify a localhost address for the Python HTTP(S) Webserver. [Required, if not using client's address]")
        # Creates an argument for storing the port number of the webserver.
        parser.add_argument("--port", "--port", help="Secify a port number for the Python HTTP(S) Webserver. [Required]")
        # Creates an argument for storing the address family.
        parser.add_argument("--address-family", "--address_family", help="Specify the type of IP address being used [Required, INET/IPV4 INET6/IPV6]")
        # Creates an argument for storing the protcol.
        parser.add_argument("--protocol", "--protocol", help="HTTP or HTTPS.")
        # Stores the path of the HTTPS certificate file.
        parser.add_argument("--cert-file", "--cert_file", help="Path the the HTTPS certificate file [Required if the protocol is set to HTTPS]")
        # Stores the path of the HTTPS certificate key file.
        parser.add_argument("--key-file", "--key_file", help="Path to the HTTPS certificate key [Required if the protcol is set to HTTPS].")
        # If specified, it will automatically open the web page when the webserver is up.
        parser.add_argument("--auto-open", "--auto_open", help="Automatically opens the page whent the server starts.", action="store_true")
        # If specified, it will bind the webserver's ip address with the user's ip address (IPv4 only).
        parser.add_argument("--use-host-address", "--use_host_address", help="If specified, it the server will be binded with the cleint's ip address [INET/IPV4 Only]", action="store_true")
        
        # Parsers the arguments, which will be stored into local variables. 
        args = parser.parse_args()

        # If the index.html files exists, then it will not cause any exceptions to be rasied and start the HTTP Webserver.
        if file_exists("index.html"):

            # If the user specifies the localhost ip and port number through arguments, then it will start the server.
            if args.ip_address != None and args.port != None or args.use_host_address and args.port != None:
                
                # If the user does want's to use their machine's ip address for the server,
                # then it will get the uer's ipv4 address and sets the address family as 'INET'.
                if args.use_host_address:
                    webserver_ip = str(socket.gethostbyname(socket.gethostname()))
                    address_family = "INET"
                
                # If the user specifies their own ip address then it will bind the server,
                # with the address specified.
                else:
                    webserver_ip = str(args.ip_address)

                webserver_port = int(args.port)
                address_family = str(args.address_family)
                webserver_protocol = str(args.protocol)
                auto_open = bool(args.auto_open)
                
                # If the user sets the protcol to be HTTP, then it will start the server with the provided arguments.
                if webserver_protocol.upper() == "HTTP":
                    run_async(start_http_server(webserver_ip, webserver_port, address_family, auto_open))
                
                # If the user sets the protcol to HTTPS, then it will start the server with the provided arguments and the HTTPS certitifcate specified.
                elif webserver_protocol.upper() == "HTTPS":    
                    https_cert = str(args.cert_file)
                    https_cert_key = str(args.key_file)
                    run_async(start_https_server(webserver_ip, webserver_port, address_family, https_cert, https_cert_key, auto_open))
                
                # If the protcol specified is not valid, then it will let the user know that it is invalid.
                else:
                    raise InvalidProtocolSpecified("Invaild server protcol")

            else:
                # If the user has a 'server_config.json' with the localhost address and port number in the same directory as the server program,
                # then it will automatically start the webserver with the localhost address and port number specified in the json configuration file.
                if file_exists("server_config.json"):

                    # Opens the existing json configuration file into read mode, and assigns two variables for string the localhost address and port number.
                    config_file = open("server_config.json", "r")
                    config_data = json.load(config_file)

                    # If the user wants to use their own ip address for the server,
                    # then it will get the user's ip address and bind into into the server.
                    if config_data["use_host_ip"]:
                        webserver_ip = str(socket.gethostbyname(socket.gethostname()))
                        webserver_port = int(config_data["webserver_port"])
                        address_family = str(config_data["address_family"])
                        webserver_protocol = str(config_data["webserver_protocol"])
                        auto_open = bool(config_data["auto_open"])
                        
                        # If the user sets the protcol to be HTTP, then it will start the server with the provided arguments.
                        if webserver_protocol.upper() == "HTTP":
                            run_async(start_http_server(webserver_ip, webserver_port, address_family, auto_open))
                        
                        # If the user sets the protcol to HTTPS, then it will start the server with the provided arguments and the HTTPS certitifcate specified.
                        elif webserver_protocol.upper() == "HTTPS":
                            https_cert = config_data["path_to_cert"]
                            https_cert_key = config_data["path_to_key"]
                            run_async(start_https_server(webserver_ip, webserver_port, address_family, https_cert, https_cert_key, auto_open))
                        
                        # If the protcol specified is not valid, then it will let the user know that it is invalid.
                        else:
                            raise InvalidProtocolSpecified("Invaild server protcol")

                    # If the user does not want to bind the server's ip address with their own ip address.
                    # Then it will bind the ip address specified in the configuration file.
                    else:
                        webserver_ip = str(config_data["webserver_ip"])
                        webserver_port = int(config_data["webserver_port"])
                        address_family = str(config_data["address_family"])
                        webserver_protocol = str(config_data["webserver_protocol"])
                        auto_open = bool(config_data["auto_open"])
                        
                        # If the user sets the protcol to be HTTP, then it will start the server with the provided arguments.
                        if webserver_protocol.upper() == "HTTP":
                            run_async(start_http_server(webserver_ip, webserver_port, address_family, auto_open))
                        
                        # If the user sets the protcol to HTTPS, then it will start the server with the provided arguments and the HTTPS certitifcate specified.
                        elif webserver_protocol.upper() == "HTTPS":
                            https_cert = str(config_data["path_to_cert"])
                            https_cert_key = str(config_data["path_to_key"])
                            run_async(start_https_server(webserver_ip, webserver_port, address_family, https_cert, https_cert_key, auto_open))
                        
                        # If the protcol specified is not valid, then it will let the user know that it is invalid.
                        else:
                            raise InvalidProtocolSpecified("Invalid server protocol")

                # If the user does not provide a localhost address and port number through arguments, or through the json config file.
                # Then it will prompt the user for a localhost address and port number. Finally it will start the websever and listen for requests.
                else:
                    address_family = str(input("Enter the type of IP address for the server (default INET): "))
                    webserver_ip = str(input("Enter an IP address for the HTTP/HTTPS webserver (default 127.0.0.1): "))
                    webserver_port = int(input("Enter a port number for the HTTP/HTTPS webserver (default 8080): "))
                    webserver_protocol = str(input("Enter the protocol to use for the webserver (Certificate must be present if you are using HTTPS): "))
                    
                    # If the user sets the protcol to be HTTP, then it will start the server with the provided arguments.
                    if webserver_protocol.upper() == "HTTP":
                        run_async(start_http_server(webserver_ip, webserver_port, address_family))
                    
                     # If the user sets the protcol to HTTPS, then it will start the server with the provided arguments and the HTTPS certitifcate specified.
                    elif webserver_protocol.upper() == "HTTPS":
                        https_cert = str(input("Enter the path of the HTTPS certificate: "))
                        https_cert_key = str(input("Enter the path of the HTTPS certificate key: "))
                        run_async(start_https_server(webserver_ip, webserver_port, address_family, https_cert, https_cert_key))

                    # If the protcol specified is not valid, then it will let the user know that it is invalid.
                    else:
                        raise InvalidProtocolSpecified("Invalid server protocol")
                    
                    

        # If the index.html file does not exist, then it will riase the FileNotFoundError exception and tell the user that the index.html does not exist in their local directory.
        else:
            raise FileNotFoundError("'index.html' was not found!")

    # When the user presses CTRL + C on their console, then it will shutdown the HTTP or HTTPS Server.
    except KeyboardInterrupt:
        if webserver_protocol.upper() == "HTTP":
            httpd.shutdown()
            if address_family.upper() == "INET" or address_family.upper() == "IPV4":
                print(f"\n{webserver_ip}:{webserver_port} stopped!\n")
            else:
                print(f"\n[{webserver_ip}]:{webserver_port} stopped!\n")
        elif webserver_protocol.upper() == "HTTPS":
            httpsd.shutdown()
            
            if address_family.upper() == "INET" or address_family.upper() == "IPV4":
                print(f"\n{webserver_ip}:{webserver_port} stopped!\n")
            else:
                print(f"\n[{webserver_ip}]:{webserver_port} stopped!\n")
            
        print(f"\n{webserver_ip}:{webserver_port} Stopped!\n")

    # If the user doesn't enter a port number then it will call the server function, and set 8080 as its port number.
    except TypeError:
        webserver_ip = "127.0.01"
        webserver_port = 8080
        address_family = "INET"
        run_async(start_http_server(webserver_ip, webserver_port, address_family))

    except OSError as error:
        # If the index.html file does not exist, then it will not start the server.
        if not file_exists("index.html"):
            pass

        # If the server socket fails to bind the localhost address and port, then it will notify the user.
        else:
            print(f"\nFailed to start server!\nError: {error}\n")

    # If any unknown error occurs, then it will shutdown the webserver and show the user what exception has been rasied.
    except Exception as error:
        if webserver_protocol.upper() == "HTTP":
            httpd.shutdown()
            if address_family.upper() == "INET" or address_family.upper() == "IPV4":
                print(f"\n{webserver_ip}:{webserver_port} has stopped due to: {error}\n")
            else:
                print(f"\n[{webserver_ip}]:{webserver_port} has stopped due to: {error}\n")
        elif webserver_protocol.upper() == "HTTPS":
            httpsd.shutdown()
            if address_family.upper() == "INET" or address_family.upper() == "IPV4":
                print(f"\n{webserver_ip}:{webserver_port} has stopped due to: {error}\n")
            else:
                print(f"\n[{webserver_ip}]:{webserver_port} has stopped due to: {error}\n")


    # Once the server is stopped after handeling the 'KeyboardInterrupt' exception or any other exception,
    # it will delete the variables that store the localhost ip and port. Then it will end the program.
    finally:
        if webserver_protocol.upper() == "HTTPS":
            del webserver_ip, webserver_port, address_family, webserver_protocol, https_cert, https_cert_key

        else:
            del webserver_ip, webserver_port, address_family, webserver_protocol
            
        sys.exit()
else:
    print("\nNot '__main__'\n")
    sys.exit()
