"""
Python WebServer

Programmed by: Paramon Yevstigneyev 
Programmed in: Python 3.10.5 (64-Bit)

Description:
This is a Python Program that can locally host a website with localhost (ex. 127.0.0.1).
Whenever you're developing a website, you can easily just have the HTML, CSS, JavaScript,
and other contents of your website to be hosted on your device. Instead of having to
put the location of the main HTML file in your web browser
"""

# Used for making a HTTP webserver, and handling HTTP requests.
import server

# Used for checking if the configuration file and the main html file exists.
import os.path

# Used for parsing the configuration file.
import json

# Used for running the asyncornous functions.
import asyncio

# Used for 
import socket

# Used for providing user input for specifying 
import argparse

try:
    # Creates an argument parser for parsing arguments.
    parser = argparse.ArgumentParser(description="A Python HTTP Webserver that will host your website.")

    # Creates an argument for storing the localhost address of the webserver.
    parser.add_argument("--ip-address", "--ip_address", help="Specify a localhost address or your IP Address for the Python HTTP Webserver.")
    # Creates an argument for stroing the port number of the webserver.
    parser.add_argument("--port-number", "--port_number", help="Secify a port number for the Python HTTP Webserver.")
    parser.add_argument("--use-client-ip-address", "--use_client_ip_address", help="If you want to host it on your network, use this option to not have it hosted locally.", action="store_true")    
    # Parsers the arguments, which will be stored into local variables. 
    args = parser.parse_args()

    # If the index.html files exists, then it will not cause any exceptions to be rasied and start the HTTP Webserver.
    if os.path.isfile("index.html"):
        if args.use_client_ip_address and args.port_number != None:
            webserver_address = socket.gethostbyname(socket.gethostname())
            webserver_port = int(args.port_number)
            asyncio.run(server.start_http_server(webserver_address, webserver_port))
            
            
        # If the user specifies the localhost ip and port number through arguments, then it will start the server.
        elif args.ip_address != None and args.port_number != None:
            webserver_address = args.ip_address
            webserver_port = int(args.port_number)
            asyncio.run(server.start_http_server(webserver_address, webserver_port))

        else:
            # If the user has a 'server_config.json' with the localhost address and port number in the same directory as the server program,
            # then it will automatically start the webserver with the localhost address and port number specified in the json configuration file.
            if os.path.isfile("server_config.json"):

                # Opens the existing json configuration file into read mode, and assigns two variables for string the localhost address and port number.
                with open("server_config.json", "r") as config_file:
                    config_data = json.load(config_file)
                    
                    use_client_address = config_data["use_client_address"]
                    
                    if use_client_address:
                        webserver_address = socket.gethostbyname(socket.gethostname())
                        webserver_port = config_data["webserver_port"]
                    else:
                        webserver_address = config_data["webserver_ip"]
                        webserver_port = config_data["webserver_port"]

                # Once the config data is stored, then it will start the webserver.
                asyncio.run(server.start_http_server(webserver_address, webserver_port))

            # If the user does not provide a localhost address and port number through arguments, or through the json config file.
            # Then it will prompt the user for a localhost address and port number. Finally it will start the websever and listen for requests.
            else:
                webserver_address = str(input("Enter a local host IP for the HTTP webserver (default. 127.0.0.1): "))
                webserver_port = int(input("Enter a port number for the HTTP webserver (default 8080): "))
                asyncio.run(server.start_http_server(webserver_address, webserver_port))

    # If the index.html file does not exist, then it will riase the FileNotFoundError exception and tell the user that the index.html does not exist in their local directory.
    else:
        raise FileNotFoundError

# When the user presses CTRL + C on their console, then it will shutdown the HTTP Server.
except KeyboardInterrupt:
    server.httpd.shutdown()
    print(f"\n{webserver_address}:{webserver_port} Stopped!\n")

# If the user doesn't enter a port number then it will call the server function, and set 8080 as its port number.
except TypeError:
    webserver_port = 8080
    asyncio.run(server.start_http_server(webserver_address, webserver_port))

except OSError as error:
    # If the index.html file does not exist, then it will not start the server.
    if not os.path.isfile("index.html"):
        print("\n'index.html' not found!\n")
    
    # If the server socket fails to bind the localhost address and port, then it will notify the user.
    else:
        print(f"\nFailed to start server!\nError: {error}\n")

# If any unknown error occurs, then it will shutdown the webserver and show the user what exception has been rasied.
except Exception as error:
    server.httpd.shutdown()
    print(f"\n{webserver_address}:{webserver_port} has stopped due to: {error}\n")

# Once the server is stopped after handeling the 'KeyboardInterrupt' exception,
# it will delete the variables that store the localhost ip and port.
finally:
    del webserver_address, webserver_port
