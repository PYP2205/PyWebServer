"""
Log

Programmed by: Paramon Yevstigneyev
Programmed in: Python 3.10.6 (64-Bit)

Description:
This is a python library made for logging requests from remote clients.
It will also log ip addresses that are blacklisted, not whitelisted, authenticated,
or not authenticated.
"""

import cgi
import json
import base64
import socket
import logging
from time import ctime
from os.path import isfile as file_exists
from http.server import SimpleHTTPRequestHandler

try:
    if file_exists("server_config.json"):
        with open("server_config.json", "r") as config_file:
            config_data = json.load(config_file)
    
    else:
        raise FileNotFoundError("'server_config.json' not found")
    
    if file_exists(config_data["log_file"]):
        logging.basicConfig(filename=config_data["log_file"], filemode="a")#, level=logging.INFO)
    else:
        logging.basicConfig(filename=config_data["log_file"], filemode="w")#, level=logging.INFO)

except KeyboardInterrupt:
    logging.debug("Server stoped")

except Exception as e:
    print(f"\n{e}\n")
    logging.debug(f"Server stopped due to: {e}")

finally:
    logging.shutdown()

class LoggingRequestHandler(SimpleHTTPRequestHandler):
    """
    This will log requests from remote clients ito a log file.
    """
    def do_GET(self):
        SimpleHTTPRequestHandler.do_GET(self)
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    def do_HEAD(self):
        SimpleHTTPRequestHandler.do_HEAD(self)
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

class LogAuthenticateListedIPSRequestHandler(SimpleHTTPRequestHandler):
    """
    Authenticates users through a username and password,
    and permits or denies acess if the remote IP address
    is blacklisted or whitelisted.
    """

    # Handles HEAD requests
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles POST requests
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles authentication requests.
    def do_authhead(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm=\"{config_data["authentication_message"]}\"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles GET requests
    def do_GET(self):
        # Encodes the login info into base64
        self.key = base64.b64encode(f'{config_data["username"]}:{config_data["clear_password"]}'.encode()).decode()

        # If the user want's to blacklist and whitelist clients, then it will deny or permit access to remote
        # clients thqt are blacklisted or whitelisted on the configuration file.
        if config_data["blacklist_ips"] and config_data["whitelist_ips"]:
                self.deny_request = False
                self.blacklisted_ips = config_data["blacklisted_ips"]

                for ip in self.blacklisted_ips:
                    if ip == self.client_address[0]:
                        self.deny_request = True
                        break

                    else:
                        pass

                self.allow_request = False
                self.whitelisted_ips = config_data["whitelisted_ips"]

                for ip in self.whitelisted_ips:
                    if ip == self.client_address[0]:
                        self.allow_request = True
                        break
                    else:
                        pass

                if self.allow_request and not self.deny_request:
                    SimpleHTTPRequestHandler.do_GET(self)
                    logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

                elif self.deny_request and not self.allow_request:
                    if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, redirecting client")

                    else:
                        self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, denying access")
                else:
                    if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blackisted or not whitelisted, redirecting client")

                    else:
                        self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is backlisted or not whitelisted, denying access")

        # This will deny access to remote clients if their remote IP address is blacklisted.
        # It will also permit access to remote clients that aren't blacklisted.
        elif config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
                self.deny_request = False
                self.blacklisted_ips = config_data["blacklisted_ips"]

                for ip in self.blacklisted_ips:

                    if ip == self.client_address[0]:
                        self.deny_request = True
                        break

                    else:
                        pass

                if self.deny_request:
                    if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, redircting client")
                    else:
                        self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, denying access")
                else:
                    SimpleHTTPRequestHandler.do_GET(self)
                    logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

        # This will permit access to remote clients, if their IP address is whitelisted.
        # This will deny access to remote clients, if their IP address is not whitelisted.
        elif config_data["whitelist_ips"] and not config_data["blacklist_ips"]:
            self.allow_request = False
            self.whitelisted_ips = config_data["whitelisted_ips"]

            for ip in self.whitelisted_ips:
                if ip == self.client_address[0]:
                    self.allow_request = True
                    break
                else:
                    pass

            if self.allow_request:
                SimpleHTTPRequestHandler.do_GET(self)
                logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

            else:
                if config_data["redirect_clients"]:
                    self.send_response(301)
                    self.send_header("Location", config_data["redirect_url"])
                    self.end_headers()
                    logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is not whitelisted, redirecting client")
                else:
                    self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                    logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is not whitelisted, denying access")                

        else:
            pass

        if self.headers.get('Authorization') is None:
            self.do_authhead()
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] No authentication header recived")
        elif self.headers.get("Authorization") == "Basic " + self.key:
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] Authenticated")
            logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' has been authenticated")
            SimpleHTTPRequestHandler.do_GET(self)
            logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

        else:
            self.do_authhead()
            print((self.headers.get("Authorization")))
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] No authentication header recived")
            logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' has not been authorized")

class LogListedIPSRequestHandler(SimpleHTTPRequestHandler):
    """
    This will permit or deny access to remote clients,
    that are whitelisted or blacklisted in the configuration file.
    And it will log it into a log file.
    """

    # Handles HEAD requests.
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles POST requests
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles GET requests
    def do_GET(self):

        # If the user want's to blacklist and whitelist clients, then it will deny or permit access to remote
        # clients thqt are blacklisted or whitelisted on the configuration file.
        if config_data["blacklist_ips"] and config_data["whitelist_ips"]:
                self.deny_request = False
                self.blacklisted_ips = config_data["blacklisted_ips"]

                for ip in self.blacklisted_ips:
                    if ip == self.client_address[0]:
                        self.deny_request = True
                        break

                    else:
                        pass

                self.allow_request = False
                self.whitelisted_ips = config_data["whitelisted_ips"]

                for ip in self.whitelisted_ips:
                    if ip == self.client_address[0]:
                        self.allow_request = True
                        break
                    else:
                        pass

                if self.allow_request and not self.deny_request:
                    SimpleHTTPRequestHandler.do_GET(self)
                    logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")
                elif self.deny_request and not self.allow_request:
                    if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, redirecting client")
                    else:
                        self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, denying access")
                else:
                    if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted, redirecting client")

                    else:
                        self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted, denying access")

        # This will deny access to remote clients if their remote IP address is blacklisted.
        # It will also permit access to remote clients that aren't blacklisted.
        elif config_data["blacklist_ips"] and not config_data["whitelist_ips"]:
            self.deny_request = False
            self.blacklisted_ips = config_data["blacklisted_ips"]

            for ip in self.blacklisted_ips:
                if ip == self.client_address[0]:
                    self.deny_request = True
                    break

                else:
                    pass

            if self.deny_request:
                if config_data["redirect_clients"]:
                        self.send_response(301)
                        self.send_header("Location", config_data["redirect_url"])
                        self.end_headers()
                        logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, denying access")
                else:
                    self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                    self.end_headers()
                    logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is blacklisted, denying access")
            else:
                SimpleHTTPRequestHandler.do_GET(self)
                logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

        # This will permit access to remote clients, if their IP address is whitelisted.
        # This will deny access to remote clients, if their IP address is not whitelisted.
        elif config_data["whitelist_ips"] and not config_data["blacklist_ips"]:
            self.allow_request = False
            self.whitelisted_ips = config_data["whitelisted_ips"]

            for ip in self.whitelisted_ips:
                if ip == self.client_address[0]:
                    self.allow_request = True
                    break
                else:
                    pass

            if self.allow_request:
                SimpleHTTPRequestHandler.do_GET(self)
                logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

            else:
                if config_data["redirect_clients"]:
                    self.send_response(301)
                    self.send_header("Location", config_data["redirect_url"])
                    self.end_headers()
                    logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is not whitelisted, redircting client")
                else:
                    self.send_error(403, "Permission Denied", f"'{self.client_address[0]}:{self.client_address[1]}' is blacklisted or not whitelisted")
                    self.end_headers()
                    logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' is not whitelisted, denying access")

        else:
            SimpleHTTPRequestHandler.do_GET(self)
            logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

class LogAuthenticateRequestHandler(SimpleHTTPRequestHandler):
    """
    This class is used to log requests and authorizition from remote clients.
    """

    # Handles HEAD requests
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    # Handles POST requests
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles Authentication requests
    def do_authhead(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm=\"{config_data["authentication_message"]}\"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' {self.command} - - {self.headers.as_string()}")

    # Handles GET requests
    def do_GET(self):
        self.key = base64.b64encode(f'{config_data["username"]}:{config_data["clear_password"]}'.encode()).decode()

        if self.headers.get('Authorization') is None:
            self.do_authhead()
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] No authentication header recived")
            logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' No authentication header was recived")
        elif self.headers.get("Authorization") == "Basic "+ self.key:
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] Authenticated")
            logging.warn(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' authenticated")
            SimpleHTTPRequestHandler.do_GET(self)

        else:
            self.do_authhead()
            print(self.headers.get("Authorization"))
            print(f"{self.client_address[0]}:{self.client_address[1]} - - [{self.date_time_string()}] Not authenticated")
            logging.info(f"[{self.date_time_string()}] '{self.client_address[0]}:{self.client_address[1]}' not authenticated")
