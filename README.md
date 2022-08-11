# PyWebServer
A Python Webserver program that would locally host a website you're working on your computer, or even on your local network. Made without any third-party Python libraries, and made with only python libraries that are built into Python 3.

# Features
* The IP address of the server can be IPv4/INET or IPv6/INET6.
* The server can not only be an HTTP server, but it can be a HTTPS server (make sure you specify the certificate and key).
* Server IP (localhost or your own) and port number can be specified through commandline arguments.
* Server IP (localhost or your own) and port number can be specified through a json configuration file. So you can have the server automatically startup when the program is executed.
* The webserver bind the server ip address with the user's ip address (IPv4/INET only) to have the webpage be hosted on the user's local network (may not work on Windows if you have multiple network adapters such as virtual adapters).
* Automatically opens the webpage when the user starts the webserver.

# Requirements
* Python 3.8 or later for the lastest patches. (Tested with Python 3.8, 3.9, and 3.10).
* Windows 10 or later, Linux, or Mac OS (Tested on Windows and Linux).
* 'index.html' and any other files in the same directory as the webserver program or source files (the HTML document must be named as 'index.html').
# Limitations
* If you're going to use an IPv6 address as the server's ip address, then you must specify a localhost ipv6 address [ex. ::, ::1].
* To generate SSL/HTTPS certificates and keys, you must generate it with OpenSSL on Linux. Or if you're on Windows, then use a third party version of OpenSSL or use MSYS to generate a HTTPS certificate and Key on Windows for the server.

# Instructions
When starting the webserver, you can specify which ip address and port to bind to the server through arguments. By the 'server_config.json' file [recommended], which there you specify which localhost ip and port you want to use. Or if you don't specify anything through arguments or the configuration file, then the program will prompt you for the ip address and port number. If nothing is specified through any of those methods, then it will bind the server with '127.0.0.1' as its ip address, and bind with port 8080. Make sure you specify an address family of the IP address specified, if you use something like '127.0.0.1', then you must specify either 'INET' or 'IPV4' (not case senstive) as the address family. If you use '::1' then you must specify 'INET6' or 'IPV6' (again not case senstive) as the address family.

If you are going to host an HTTPS webstie with this program, then you must specify the HTTPS certificate and its key for it to be able to host your website with HTTPS. To generate the HTTPS certificate and key, use the Linux bash script provided to generate a certificate. If you're on Windows, then use MSys to generate a certificate for the server.

Once you start the server, it will be listing for any requests you send and handle them. The program will display the URL to enter into your browser, you can copy and paste it or set the program to automattically open up the webpage for you.

If you would like your webpage to be automatically up when the program is executed, then I would recommend using the 'server_config.json' file for specifying the server IP, port number, use your own ip address, or to have it automatically open up when the server starts up.

# Configuration File
* "auto_open": set this to 'true' or false if you want your webpage to be automatically opened when the server starts up [Optional].
* "use_host_ip": Specify true or false if you want the program to bind the server's ip with your machine's ip address. [Optional, but only works with IPv4/INET addresses].
* "webserver_ip": Specify a localhost ip or your own ip for the server to bind. [only required if 'use_client_address' is set to false. And only localhost IPv6/INET6 addresses work for IPv6].
* "webserver_port" : Specify a port number like 8080 or 8000 for the server to bind and listen for requests [Required]
* "webserver_protocol" : Enter 'HTTP' or 'HTTPS' to se the type of protcol to use for the server [Required, not case senstive].
* "address_family" : Enter 'PV4' 'INET', 'IPV6', or 'INET6' (not case sentive) as the server's address family. If you use an IPv4 address as the server's ip address, then you must set 'INET' or 'IPV4' as the server's address family. Otherwise if you use an IPv6 address as the server's ip address, then you must specify 'INET6' or 'IPV6' as the server's address family.
* "path_to_cert" : Path of the HTTPS certificate file [required if HTTPS is used as the server's protocol].
* "path_to_key" : Path of the HTTPS certificate key file [required if HTTPS is used as the server's protocol].

# Command-Line Arguments
* "--ip-address": Specify your IPv4 address, a localhost IPv4 address, or a IPv6 localhost address. [Required]
* "--port": Specify a port number for the server to listen to requests, ex. 8080, 8000, etc. [Required]
* "--protocol": Specify HTTP or HTTPS for the webserver protocol [Required].
* "--cert-file": Specify the path of a HTTPS certificate file [Required if using HTTPS]
* "--key-file": Specify the path of a HTTPS certificate key file [Required if using HTTPS]
* "--address-family": Specify the address family of the ip address being used [Required].
* "--auto-open": If specified, then it will open the webpage when the server starts up. [Optional]
* "--use-host-address": If specified, then it will bind the server with your machines IP address [Optional, only works with IPv4]
