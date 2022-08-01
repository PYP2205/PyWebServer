# ParaYev-WebServer
A simple Python Webserver that would locally host a website you're working on your computer, or even on your local network.

# Features
* Server IP (localhost or your own) and port number can be specified through commandline arguments.
* Server IP (localhost or your own) and port number can be specified through a json configuration file. So you can have the server automatically startup when the program is executed.

# Requirements
* Python 3.8 or later (Tested with Python 3.8, 3.9, and 3.10).
* Windows 10 or later, Linux, or Mac OS.
* 'index.html' or any other files in the same directory as the webserver program or source files.

# Instructions
When starting the webserver, you can specify which ip address and port to bind to the server through arguments. By the 'server_config.json' file [recommended], which there you specify which localhost ip and port you want to use. Or if you don't specify anything through arguments or the configuration file, then the program will prompt you for the ip address and port number. If nothing is specified through any of those methods, then it will bind the server with '127.0.0.1' as its ip address, and bind with port 8080.

Once you start the server, it will be listing for any requests you send and handle them. The program will display the URL to enter into your browser, you can copy and paste it or set the program to automattically open up the webpage for you.

If you would like your webpage to be automatically up when the program is executed, then I would recommend using the 'server_config.json' file for specifying the server IP, port number, use your own ip address, or to have it automatically open up when the server starts up.

# Configuration File
* "open_page_on_startup" : Specify true or false if you want the program to automatically open the web page for you when the server starts up. [Optional]
* "use_client_address" : Specify true or false if you want the program to bind the server's ip with your machine's ip address. [Optional, but may not work properly if your have multiple network adapters like virtual adapters]
* "server_ip" : Specify a localhost ip or your own ip for the server to bind. [not required if you want it to use your machine's ip address]
* "server_port" : Specify a port number like 8080 or 8000 for the server to bind. [Required]
