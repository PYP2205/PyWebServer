#!/bin/bash
echo "OpenSSL HTTPS Certificate Generator"
echo
show_help() {
    echo "Generate SSL Certificates"
    echo
    echo "gen_cert.sh [Days Valid] [Certificate Name] [Key Name]"
    echo "[Days Valid]: Enter the amount of days the certificate would be valid [Required]"
    echo "[Certificate Name]: Name of the certificate file ending in .pem or .crt [Required]"
    echo "[Key Name]: name of the certificate private key file ending in .pem or .key [Required]"
    echo
}
if [ "$1" = "help" ]; then
    show_help
    exit 0

else
    if [$1 -gt 0]; then
        if ["$2" != ""]; then
            if ["$3" != ""]; then
                echo "Generating HTTPS Certificate..."
                echo
                openssl req -newkey rsa:4096  -x509  -sha512  -days $1 -nodes -out $2 -keyout $3
                echo
                echo "Certificate Generated!"
                exit 0
            else
                echo "Enter a file name for the HTTPS Certificate Key"
                echo
                exit 1
            fi
        else
            echo "Enter a file name for the HTTPS Certificate"
            echo
            exit 1
        fi
    else
        echo "Enter the amount of days the certificate would be valid"
        echo
        exit 1
    fi
fi