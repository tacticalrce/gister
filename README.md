# Installation
Install Dependencies with PIP
* pip install pyaes
* pip install requests
* pip install pyqrcode

# Usage
First, come up with an out-of-band method of communication with your recipient.
Come up with a shared password that you will use as part of your crypto.

## gister_transmit
* gister_transmit.py \<file_to_send\>
* Enter in the shared password
* Transmit the GIST ID and MESSAGE SALT using out-of-band method to recipient

## gister_receive
* gister_receive.py \<gist_id\> \<message_salt\>
* Enter in the shared password
* If decrypted, the file will be in the current working directory

# ETC
If you'd like to view your message on GIST, just browse to https://gist.github.com/_message_id_
