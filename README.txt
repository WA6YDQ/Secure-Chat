This is schat, a secure command line chat program.

This was written under Linux, but can be ported to any 
platform with openssl libraries available to it.


--- PREREQUISITS ---

The openssl development libraries 
(libssl-dev on a debian platform: sudo apt-get libssl-dev)
a c (gcc) compiler and make


--- BUILDING ---

Type the following:
make
sudo make install

The binaries will be in /usr/local/bin


--- RUNNING ---

schat is a chat program to connect two users over a 
TCP/IP connection. 

The first user will type schat at the command prompt.
The user will be asked for a session key which is used
to encrypt the message traffic. Both users must use the
same session key decided on earlier. 
Minimum key length is 5 characters, max is 80.

After typing in the key, the program will wait for a 
remote connection. If you want to terminate the program before 
connecting, press ctrl-C.

The remote user types:
schat [IP address of the server]

Obviously, the IP address of the server (first person to 
start schat)  must be known to the remote user, and there must
exist an open path between the two machines. The port used 
is 9001. This can be changed in the defines before building.

The remote user will be asked for a session key. After that 
the two computers will connect over TCP/IP, negeotiate the 
keys and if successful, you will be able to chat back & forth
over a secured connection.

When you wish to end the chat session, either of the users
types :CLOSE on the beginning of a blank line. Both connections 
will then terminate.

If the two keys do not match, both users will be told the 
keys don't match, but communications will continue. However the 
link will be un-encrypted. This can be useful to negeotiate
a common set of keys.

--- DETAILS ---

The session keys typed at the beginning are hashed with SHA256.
The actual key is this hash and is 256 bits long. The iv is derived 
from this hash and is 128 bits. The end to end encryption is thru
aes256. The messages are padded to modulo 16. Each line is terminated
by a linefeed. The maximum line length is set in the defines at the
top of the source code and is currently set to 1024 bytes.

If a user exits schat and immediately runs it again to start a new
session, the remote user may not be able to connect. The operating 
system (Linux in this case) will keep a TCP/IP connection open for 
a few seconds after closing. You can tell if this is the case by typing:

netstat -t tcp | grep 9001

and looking for a line with the port 9001 displayed. The State will
usually be TIME_WAIT. Just wait a few seconds (usually 15 or less) for this
to clear.

There is more documentation in the schat.c file.
