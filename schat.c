/* chat - encrypted chat app
 * (C) kurt theis 3/2022
 *
 * This is a chat program. When starting, you will be prompted for a session key.
 * The session key is any maximum 80 character string. The session keys MUST
 * match at each end. A one-time-pad can be useful as a source of session keys.
 * The actual key and the iv are derived from the session key using SHA256.
 *
 * If the session keys match on both ends, the chat session will continue
 * using aes256 to end-end encrypt the messages. 
 *
 * If the session keys do not match, you will still be able to communicate but in plaintext
 * mode (non-encrypted). This is useful so you can settle on a session key and restart.
 *
 * To exit the chat program, either user will send ':CLOSE' (no quotes used).
 * This will end the connection and exit the program on both sides.
 *
 * The longest message is defined by BUFFSIZE below. 
 *
 * There are two users in chat: the server and the client.
 * The server starts the chat program and waits for a remote connection.
 * The server user types 'chat' (no quotes used) and waits for a connection.
 * The client types 'chat [ip address of server]' (no quotes used) to establish 
 * an end to end connection. The IP address of the server must be known to the client.
 *
 * Crypto routines from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 * Any other non-original code is attributed on the source.
 *
 */

#define PORT 9001			/* server port - this server listens on this port # */
#define BUFFSIZE 1024			/* max size-1 used for keyboard input */

/* network, general use */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <wiringPi.h>
#include <time.h>

/* openssl */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

void handleErrors(void) {
	return;
}

/* encrypt a string using aes256 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this case we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* decrypt a string using aes256 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this case we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}



/* main code module */
int main(int argc, char *argv[]) {

	/* openssl variables */
	// !!!NOTE!!! key and iv as presented here are NOT USED. The actual values are derived below
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";  // 256 bit key
	unsigned char *iv = (unsigned char *)"0123456789012345";   // 128 bit IV

	unsigned char *plaintext;
	unsigned char ciphertext[BUFFSIZE];
	unsigned char decryptedtext[BUFFSIZE];

	int decryptedtext_len, ciphertext_len;
	int ENCFLAG = 1;		// 0=not encrypted, 1=encrypted, derived below in key negotiation

	/* network variables (client/server) */
	int listenfd = 0, connfd = 0;
	int n=0;
	int FLAG = 0;

	struct sockaddr_in serv_addr, cli_addr;
  	int clilen = sizeof(cli_addr);
  	char sendBuff[BUFFSIZE], recvBuff[BUFFSIZE], kbdBuff[BUFFSIZE];

	/* network (client) variables */
	char SERVER_ADDR[64];		// ip address or domain name	
	int bytesAvailable = 0;

	FILE *fd;		// used to transfer files
	int kbd=0;		// file handle for keyboard

	OpenSSL_add_all_algorithms();		// make avail all ssl 
	ERR_load_crypto_strings();

	/* get the key/password from the user */
	char session_key[81]; 
	while (strlen(session_key) < 5) {
		memset(session_key,0,sizeof(session_key));
		fprintf(stdout,"enter a (min 5/max 80 char) session key: ");
		fgets(session_key,80,stdin);
	}

	/* compute hash of session_key */
	/* we use the sha256 hash of the entered key as the actual session key */
	/* and the hash of the session key as the iv */
	
	// the openssl sha routines come from https://stackoverflow.com/questions/918676/generate-sha-hash-in-c-using-openssl-library

	unsigned char session_key_hash[80];
	SHA256(session_key,strlen(session_key),session_key_hash);
	// debugging to view the hex value of the hash
	//for (int i=0; i<32; i++) printf("%02X", session_key_hash[i]); 
	//printf("\n");
	key = session_key_hash;

	/* compute iv */
	unsigned session_iv[81];
	unsigned char session_iv_hash[80];
	SHA256(session_key_hash,32,session_iv_hash);
	for (int i=16; i<80; i++) session_iv_hash[i] = '\0';	// mask off all but the first 16 bytes (128 bits)
	iv = session_iv_hash;


	/* are we called as a server, or client? Clients supply an IP address. */

	if (argc == 1) goto SERVER;
	if (argc == 2) goto CLIENT;
	// else show usage
	printf("usage: chat 			Run as a chat server\n");
	printf("       chat [ip address]	Run as a client w/ip address as the server\n");
	return 1;


/* ------------------------------------------------------------------ */

CLIENT:	// run this when contacing a server (the CLIENT is the remote end)
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	memset(sendBuff, 0, sizeof(sendBuff));
	memset(recvBuff, 0, sizeof(recvBuff));

	/* set up the network port */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	strcpy(SERVER_ADDR,argv[1]);
	serv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
	if (connect(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr,"Connection Failed\n");
		fprintf(stderr,"Address used: [%s]\n",SERVER_ADDR);
		fprintf(stderr,"Try using an IP address instead of a domain name\n");
		fprintf(stderr,"and verify the other end is actually listening for a connection.\n");
		return 1;
	}

	/* open the keyboard, non-blocking for 2-way comms */
        kbd = open("/dev/stdin", O_RDONLY | O_NONBLOCK);
        if (kbd == 0) {
        fprintf(stderr,"Error opening stdin\n");
        return 1;
        }
	
	/* set socket for non-blocking */
        fcntl(listenfd, F_SETFL, O_NONBLOCK);
	
	/* connected - tell user */
	fprintf(stdout,"Connected - type :CLOSE to terminate\n");

	/* negotiate keys, set up encryption */
	fprintf(stdout,"negotiating keys...\n");

	// wait for encrypted string
	while (n < 1) {
		n = read(listenfd, recvBuff, sizeof(recvBuff));
	}
	decryptedtext_len = decrypt(recvBuff, n, key, iv, decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';

	if (strcmp(decryptedtext,"the quick brown fox")==0)
		ENCFLAG = 1;
	else {
		fprintf(stdout,"key exchange failed\n");
		ENCFLAG = 0;
	}

	// re-encrypt the received string
	plaintext = decryptedtext; 
	memset(ciphertext,0,sizeof(ciphertext));
	ciphertext_len = encrypt(plaintext, decryptedtext_len, key, iv, ciphertext);
	
	// write back to server
	int err = write(listenfd, ciphertext, ciphertext_len);	

	/* show encryption status */
	if (!ENCFLAG) fprintf(stdout,"\n[plaintext mode]\n");
	if (ENCFLAG) fprintf(stdout,"\n[encrypted mode]\n");

	// connected - run loop until :CLOSED is seen
	while (1) {
		usleep(2000);		// keep cpu cycles down
		n = 0; 
		memset(recvBuff,0,sizeof(recvBuff));     // start fresh
		memset(kbdBuff,0,sizeof(kbdBuff));
		memset(decryptedtext,0,sizeof(decryptedtext));
		memset(ciphertext,0,sizeof(ciphertext));
		
		/* test keyboard */
		n = read(kbd, kbdBuff, sizeof(kbdBuff)-1);
		if (n > 0) {
			kbdBuff[n] = 0;
			if (!ENCFLAG) {		// non-encrypted
				write(listenfd, kbdBuff, strlen(kbdBuff));
				if (strncmp(kbdBuff, ":CLOSE",6)==0) {
					close(listenfd);
					return 0;
				}
				continue;
			}
			if (ENCFLAG) {
                             	int err = 0;
			     	// plaintext in kbdBuff - encrypt it
				plaintext = kbdBuff;            // assign pointers
                                ciphertext_len = encrypt(plaintext, strlen((char *)plaintext),key, iv, ciphertext);
                                err = write(listenfd, ciphertext, ciphertext_len);
                                if (err != ciphertext_len) 
					printf("ciphertext_len=%d, write len=%d\n",ciphertext_len,err);
				if (strncmp(kbdBuff,":CLOSE",6)==0) {
					close(listenfd);
					return 0;
				}
				continue;
                        }
			fprintf(stdout,"unknown error\n"); fflush(stdout);
			continue;
		}
		
		/* test newtwork data*/
		n = read(listenfd, recvBuff, sizeof(recvBuff)-1);
		if (n < 1) continue;

		/* get/display network text */
		recvBuff[n] = 0;
		if (!ENCFLAG) {		// show unencrypted text 
			fprintf(stdout,"pt> %s",recvBuff);
			fflush(stdout);
			if (strncmp(recvBuff,":CLOSE",6)==0) {
				close(listenfd);
				close(kbd);
				return 0;
			}
		}
		if (ENCFLAG) {
			decryptedtext_len = decrypt(recvBuff, n, key, iv, decryptedtext);
    			/* Add a NULL terminator. We are expecting printable text */
   			decryptedtext[decryptedtext_len] = '\0';
			fprintf(stdout,"> %s",decryptedtext);
			fflush(stdout);
			if (strncmp(decryptedtext,":CLOSE",6)==0) {
				close(listenfd);
				close(kbd);
				return 0;
			}
		}

		
		
		// test what was sent (this is a just-in-case the above failed somehow)
		if (strncmp(recvBuff,":CLOSE",6)==0) {	// end connection and shut down
			close(listenfd);
			close(kbd);
			printf("exiting connection\n");
			return 0;
		}
		continue;

		 
	}




/* ------------------------------------------------------------------ */

SERVER:	// run this when acting as a server

	/* initialize tcp/ip port */
	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&serv_addr, 0, sizeof(serv_addr));
	memset(sendBuff, 0, sizeof(sendBuff));
	memset(recvBuff, 0, sizeof(recvBuff));

	serv_addr.sin_family = AF_INET;
  	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* same as 0.0.0.0 */
  	serv_addr.sin_port = htons(PORT);

	/* assign a port name */
	bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));

	if(listen(listenfd, 0) == -1){	// the 0 is the backlog of other connections
		printf("ERROR - Failed to listen\n");	/* this may happen due to bad permissions, etc */
      		return 1;
  	}

	fprintf(stdout,"Server Running. Listening on port %d\n",PORT);

	/* port is set up and listening */

	while (1) {
		memset(kbdBuff,0,sizeof(kbdBuff));
		memset(recvBuff,0,sizeof(recvBuff));	// start fresh

		fprintf(stdout,"Waiting for connection (^C to exit)\n");
		connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &clilen); // accept awaiting request
		/* use: fcntl(socket, F_SETFL, O_NONBLOCK); for non-blocking */

		/* user connected to us */
		fprintf(stdout,"Connection request from %s\n", inet_ntoa(cli_addr.sin_addr));
		fprintf(stdout,"Connected - type :CLOSE to terminate\n");

		/* verify encryption works end-end */
		fprintf(stdout,"negotiating keys...\n");

		// send an encrypted string
		strcpy(kbdBuff,"the quick brown fox");
		plaintext = kbdBuff;
		ciphertext_len = encrypt(plaintext, strlen((char *)plaintext),key, iv, ciphertext);
		err = write(connfd, ciphertext, ciphertext_len);
		if (err != ciphertext_len) {
			fprintf(stderr,"error setting up path\n");
			return 1;
		}

		// see if return string matches
		n = 0;
		while (n < 1) {
			n = read(connfd, recvBuff, sizeof(recvBuff)-1);
		}
		decryptedtext_len = decrypt(recvBuff, n, key, iv, decryptedtext);
		decryptedtext[decryptedtext_len] = '\0';
		if (strcmp(decryptedtext,kbdBuff)==0) 
			ENCFLAG = 1;
		else {
			fprintf(stdout,"key exchange failed\n");
			ENCFLAG = 0;
		}


		/* get ready to accept text and commands from remote end */
		memset(recvBuff,0,sizeof(recvBuff));
		memset(kbdBuff,0,sizeof(kbdBuff));
		memset(decryptedtext,0,sizeof(decryptedtext));
		memset(ciphertext,0,sizeof(ciphertext));
		n = 0;

		/* open the keyboard, non-blocking for 2-way comms */
		kbd = open("/dev/stdin", O_RDONLY | O_NONBLOCK);
		if (kbd == 0) {
			fprintf(stderr,"Error opening stdin\n");
			return 1;
		}

		/* set socket for non-blocking */
		fcntl(connfd, F_SETFL, O_NONBLOCK);

		/* show encryption status */
		if (!ENCFLAG) fprintf(stdout,"\n[plaintext mode]\n");
		if (ENCFLAG) fprintf(stdout,"\n[encrypted mode]\n");

		while (1) {
			usleep(20000);		// keep cpu load down
			n = 0; 
			memset(recvBuff,0,sizeof(recvBuff));
			memset(kbdBuff,0,sizeof(kbdBuff));		// start fresh
			memset(ciphertext,0,sizeof(ciphertext));
			memset(decryptedtext,0,sizeof(decryptedtext));

			/* test keyboard. If entered chars, encrypt and send */
			n = read(kbd, kbdBuff, sizeof(kbdBuff)-1);
			if (n > 0) {
				kbdBuff[n] = 0;
				if (ENCFLAG) {	// plaintext in kbdBuff - encrypt it
					int err = 0;
					plaintext = kbdBuff;		// assign pointers
					ciphertext_len = encrypt(plaintext, strlen((char *)plaintext),key, iv, ciphertext);
					err = write(connfd, ciphertext, ciphertext_len);
					if (err != ciphertext_len)
                                        	fprintf(stderr,"ciphertext_len=%d, write len=%d\n",ciphertext_len,err);
					if (strncmp(kbdBuff,":CLOSE",6)==0) {
						close(connfd);
						close(kbd);
						return 0;
					}
					continue;
				}
				if (!ENCFLAG) {
					write(connfd, kbdBuff, strlen(kbdBuff));
					if (strncmp(kbdBuff,":CLOSE",6)==0) {
						close(connfd);
						close(kbd);
						return 0;
					}
					continue;
				}
				fprintf(stderr,"unknown error\n");
				continue;
			}
			
			/* test for remote data */
			n = read(connfd, recvBuff, sizeof(recvBuff)-1);
			if (n < 1) continue;
			
			recvBuff[n] = 0;  	/* n is size of chars read, put NULL at end */

			/* test what was sent */

			/* unknown command, must be chat text - display message and continue */
			// if message is encrypted - decrypt then display it
			if (ENCFLAG) {
				decryptedtext_len = decrypt(recvBuff, n, key, iv, decryptedtext);
                        	/* Add a NULL terminator. We are expecting printable text */
                        	decryptedtext[decryptedtext_len] = '\0';
                        	fprintf(stdout,"> %s",decryptedtext);
				fflush(stdout);
				if (strncmp(decryptedtext,":CLOSE",6)==0) {
					close(connfd);
					close(kbd);
					return 0;
				}

			} 
			if (!ENCFLAG) {
				fprintf(stdout,"pt> %s",recvBuff);
				if (strncmp(recvBuff,":CLOSE",6)==0) {
					close(connfd);
					close(kbd);
					return 0;
				}
			}
			continue;
		}

		/* exited out of loop (these routines are not currently used) */
		if (FLAG == 1) {
			FLAG = 0;
			n = 0; memset(recvBuff,0,sizeof(recvBuff));	// clean up
			close(kbd);
			close(connfd);
			continue;	// 1 means done with remote, resume waiting
		}

		if (FLAG == 2) {
			fprintf(stdout,"Exiting program\n");
			break;
		}

		fprintf(stdout,"Unknown command FLAG %d\n",FLAG);
		FLAG = 0;
		continue;
	}

	/* user exited chat app - close port and exit */
	close(connfd);
	close(kbd);
	return 0;
}

