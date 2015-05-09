#define _GNU_SOURCE
#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h> 
#include <openssl/objects.h> 
#include <openssl/bn.h>

#define MAX_ARG1_SIZE 14 //b e g i n - s e s s i o n + 1 for null char
#define MAX_ARG2_SIZE 251 //+1 for null char
#define MAX_LINE_SIZE 1001
#define ENC_LEN 2048
#define MAX_RSP_SIZE 11
#define MAX_MSG_SIZE 301
#define MAX_CRYP 4098
#define MAX_SIGN 300

int padding = RSA_PKCS1_PADDING;
unsigned int glo_slen = 0;
unsigned char *glo_sig = NULL;
char *atmfile;

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    atm->session_started = 0;
    memset(atm->username, 0x00, 251);

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        atm->session_started = 0;
        memset(atm->username, 0x00, 251);
        close(atm->sockfd);
	free(atmfile);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
    // TODO: Implement the ATM's side of the ATM-bank protocol
    char arg1[MAX_ARG1_SIZE];
    char arg1temp[MAX_LINE_SIZE];
    char arg2[MAX_ARG2_SIZE];
    char arg2temp[MAX_LINE_SIZE];

    memset(arg1, 0x00, MAX_ARG1_SIZE);
    memset(arg1temp, 0x00, MAX_LINE_SIZE);
    memset(arg2, 0x00, MAX_ARG2_SIZE);
    memset(arg2temp, 0x00, MAX_LINE_SIZE);

    sscanf(command, "%s %s", arg1temp, arg2temp);
    if(strlen(arg1temp) > 13 || strlen(arg1temp) < 1){
        printf("Invalid command\n");
        return;
    }

    strncpy(arg1, arg1temp, strlen(arg1temp));
    if(strcmp(arg1, "begin-session") == 0){
        if(atm->session_started == 1){
            printf("A user is already logged in\n");
            return;
        }

        if(arg2temp == NULL || strlen(arg2temp) < 1){
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        if(strlen(arg2temp) > 250){
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        if(username_is_valid(arg2temp) == -1){
            printf("Usage: begin-session <user-name>\n");
            return;           
        }
        strncpy(arg2, arg2temp, strlen(arg2temp));


        //check user exists
        char enc[ENC_LEN], dec[MAX_RSP_SIZE], recv[ENC_LEN];
        char msg1[strlen(arg2)+3];
        memset(msg1, 0x00, strlen(arg2)+3);
        memset(enc, 0x00, ENC_LEN);
        memset(dec, 0x00, MAX_RSP_SIZE);
        memset(recv, 0x00, ENC_LEN);
        strncpy(msg1, "? ", 2);
        strncat(msg1, arg2, strlen(arg2));
        if(encrypt_and_sign(msg1, enc) == -1){
            printf("Unable to access %s's card\n", arg2);
            return;
        };
        atm_send(atm, enc, sizeof(enc));
        atm_recv(atm, recv, ENC_LEN);
        if(decrypt_and_verify(recv,dec) == -1){
            printf("Unable to access %s's card\n", arg2);
            return;
        }

        if(strlen(dec) > 10){
            printf("Unable to access %s's card\n", arg2);
            return;
        }
        
        char resp[MAX_RSP_SIZE]; //max response is only 10 characaters
        memset(resp, 0x00, MAX_RSP_SIZE);
        sscanf(dec, "%s", resp);

		if(strlen(resp) > 10){
			printf("Unable to access %s's card\n", arg2);
            return;		
		}

        if(strcmp(resp, "invalid") == 0){
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        if(strcmp(resp, "ng") == 0){
            printf("No such user\n");
            return;
        }

        if(strcmp(resp, "s") != 0){
            //Should not even be possible
            printf("Usage: begin-session <user-name>\n");
            return;
        }
	
        char pin[5], line[1000];
        memset(line, 0x00, 1000);
        memset(pin, 0x00, 5);
        printf("PIN? ");
	
	fgets(line, 1000, stdin);
        if(strlen(line) != 4 && line[4] != '\n'){
        	if(strlen(line) > 4){
        		
        	}
            printf("Not authorized\n");
            return;
        }

	strncpy(pin, line, 4);

        if(contains_nondigit(pin) == 0){
            printf("Not authorized\n");
            return;
        }

        char msg[260]; // p + username + pin + spaces -> 1 + 250 + 4 + 3 + 1(Null)

        //reset prev used vars
        memset(msg, 0x00, MAX_MSG_SIZE);
        memset(enc, 0x00, ENC_LEN);
        memset(dec, 0x00, MAX_RSP_SIZE);
        memset(recv, 0x00, ENC_LEN);
        memset(resp, 0x00, MAX_RSP_SIZE);
        strncpy(msg, "p ", 2);
        strncat(msg, arg2, strlen(arg2));
        strncat(msg, " ", 1);
        strncat(msg, pin, 4);
        if(encrypt_and_sign(msg, enc) == -1){
            printf("Not authorized\n");
            return;
        };
        atm_send(atm, enc, sizeof(enc));
        atm_recv(atm, recv, ENC_LEN);
        if(decrypt_and_verify(recv,dec) == -1){
            printf("Not authorized\n");
            return;
        }

        if(strlen(dec) > 10){
            printf("Not authorized\n");
            return;
        }

        sscanf(dec, "%s", resp);

		if(strlen(resp) > 10){
			printf("Not authorized\n");
			return;
		}

        if(strcmp(resp, "s") !=  0){
            printf("Not authorized\n");
            return;
        } else {
            printf("Authorized\n");
        }

        strncpy(atm->username, arg2, strlen(arg2));
        atm->session_started = 1;
        return;

    } else if (strcmp(arg1, "withdraw") == 0){
        if(atm->session_started == 0){
            printf("No user logged in\n");
            return;
        }

        if(arg2temp == NULL || strlen(arg2temp) < 1){
            printf("Usage: withdraw <amt>\n");
            return;
        }

        if(strlen(arg2temp) > 10){
            printf("Usage: withdraw <amt>\n");
            return;            
        }

        strncpy(arg2, arg2temp, strlen(arg2temp));
        if(contains_nondigit(arg2) == 0){
            printf("Usage: withdraw <amt>\n");
            return;             
        }

        char enc[ENC_LEN], dec[MAX_RSP_SIZE], recv[ENC_LEN], msg[MAX_MSG_SIZE], resp[MAX_RSP_SIZE];
        memset(msg, 0x00, MAX_MSG_SIZE);
        memset(enc, 0x00, ENC_LEN);
        memset(dec, 0x00, MAX_RSP_SIZE);
        memset(recv, 0x00, ENC_LEN);
        memset(resp, 0x00, MAX_RSP_SIZE);

        strncpy(msg, "w ", 2);
        strncat(msg, atm->username, strlen(atm->username));
        strncat(msg, " ", 1);
        strncat(msg, arg2, strlen(arg2));

        if(encrypt_and_sign(msg, enc) == -1){
            printf("Usage: withdraw <amt>\n");
            return;
        };
        atm_send(atm, enc, sizeof(enc));
        atm_recv(atm, recv, ENC_LEN);
        if(decrypt_and_verify(recv,dec) == -1){
            printf("Usage: withdraw <amt>\n");
            return;
        }

        if(strlen(dec) > 10){
            printf("Usage: withdraw <amt>\n");
            return;
        }

        sscanf(dec, "%s", resp);

        if(strcmp(resp, "invalid") == 0 || strcmp(resp, "une") == 0){
            printf("Usage: withdraw <amt>\n");
            return;
        }

        if(strcmp(resp, "ng") == 0){
            printf("Insufficient funds\n");
            return;
        }

        if(strcmp(resp, "s") == 0){
            printf("$%s dispensed\n", arg2);
            return;
        }

    } else if (strcmp(arg1, "balance") == 0){
        if(atm->session_started == 0){
            printf("No user logged in\n");
            return;
        }

        char enc[ENC_LEN], dec[MAX_RSP_SIZE], recv[ENC_LEN], msg[MAX_MSG_SIZE], resp[MAX_RSP_SIZE];
        memset(msg, 0x00, MAX_MSG_SIZE);
        memset(enc, 0x00, ENC_LEN);
        memset(dec, 0x00, MAX_RSP_SIZE);
        memset(recv, 0x00, ENC_LEN);
        memset(resp, 0x00, MAX_RSP_SIZE);

        strncpy(msg, "b ", 2);
        strncat(msg, atm->username, strlen(atm->username));

        if(encrypt_and_sign(msg, enc) == -1){
            printf("Usage: balance\n");
            return;
        };
        atm_send(atm, enc, sizeof(enc));
        atm_recv(atm, recv, ENC_LEN);
        if(decrypt_and_verify(recv,dec) == -1){
            printf("Usage: balance\n");
            return;
        }

        if(strlen(dec) > 10){
            printf("Usage: balance\n");
            return;
        }

        sscanf(dec, "%s", resp);

        if(strcmp(resp, "invalid") == 0 || strcmp(resp, "une") == 0){
            printf("Usage: balance\n");
            return;
        }

        printf("$%s\n", resp);
        return;

    } else if (strcmp(arg1, "end-session") == 0){
        if(atm->session_started == 0){
            printf("No user logged in\n");
            return;
        }

        memset(atm->username, 0x00, 251);
        atm->session_started = 0;

        printf("User logged out\n");
    } else {
        printf("Invalid command\n");
        return;
    }

	/*
	 * The following is a toy example that simply sends the
	 * user's command to the bank, receives a message from the
	 * bank, and then prints it to stdout.
	 */

	/*
    char recvline[10000];
    int n;

    atm_send(atm, command, strlen(command));
    n = atm_recv(atm,recvline,10000);
    recvline[n]=0;
    fputs(recvline,stdout);
	*/
}

int username_is_valid(char *username){
    if(username == NULL){
        return 0;
    }

    int i;
    for(i = 0; i < strlen(username); i++){
        if(username[i] > 122 || username[i] < 65){
            return -1;
        } else if (username[i] > 90 && username[i] < 97){
            return -1;
        }
    }
    return 1;
}

int contains_nondigit(char *str){
    int i;
    for(i = 0; i < strlen(str); i++){
        if(str[i] < 48 || str[i] > 57){
            return 0;
        }
    }
    return -1;
}

void atm_init(char *init){
    atmfile = malloc((strlen(init)+1)*sizeof(char));
    strncpy(atmfile, init, strlen(init)+1);

}

int signature(char *msg, RSA *r) { 
    unsigned char *sig;   
    sig = (unsigned char*) malloc(RSA_size(r));
    glo_sig = sig;
 
    return RSA_sign(NID_sha1, (const unsigned char*)msg, (unsigned char)strlen(msg), sig, &glo_slen, r);
}


int verify(char *msg, RSA *r) {
    return RSA_verify(NID_sha1, (const unsigned char*)msg, (unsigned int)strlen(msg), glo_sig, glo_slen, r); 
}

void getKeys(char *keys[]){
    FILE *atm;    
    char *line;
    size_t leng = 0;
    ssize_t lines;
    //char end[] = "-----END RSA PRIVATE KEY-----\n";
    char start[] = "-----BEGIN RSA PRIVATE KEY-----\n";
    int swit = 0;
    
    char *pubkey, *prikey;

    pubkey = malloc(MAX_CRYP*sizeof(char));
    prikey = malloc(MAX_CRYP*sizeof(char));
    atm = fopen(atmfile, "r");

    //file opening fail
    if(atm == NULL){
        //printf("atm file not opening\n");
        return;
    }

    while ((lines = getline(&line, &leng, atm)) != -1){
        if(strncmp(line, start, strlen(start)) == 0){
            swit = 1;
        }

        if(swit == 0){
            strncat(pubkey, line, strlen(line));
        }
        else{
            strncat(prikey, line, strlen(line));
        }
    }

    keys[0] = malloc(strlen(pubkey)+2);
    keys[1] = malloc(strlen(prikey)+2);
    strncpy(keys[0], pubkey, strlen(pubkey)+2);
    strncpy(keys[1], prikey, strlen(prikey)+2);
   

    free(prikey);
    free(pubkey);
    fclose(atm);
    
}

RSA * createRSA(char *key,int type)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);

    //check bio 
    if (keybio==NULL){
        //printf( "Failed to create key BIO");
        return NULL;
    }

    //check public 0 or private 1
    if(type){
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    else{
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }

    //check RSA
    if(rsa == NULL){
        //printf( "Failed to create RSA\n");
    }
 
    return rsa;
}


int encrypt_and_sign(char *msg, char *enc){
    unsigned int sign;
    //unsigned char encmsg[MAX_CRYP]={};
    char *keys[2];
    int i;

    if(strlen(msg) > MAX_SIGN){
        //printf("Message size is too big\n");
        return -1;
    }
    getKeys(keys);

    RSA *rsa = createRSA(keys[1],1);
    if(rsa == NULL){
        return -1;
    }

    int enclen = RSA_private_encrypt(strlen(msg),(unsigned char *)msg,(unsigned char*)enc,rsa,padding);
    
    if(enclen == -1){
        //printf("Encryption failed\n");
        return -1;
    }

    sign = signature(msg, rsa);
    if (sign == 0){
        //printf("Signing Failed");
        return -1;
    }

    for(i=0; i< 2; i++){
        free(keys[i]);
    }
    
    //printf("Encryption and Siging succeeded\n");
    return 0;
}

int decrypt_and_verify(char *enc, char *dec){
    //unsigned char decmsg[MAX_CRYP]={};
    char *keys[2]; 
    unsigned int verified;
    int i;
        
    getKeys(keys);


    RSA *rsa = createRSA(keys[0],0);
    if(rsa == NULL){
        return -1;
    }

    int declen = RSA_public_decrypt(strlen(enc),(unsigned char *)enc,(unsigned char *)dec,rsa,padding);
    
    if(declen == -1){
        //printf("Decryption failed\n");
        return -1;
    }

    verified = verify(dec, rsa);
    if(verified == -1){
        return -1;
    }

    for( i=0; i< 2; i++){
        free(keys[i]);
    }

    //printf("Decryption and Verify succeeded\n");
    return 0;
}
