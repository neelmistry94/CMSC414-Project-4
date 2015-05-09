/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files, but not .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <openssl/rsa.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

typedef struct _ATM
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    // Protocol state
    // TODO add more, as needed
    int session_started; //0 no, 1 yes //7 chars from ATM (): and 250 from max username + 1 for null
	char username[251]; //+1 for null
} ATM;

ATM* atm_create();
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);
int username_is_valid(char *username);
int contains_nondigit(char *str);
void atm_init(char *init);
int signature(char *msg, RSA *r);
int verify(char *msg, RSA *r);
void getKeys(char *keys[]);
RSA * createRSA(char *key,int type);
int encrypt_and_sign(char *msg, char *enc);
int decrypt_and_verify(char *enc, char *dec);

#endif
