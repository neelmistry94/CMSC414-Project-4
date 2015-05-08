/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * Commands from stdin be handled by bank_process_local_command.
 *
 * Remote commands from the ATM should be handled by
 * bank_process_remote_command.
 *
 * The Bank can read both .card files AND .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __BANK_H__
#define __BANK_H__

#include "list.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>


typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;

    // Protocol state
    // TODO add more, as needed
    List *pin_bal;
} Bank;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);
int username_is_valid(char *username);
int user_exists(char *username);
int valid_pin(char *pin);
int valid_balanceamt_input(char *balance);
int contains_nondigit(char *str);
void send_invalid();
void send_s();
void send_ng();
void send_une();
void send_ce();
void send_bal(char *bal);
int get_bal(char *username, char *pin);
int decrypt_and_verify(char* msg, char dec[]);
void encrypt_and_sign(char *msg, char enc[]);
void get_salt(char salt[]);

#endif

