#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define MAX_ARG1_SIZE = 12; //11 + Null
#define MAX_ARG2_SIZE = 251; //250 + Null character
#define MAX_OTHER_ARG_SIZE = 10; //9 + Null
#define MAX_LINE_SIZE = 10000;

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    char arg1[MAX_ARG1_SIZE];
    char arg1temp[MAX_LINE_SIZE];
    char arg2[MAX_ARG2_SIZE];
    char arg2temp[MAX_LINE_SIZE];
    char arg3[MAX_ARG3_SIZE];
    char arg3temp[MAX_LINE_SIZE];
    char arg4[MAX_ARG3_SIZE];
    char arg4temp[MAX_LINE_SIZE];
 

    memset(arg1, 0x00, MAX_ARG1_SIZE);
    memset(arg1temp; 0x00, MAX_LINE_SIZE);
    memset(arg2, 0x00, MAX_ARG2_SIZE);
    memset(arg2temp; 0x00, MAX_LINE_SIZE);
    memset(arg3, 0x00, MAX_OTHER_ARG_SIZE);
    memset(arg3temp; 0x00, MAX_LINE_SIZE);
    memset(arg4, 0x00, MAX_OTHER_ARG_SIZE);
    memset(arg4temp; 0x00, MAX_LINE_SIZE);

    //parse first command
    if(strlen(command) > MAX_LINE_SIZE){
        printf("Invalid command");
        return;
    }

    sscanf(command, "%s %s %s %s", arg1temp, arg2temp, arg3temp, arg4temp);
    strncpy(arg1, arg1temp, MAX_ARG1_SIZE);

    if(strcmp(arg1, "create-user") == 0){
        //3 more arguments
        if(arg2temp == NULL || arg3temp == NULL || arg4temp == NULL){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }

        strncpy(arg2, arg2temp, MAX_ARG2_SIZE);
        //no need to use regexp. A-Z ascii dec range is 65-90, a-z 97-122
        if(username_is_valid(arg2) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }

        //create user, .card file

    } else if (strcmp(arg1, "deposit") == 0) {
        if(arg2temp == NULL || arg3temp == NULL){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }

        strncpy(arg2, arg2temp, MAX_ARG2_SIZE);
        if(username_is_valid(arg2) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
   
    } else  if (strcmp(arg1, "balance") == 0) {
        if(arg2temp == NULL || username_is_valid == -1){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }

        strncpy(arg2, arg2temp, MAX_ARG2_SIZE);
        if(username_is_valid(arg2) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>");
            return;
        }

    } else {
        printf("Invalid command");
        return;
    }
    // TODO: Implement the bank's local commands
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    //decrypt on arrival


    // TODO: Implement the bank side of the ATM-bank protocol

	/*
	 * The following is a toy example that simply receives a
	 * string from the ATM, prepends "Bank got: " and echoes 
	 * it back to the ATM before printing it to stdout.
	 */

	/*
    char sendline[1000];
    command[len]=0;
    sprintf(sendline, "Bank got: %s", command);
    bank_send(bank, sendline, strlen(sendline));
    printf("Received the following:\n");
    fputs(command, stdout);
	*/
}

//-1 false, 1 true, 0 unknown/null; A-Z ascii dec range is 65-90, a-z 97-122
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

int user_exists(char* username){
    int ufilelen = strlen(username) + 5;
    char ext[5] = ".card";
    char userfile[ufilelen]; //5 = . c a r d
    memset(userfile, 0x00, ufilelen);
    strncpy(userfile, username, strlen(username));
    strncat(userfile, ext, 5);

    if(access(userfile, F_OK) != -1){
        return 0;
    } else { 
        return - 1;
    }
}

void decrypt_incoming(char* str, char *dec){

}

void encrypt_outgoing(char *str, char *enc){

}