#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/sha.h>

#define MAX_ARG1_SIZE 12 //11 + 1 for Null
#define MAX_ARG2_SIZE 251 //250 + Null character
#define MAX_OTHER_ARG_SIZE 12 //9 + Null
#define MAX_LINE_SIZE 1001 //10000 + Null
#define ENC_LEN 2048
#define MAX_INC_MSG 300

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

    //create bal_list
    bank->pin_bal = list_create();
    bank->usr_pin = list_create();
	bank->pin_usr = list_create();

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        fclose(bank->init);
		list_free(bank->pin_usr);
        list_free(bank->usr_pin);
        list_free(bank->pin_bal);
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
    char arg3[MAX_OTHER_ARG_SIZE];
    char arg3temp[MAX_LINE_SIZE];
    char arg4[MAX_OTHER_ARG_SIZE];
    char arg4temp[MAX_LINE_SIZE];
 

    memset(arg1, 0x00, MAX_ARG1_SIZE);
    memset(arg1temp, 0x00, MAX_LINE_SIZE);
    memset(arg2, 0x00, MAX_ARG2_SIZE);
    memset(arg2temp, 0x00, MAX_LINE_SIZE);
    memset(arg3, 0x00, MAX_OTHER_ARG_SIZE);
    memset(arg3temp, 0x00, MAX_LINE_SIZE);
    memset(arg4, 0x00, MAX_OTHER_ARG_SIZE);
    memset(arg4temp, 0x00, MAX_LINE_SIZE);

    //parse first command
    if(strlen(command) >= MAX_LINE_SIZE){
        printf("Invalid command\n");
        return;
    }

    sscanf(command, "%s %s %s %s", arg1temp, arg2temp, arg3temp, arg4temp);
    
    if(arg1temp == NULL || strlen(arg1temp) < 1){
        printf("Invalid command\n");
        return;
    }

    //max arg1 length is 11 (c r e a t e - u s e r)
    if(strlen(arg1temp) > 11){
        printf("Invalid command\n");
        return;
    }

    strncpy(arg1, arg1temp, MAX_ARG1_SIZE);
    if(strcmp(arg1, "create-user") == 0){
        //3 more arguments
        if(strlen(arg2temp) < 1 || strlen(arg3temp) < 1 || strlen(arg4temp) < 1){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;
        }

        //max username 250 chars
        if(strlen(arg2temp) > 250){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;
        }

        strncpy(arg2, arg2temp, strlen(arg2temp));
        //no need to use regexp. A-Z ascii dec range is 65-90, a-z 97-122
        if(username_is_valid(arg2) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;
        }

        //does user exist?
        if(user_exists(arg2) == 0){
            printf("Error user %s already exists\n", arg2);
            return;
        }

        //pin is 4 chars
        if(strlen(arg3temp) != 4){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;
        }

        strncpy(arg3, arg3temp, strlen(arg3temp));
        //check valadity of arg3 (pin)
        if(valid_pin(arg3) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;
        }

        //balance is INT_MAX, here is 2,147,483,647 or 10 chars
        if(strlen(arg4temp) > 10){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;           
        }

        strncpy(arg4, arg4temp, strlen(arg4temp));
        //check validity of balance (should not be negative or higher than INT_MAX)
        if(valid_balanceamt_input(arg4) == -1){
            printf("Usage: create-user <user-name> <pin> <balance>\n");
            return;    
        }


        /***MAKE .CARD***/
        //hash pin make sure using -lcrypto in makefile
        unsigned char hash[SHA_DIGEST_LENGTH + 1];
		memset(hash, 0x00, SHA_DIGEST_LENGTH + 1);
        size_t hlength = sizeof(arg3);
       //REMEMBER TO USE A SALT
        SHA1((unsigned char *)arg3, hlength, hash);

        //just concanting username and extension
        char *ext = ".card";
        int ufilelen = strlen(arg2) + 6; //5 = . c a r d and + 1 for null
        char userfile[ufilelen]; //5 = . c a r d
        memset(userfile, 0x00, ufilelen);
        strncpy(userfile, arg2, strlen(arg2));
        strncat(userfile, ext, 5);
        FILE *card = fopen(userfile, "w");
        if(card == NULL){
            printf("Error creating card file for user %s\n", arg2);
            //roll back bank, which means just delete file
            remove(userfile);
            return;
        }

        //put hashed pin in file
        fprintf(card, "%s\n", hash);

        //close
        fclose(card);

        //make balance an int
        int bal = strtol(arg4, NULL, 10);

        //add to hash to pin->balance list and user->pin list
        list_add(bank->pin_bal, arg3, &bal);
        list_add(bank->usr_pin, arg2, arg3);
		list_add(bank->pin_usr, arg3, arg2);

        printf("Created user %s\n", arg2);
        return;

    } else if (strcmp(arg1, "deposit") == 0) {
        if(strlen(arg2temp) < 1 || strlen(arg3temp) < 1){
            printf("Usage: deposit <user-name> <amt>\n");
            return;
        }

        //max username 250 chars
        if(strlen(arg2temp) > 250){
            printf("Usage: deposit <user-name> <amt>\n");
            return;
        }

        strncpy(arg2, arg2temp, strlen(arg2temp));
        //no need to use regexp. A-Z ascii dec range is 65-90, a-z 97-122
        if(username_is_valid(arg2) == -1){
            printf("Usage: deposit <user-name> <amt>\n");
            return;
        }

        //does user exist?
        if(user_exists(arg2) == -1){
            printf("No such user\n");
            return;
        }

        //amt max is INT_MAX, here is 2,147,483,647 or 10 chars
        if(strlen(arg3temp) > 10){
                if(contains_nondigit(arg3temp) == 0){
                    printf("Usage: deposit <user-name> <amt>\n");
                    return;
                } else if(strlen(arg3temp) > 10 || strtol(arg3temp, NULL, 10) > INT_MAX){
                    printf("Too rich for this program\n");
                    return;
                }
            printf("Usage: deposit <user-name> <amt>\n");
            return;           
        }

        strncpy(arg3, arg3temp, strlen(arg3temp));
        //check validity of balance (should not be negative or higher than INT_MAX)
        if(valid_balanceamt_input(arg3) == -1){
            printf("Usage: deposit <user-name> <amt>\n");
            return;    
        }
		char *pin = (char *) list_find(bank->usr_pin, arg2);
        int curr_bal = *((int *) list_find(bank->pin_bal, pin));
		int amt = strtol(arg3, NULL, 10);
		long new_bal = amt + curr_bal;	

		//checks if new_bal was capped
		if( (new_bal == INT_MAX) && ((new_bal - amt) != curr_bal)){
            printf("Too rich for this program\n");
            return;   
		}		

        if(new_bal > INT_MAX ){
             printf("Too rich for this program\n");
            return;          
        }

        //update balance
		list_del(bank->pin_bal, pin);
        list_add(bank->pin_bal, pin, &new_bal);

        printf("$%s added to %s's account\n", arg3, arg2);
        return;
   
    } else  if (strcmp(arg1, "balance") == 0) {
        if(strlen(arg2temp) < 1 || username_is_valid(arg2temp) == -1){
            printf("Usage: balance <user-name>\n");
            return;
        }

        if(strlen(arg2temp) > 250){
            printf("Usage: balance <user-name>\n");
            return;
        }

        strncpy(arg2, arg2temp, MAX_ARG2_SIZE);
        if(username_is_valid(arg2) == -1){
            printf("Usage: balance <user-name>\n");
            return;
        }

        //does user exist?
        if(user_exists(arg2) == -1){
            printf("No such user\n");
            return;
        }

        int curr_bal = get_bal(bank, arg2);
        printf("$%d\n", curr_bal);
        return;

    } else {
        printf("Invalid command\n");
        return;
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    //decrypt and verify arrival
    char dec[ENC_LEN];
    char enc[ENC_LEN];
    memset(dec, 0x00, ENC_LEN);
    memset(enc, 0x00, ENC_LEN);

    if(decrypt_and_verify(command, dec) == -1){
        send_invalid(bank);
        return;
    }

    //dec is the actual command
    char arg1[2]; //first command is always a single character
    char arg1temp[MAX_INC_MSG + 1];
    char arg2[251]; //second is always username
    char arg2temp[MAX_INC_MSG + 1];
    char arg3[5]; //third arg always pin
    char arg3temp[MAX_INC_MSG + 1];
    char arg4[11]; //4 can only be amt, max 10 chars
    char arg4temp[MAX_INC_MSG + 1];

    memset(arg1, 0x00, 2);
    memset(arg1temp, 0x00, MAX_INC_MSG + 1);
    memset(arg2, 0x00, 251);
    memset(arg2temp, 0x00, MAX_INC_MSG + 1);
    memset(arg3, 0x00, 5);
    memset(arg3temp, 0x00, MAX_INC_MSG + 1);
    memset(arg4, 0x00, 11);
    memset(arg4temp, 0x00, MAX_INC_MSG + 1);

    sscanf(dec, "%s %s %s %s", arg1temp, arg2temp, arg3temp, arg4temp);
    if(arg1temp == NULL || strlen(arg1temp) < 1){
        send_invalid(bank);
        return;
    }

    if(strlen(arg1temp) > 1){
        send_invalid(bank);
        return;
    }

    strncpy(arg1, arg1temp, strlen(arg1temp));

    if(arg2temp == NULL || strlen(arg2temp) < 1){
        send_invalid(bank);
        return;
    }

    if(strlen(arg2temp) > 250){
        send_invalid(bank);
        return;
    }

    strncpy(arg2, arg2temp, strlen(arg2temp));

    if(username_is_valid(arg2) == -1){
        send_invalid(bank);
        return;
    }

    if(strcmp(arg1, "?") == 0){ // "? username" -> does user exist

        if(user_exists(arg2) != -1){
            send_s(bank);
        } else {
            send_ng(bank);
        }
        return;

    } else if (strcmp(arg1, "w") == 0){ // "w username pin amt" -> withdrawal

        if(user_exists(arg2) == -1){
            send_une(bank);
            return;
        }

        if(arg3temp == NULL || strlen(arg3temp) < 1){
            send_invalid(bank);
            return;
        }

        if(strlen(arg3temp) != 4){
            send_invalid(bank);
            return;
        }

        if(contains_nondigit(arg3temp) == 0){
            send_invalid(bank);
            return;
        }

        strncpy(arg3, arg3temp, strlen(arg3temp));

        if(arg4temp == NULL || strlen(arg4temp) < 1){
            send_invalid(bank);
            return;
        }

        if(strlen(arg4temp) > 11){
            send_invalid(bank);
            return;
        }

        if(contains_nondigit(arg4temp) == 0){
            send_invalid(bank);
            return;
        }

        strncpy(arg4, arg4temp, strlen(arg4temp));

        long temp = strtol(arg4, NULL, 10);
        if(temp < 0 || temp > INT_MAX){
            send_ng(bank); //ng = insufficient funds for here
            return;
        }

        int amt = temp;
        int curr_bal = get_bal(bank, arg2);
        int new_bal = amt - curr_bal;
        if(new_bal < 0){
            send_ng(bank);
            return;
        }

		list_del(bank->pin_bal, arg3);
        list_add(bank->pin_bal, arg3, &new_bal);

        send_s(bank);
        return;

    } else if (strcmp(arg1, "b") == 0){ // "b username pin" -> balance of user
        if(user_exists(arg2) == -1){
            send_une(bank);
            return;
        }

        if(arg3temp == NULL || strlen(arg3temp) < 1){
            send_invalid(bank);
            return;
        }

        if(strlen(arg3temp) != 4){
            send_invalid(bank);
            return;
        }

        if(contains_nondigit(arg3temp) == 0){
            send_invalid(bank);
            return;
        }

        strncpy(arg3, arg3temp, strlen(arg3temp));

        int bal = get_bal(bank, arg2);
        char balstr[11];
        memset(balstr, 0x00, 11);
        sprintf(balstr, "%d", bal);
        send_bal(bank, balstr);
        return;

    } else if (strcmp(arg1, "p") == 0){ // p username pin -> is valid pin?
        if(user_exists(arg2) == -1){
            send_une(bank);
            return;
        }

        if(arg3temp == NULL || strlen(arg3temp) < 1){
            send_invalid(bank);
            return;
        }

        if(strlen(arg3temp) != 4){
            send_invalid(bank);
            return;
        }

        if(contains_nondigit(arg3temp) == 0){
            send_invalid(bank);
            return;
        }

        strncpy(arg3, arg3temp, strlen(arg3temp));

        unsigned char hash[SHA_DIGEST_LENGTH];
		memset(hash, 0x00, SHA_DIGEST_LENGTH);
        size_t plength = sizeof(arg3);
        //REMEMBER TO USE A SALT
        SHA1((unsigned char *)arg3, plength, hash);

        /* PIN ONLY valid where card file and list (hashed) match!
		*/
        char *found = (char *) list_find(bank->usr_pin, arg2);
        if(found == NULL){
            send_ng(bank);
            return;
        }

		unsigned char hash_from_list[SHA_DIGEST_LENGTH];
		memset(hash_from_list, 0x00, SHA_DIGEST_LENGTH);
		size_t flength = sizeof(found);
		SHA1((unsigned char*)found, flength, hash_from_list);

		if(memcmp(hash, hash_from_list, sizeof(hash_from_list)) != 0){
			send_ng(bank);
			return;
		}		

        char *ext = ".card";
        int ufilelen = strlen(arg2) + 6; //5 = . c a r d and + 1 for null
        char userfile[ufilelen]; //5 = . c a r d
        memset(userfile, 0x00, ufilelen);
        strncpy(userfile, arg2, strlen(arg2));
        strncat(userfile, ext, 5);
        FILE *card = fopen(userfile, "r");
        if(card == NULL){
            send_ce(bank);
            return;
        }

        char line[SHA_DIGEST_LENGTH];
        fgets(line, SHA_DIGEST_LENGTH, card);

        fclose(card);
        //not sure can use strcmp to compare hashes
        if(memcmp(hash, line, sizeof(line)) == 0){
            send_s(bank);
        } else {
            send_ng(bank);
        }
        return;

    } else {
        send_invalid(bank);
        return;
    }


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

//0 = true, -1 = false
int user_exists(char *username){
    char *ext = ".card";
    int ufilelen = strlen(username) + 6; //5 = . c a r d and + 1 for null
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

//0  true, -1 false
int valid_pin(char *pin){
    if(contains_nondigit(pin) == 0){
        return -1;
    }

    long d = strtol(pin, NULL, 10);
    if (d < 0 || d > 9999){
        return -1;
    }
    return 0;
}

// 0 true, -1 false
int valid_balanceamt_input(char *balance){
    if(contains_nondigit(balance) == 0){
        return -1;
    }

    long d = strtol(balance, NULL, 10);
    if( d == INT_MAX && strcmp(balance, "2147483647") != 0){
        return -1;//means balance was put down to MAX, so it's too much.
    }
    if( d < 0 || d > INT_MAX){
        return -1;
    }
    return 0;
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

//send "invalid" message
void send_invalid(Bank *bank){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign("invalid", enc) == -1){
        //should never happen
         return;       
    }
    bank_send(bank, enc, sizeof(enc));
    return; 

}

//send "s" (success) message
void send_s(Bank *bank){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign("s", enc) == -1){
        //should never happen
        return;
    } 
    bank_send(bank, enc, sizeof(enc));
    return;  
} 

///send "ng" (no good) message
void send_ng(Bank *bank){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign("ng", enc) == -1){
        //should never happen
        return;
    } 
    bank_send(bank, enc, sizeof(enc));
    return; 
}

//send "une" (user no exist) message
void send_une(Bank *bank){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign("une", enc) == -1){
        //should never happen
        return;
    } 
    bank_send(bank, enc, sizeof(enc));
    return; 
}

//send "ce" (card read error) message
void send_ce(Bank *bank){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign("ce", enc) == -1){
        //should never happen
        return;
    } 
    bank_send(bank, enc, sizeof(enc));
    return; 
}

void send_bal(Bank *bank, char *bal){
    char enc[ENC_LEN];
    memset(enc, 0x00, ENC_LEN);
    if(encrypt_and_sign(bal, enc) == -1){
        //should never happen
        return;
    } 
    bank_send(bank, enc, sizeof(enc));
    return; 
}

//-1 if failed, 0 and higher got it
int get_bal(Bank *bank, char *username){
   if(username_is_valid(username) == -1 || user_exists(username) == -1){
        return -1;
   } 
    /*//hash pin make sure using -lcrypto in makefile
    unsigned char hash[SHA_DIGEST_LENGTH];
    size_t plength = sizeof(pin);
    //REMEMBER TO USE A SALT
    SHA1((unsigned char *)pin, plength, hash);

    int* bal = (int *) (list_find(bank->pin_bal, (char *) hash));*/
	char *pin = (char *) list_find(bank->usr_pin, username);
    int* bal =  list_find(bank->pin_bal, pin);

    if(bal == NULL){
        return -1;
    } else {
        return *bal;
    }
}

//-1 if failed to encrypt and sign
/*stores encrypted msg into enc[], and signs it as well.
store signature in a temp file to be read by otherside
*/
int encrypt_and_sign(char *msg, char *enc){
    strncpy(enc, msg, strlen(msg));
    return 0;
}

//-1 if failed to decrypt or verify
/*takes in msg and decrypts it and verifies it's certificate(signature) as well
tores decrypted msg in dec[]. If dec is not being stored, try changing the parameter
to char *dec
read signature from temp file made
 by otherside*/
int decrypt_and_verify(char *enc, char *dec){
    //placeholder
    strncpy(dec, enc, sizeof(enc));
    return 0;
}


//gets the salt for hashing
void get_salt(char *salt){

}
