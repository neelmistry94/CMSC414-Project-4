/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */
#define _GNU_SOURCE
#include "atm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char**argv)
{
    char user_input[1000];
    char ext[] = ".atm";
    char temp[5];

    ATM *atm = atm_create();

    if(argv[1] == NULL){
      printf("Error opening bank initialization file\n");
      return 64;
    }
    
    //check extension of argv[1] for .atm file
    strncpy(temp, argv[1]+(strlen(argv[1])-4), 5);

    if(strncmp(temp, ext, strlen(ext)) == 0){
       //printf("atm file: %s\n",argv[1]);
       atm_init(argv[1]);
    }
    else{
       //printf("no atm file: %s",argv[1]);
       return 64;
    }

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 1000,stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        if(atm->session_started == 1){
            printf("ATM (%s): ", atm->username);
        } else {
            printf("%s", prompt);
        }
        fflush(stdout);
    }
    atm_free(atm);
	return EXIT_SUCCESS;
}
