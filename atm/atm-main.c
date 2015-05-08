/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main()
{
    char user_input[1000];

    ATM *atm = atm_create();

    FILE *init = fopen("init.atm", "r");
    if(init == NULL){
        printf("Error opening ATM initialization file\n");
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
	return EXIT_SUCCESS;
}
