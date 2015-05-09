/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
   int n;
   char ext[] = ".bank";
   char temp[6];
   char sendline[1000];
   char recvline[1000];

   Bank *bank = bank_create();
    if(argv[1] == NULL){
      printf("Error opening bank initialization file\n");
      return 64;
    }

    strncpy(temp, argv[1]+(strlen(argv[1])-5), 6);
    
    if(strncmp(temp, ext, strlen(ext)) == 0){
      //printf("bank file: %s\n",argv[1]);
      bank_init(argv[1]);
    }
    else{
      printf("Error opening bank initialization file\n");
      return 64;
    }

   printf("%s", prompt);
   fflush(stdout);

   while(1)
   {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 1000, stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 1000);
           bank_process_remote_command(bank, recvline, n);
       }
   }

   bank_free(bank);
   return EXIT_SUCCESS;
}
