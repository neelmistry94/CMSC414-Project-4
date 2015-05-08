#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const int intmax = 2048;

void getKeys(char *keys[]){
	FILE *pri, *pub;	
	char *line;
	size_t leng = 0;
	ssize_t lines;
	int i, j;
	
	for(i = 0; i < 2; i++){	
	char *prikey, *pubkey;

	prikey = malloc(4098*sizeof(char));
	pubkey = malloc(4098*sizeof(char));	

	system("openssl genrsa -out private.pem 2048");
	system("openssl rsa -in private.pem -out public.pem -pubout");

	pri = fopen("private.pem", "r");
	pub = fopen("public.pem", "r");

	if(pri == NULL || pub == NULL){
		exit(0);
	}

	if(i == 0){
	   j = 3; 
	}
	else{
	   j = 2;
	}

	while ((lines = getline(&line, &leng, pri)) != -1){
		strcat(prikey, line);
	}

	while ((lines = getline(&line, &leng, pub)) != -1){
		strcat(pubkey, line);
	}

	keys[j] = malloc(strlen(prikey));
	strncpy(keys[j], prikey, strlen(prikey));
	keys[i] = malloc(strlen(pubkey));
	strncpy(keys[i], pubkey, strlen(pubkey));

	system("rm private.pem");
	system("rm public.pem");

	fclose(pri);
	fclose(pub);
	}
}

//-----BEGIN RSA PRIVATE KEY-----

int main(int argc, char**argv){

   FILE *atm, *bank;
   char *keys[4], randstr[intmax];
   char *atmpath, *bankpath;
   char atmExt[] = ".atm";
   char bankExt[] = ".bank";
   int i, random;
   
   
   //check if there is only one argument
   if(argc != 2){
	printf("Usage: init <filename>\n");
	return 62;
   }
   
   atmpath = malloc(strlen(argv[1])+strlen(atmExt)+1); 
   bankpath = malloc(strlen(argv[1])+strlen(bankExt)+1);

   if(atmpath != NULL || bankpath != NULL){
	strcat(atmpath, argv[1]);
	strcat(atmpath, atmExt);
	strcat(bankpath, argv[1]);
	strcat(bankpath, bankExt);
   }
   //check if file already exists
   if( access(atmpath, F_OK) != -1 || access(bankpath, F_OK) != -1){
	printf("Error: one of the files already exists\n");
	return 63;
   }

   getKeys(keys);

   if((atm = fopen(atmpath, "w"))==NULL || (bank = fopen(bankpath, "w"))==NULL){
	printf("Error creating initialization files\n");
	return 64;
   }

   for(i = 0; i < 4; i++){

	if((i%2)==0){
	   fputs(keys[i],bank);
	}
	else{
	   fputs(keys[i],atm);
	}
	free(keys[i]);

   }
   srand(time(0));
   random = rand();
   snprintf(randstr, sizeof(randstr), "%d", random);
   fputs(randstr, bank);

   if(fclose(atm)||fclose(bank)){
	printf("Error creating initialization files\n");
	return 64;
   }
	
/*   • Otherwise, if for any other reason the program fails, print 
“Error creating initialization files” and return value 64 
(you do not need to delete or revert any files you may have created).
*/
   free(atmpath);
   free(bankpath);  
   printf("Successfully initialized bank state\n");
   return 0;
}
