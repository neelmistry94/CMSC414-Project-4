#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

const int bits = 2048;
const int expo = 65537;
//for random value at the end of .bank
const int intmax = 2048;

void getKeys(char *keys[]){

   int pubkeylen, prikeylen;
   char *pri_key, *pub_key;
   RSA *rsa;
   BIO *pubBio, *priBio;
   int i, j;  //indexing purpose

   //runs 2 times because 2 sets of pub/secret keys
	for(i = 0; i < 2; i++){
		//generate a pair of RSA key
		rsa = RSA_generate_key(bits, expo, 0, 0);

		/* getting string pem file form */ 
		pubBio = BIO_new(BIO_s_mem());
		priBio = BIO_new(BIO_s_mem());

		PEM_write_bio_RSAPrivateKey(priBio, rsa, NULL, NULL, 0, NULL, NULL);
		PEM_write_bio_RSAPublicKey(pubBio, rsa);
	 
		prikeylen = BIO_pending(priBio);
		pubkeylen = BIO_pending(pubBio);

		/* Null-terminate */
		pri_key = calloc(prikeylen+1, 1);
		pub_key = calloc(pubkeylen+1, 1);

		BIO_read(priBio, pri_key, prikeylen);
		BIO_read(pubBio, pub_key, pubkeylen);

		if(i == 0){
		   j = 3; 
		}
		else{
		   j = 2;
		}

		keys[j] = malloc(prikeylen+1);
		strncpy(keys[j], pri_key, prikeylen+1);
		keys[i] = malloc(pubkeylen+1);
		strncpy(keys[i], pub_key, pubkeylen+1);

		BIO_free_all(priBio);
		BIO_free_all(pubBio);
		RSA_free(rsa);
		free(pri_key);
		free(pub_key);
	}

}

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
   
   //generating random key at the end of .bank
   srand(time(0));
   random = rand();
   snprintf(randstr, sizeof(randstr), "%d", random);
   fputs(randstr, bank);

	if(fclose(atm)||fclose(bank)){
		printf("Error creating initialization files\n");
		return 64;
	}
	
/*   
if for any other reason the program fails, print 
“Error creating initialization files” and return value 64 
(you do not need to delete or revert any files you may have created).
*/

   free(atmpath);
   free(bankpath);  
   printf("Successfully initialized bank state\n");
   return 0;
}
