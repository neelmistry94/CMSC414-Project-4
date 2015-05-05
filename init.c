‪#‎include‬ <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

int main(int argc, char**argv){
	FILE *atm, *bank;
	char *atmpath, *bankpath;
	char atmExt[] = ".atm";
	char bankExt[] = ".bank";
	
	atmpath = malloc(strlen(argv[1])+strlen(atmExt)+1); 
	bankpath = malloc(strlen(argv[1])+strlen(bankExt)+1);
	
	if(atmpath != NULL || bankpath != NULL){
		strcat(atmpath, argv[1]);
		strcat(atmpath, atmExt);
		strcat(bankpath, argv[1]);
		strcat(bankpath, bankExt);
	}
	
	printf("%s and %s\n", atmpath, bankpath);
	
	if( access(atmpath, F_OK) != -1 || access(bankpath, F_OK) != -1){
		printf("Error: one of the files already exists\n");
		return 0;
	}

	atm = fopen(atmpath, "w");
	bank = fopen(bankpath, "w");
	
	fprintf(atm, "Chijike is dumb as hell\n");
	fputs("chijike is stupid as hell\n", atm);
	
	fclose(atm);
	fclose(bank);
	
	free(atmpath);
	free(bankpath);
	
	printf("Successfully initialized bank state\n");
	return 0;
}