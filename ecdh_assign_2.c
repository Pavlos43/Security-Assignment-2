#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

#define DEFAULT_CONTEXT "ECDH_KDF"

void helpMessage(){
	printf("-o path\tPath to output file\n-a number\tAlice's private key (optional, hexadecimal format)\n-b number\tBob's private key (optional, hexadecimal format)\n-c context\tContext string for key derivation (default: ECDH_KDF)\n-h\tThis help message\n");
}
int main(int argc,char* argv[]){
	int opt;
	char* path=NULL;
	char* alicePrivKey=NULL;
	char* bobPrivKey=NULL;
	char* context=NULL;

	while((opt=getopt(argc,argv,"o:a:b:c:h"))!=-1){
		switch(opt){
			case 'o':
				path=optarg;
				break;
			case 'a':
				alicePrivKey=optarg;
				break;
			case 'b':
				bobPrivKey=optarg;
				break;
			case 'c':
				context=optarg;
				break;
			case 'h':
				helpMessage();
				return 0;
			case '?':
				return 1;
		}
	}
	
	if(path==NULL){
		printf("Must contain:-o path\tPath to output file");
		return 1;
	}

	if(context==NULL){
		context=(char*)malloc(strlen("ECDH_KDF")+1);
		strcpy(context,DEFAULT_CONTEXT);
	}

	if(sodium_init()<0){
		printf("Error initializing lisodium");
		return 1;
	}

	unsigned char a_publicKey[crypto_kx_PUBLICKEYBYTES];
	unsigned char a_newPrivateKey[crypto_kx_SECRETKEYBYTES];
	char* cleanedAliceKey;	
	
	if(alicePrivKey==NULL){
		
		crypto_kx_keypair(a_publicKey,a_newPrivateKey);
	}
	else{
		if(strncmp(alicePrivKey,"0x",2)==0||strncmp(alicePrivKey,"0X",2)==0){
			cleanedAliceKey=(char*)malloc(strlen(alicePrivKey)-1);
			if(cleanedAliceKey==NULL){
				printf("Did not manage to clean");
			}
			strcpy(cleanedAliceKey,alicePrivKey+2);
		}
		else{
			cleanedAliceKey=(char*)malloc(strlen(alicePrivKey)+1);
			strcpy(cleanedAliceKey,alicePrivKey);
		}
		if(sodium_hex2bin(a_newPrivateKey,crypto_kx_SECRETKEYBYTES,cleanedAliceKey,strlen(cleanedAliceKey),NULL,NULL,NULL)!=0){
			printf("Failed convertion");
			return 1;
		}
		crypto_scalarmult_base(a_publicKey,a_newPrivateKey);
	}

	unsigned char b_publicKey[crypto_kx_PUBLICKEYBYTES];
	unsigned char b_newPrivateKey[crypto_kx_SECRETKEYBYTES];
	char* cleanedBobKey;
	
	if(bobPrivKey==NULL){
		crypto_kx_keypair(b_publicKey,b_newPrivateKey);
	}
	else{
		if(strncmp(bobPrivKey,"0x",2)==0||strncmp(bobPrivKey,"0X",2)==0){
			cleanedBobKey=(char*)malloc(strlen(bobPrivKey)-1);
			if(cleanedBobKey==NULL){
				printf("Did not manage to clean");
			}
			strcpy(cleanedBobKey,bobPrivKey+2);
		}
		else{
			cleanedBobKey=(char*)malloc(strlen(bobPrivKey)+1);
			strcpy(cleanedBobKey,bobPrivKey);
		}
		if(sodium_hex2bin(b_newPrivateKey,crypto_kx_SECRETKEYBYTES,cleanedBobKey,strlen(cleanedBobKey),NULL,NULL,NULL)!=0){
			printf("Failed convertion");
			return 1;
		}
		crypto_scalarmult_base(b_publicKey,b_newPrivateKey);
	}

	unsigned char a_secretKey[crypto_scalarmult_BYTES];
	unsigned char b_secretKey[crypto_scalarmult_BYTES];
	//NA tsekaroume ta megethoi

	crypto_scalarmult(a_secretKey,a_newPrivateKey,b_publicKey);
	crypto_scalarmult(b_secretKey,b_newPrivateKey,a_publicKey);

	if(crypto_verify_32(a_secretKey,b_secretKey)!=0){
		printf("The secrets are not the same.");
		sodium_memzero(a_newPrivateKey,sizeof(a_newPrivateKey));
		sodium_memzero(b_newPrivateKey,sizeof(b_newPrivateKey));
		sodium_memzero(a_secretKey,sizeof(a_secretKey));
		sodium_memzero(b_secretKey,sizeof(b_secretKey));
		return 1;
	}

	unsigned char a_encryptionKey[crypto_kdf_KEYBYTES];
	unsigned char a_macKey[crypto_kdf_KEYBYTES];


	unsigned char b_encryptionKey[crypto_kdf_KEYBYTES];
	unsigned char b_macKey[crypto_kdf_KEYBYTES];

	if(crypto_kdf_derive_from_key(a_encryptionKey,crypto_kdf_KEYBYTES,1,context,a_secretKey)!=0){
		printf("Failed to derive Alice's encryprion key");
		return 1;
	}

	if(crypto_kdf_derive_from_key(b_encryptionKey,crypto_kdf_KEYBYTES,1,context,b_secretKey)!=0){
		printf("Failed to derive Bob's encryprion key");
		return 1;
	}

	if(crypto_verify_32(a_encryptionKey,b_encryptionKey)!=0){
		printf("The encryption key's are not the same.");
		sodium_memzero(a_newPrivateKey,sizeof(a_newPrivateKey));
		sodium_memzero(b_newPrivateKey,sizeof(b_newPrivateKey));
		sodium_memzero(a_secretKey,sizeof(a_secretKey));
		sodium_memzero(b_secretKey,sizeof(b_secretKey));
		sodium_memzero(a_encryptionKey,sizeof(a_encryptionKey));
		sodium_memzero(b_encryptionKey,sizeof(b_encryptionKey));
		return 1;
	}

	if(crypto_kdf_derive_from_key(a_macKey,crypto_kdf_KEYBYTES,2,context,a_secretKey)!=0){
		printf("Failed to derive Alice's mac key");
		return 1;
	}

	if(crypto_kdf_derive_from_key(b_macKey,crypto_kdf_KEYBYTES,2,context,b_secretKey)!=0){
		printf("Failed to derive Bob's mac key");
		return 1;
	}

	if(crypto_verify_32(a_macKey,b_macKey)!=0){
		printf("The mac key's are not the same.");
		sodium_memzero(a_newPrivateKey,sizeof(a_newPrivateKey));
		sodium_memzero(b_newPrivateKey,sizeof(b_newPrivateKey));
		sodium_memzero(a_secretKey,sizeof(a_secretKey));
		sodium_memzero(b_secretKey,sizeof(b_secretKey));
		sodium_memzero(a_encryptionKey,sizeof(a_encryptionKey));
		sodium_memzero(b_encryptionKey,sizeof(b_encryptionKey));
		sodium_memzero(a_macKey,sizeof(a_macKey));
		sodium_memzero(b_macKey,sizeof(b_macKey));
		return 1;
	}

	FILE *fp= fopen(path,"w");

	if (fp==NULL){
		printf("Cannot open file");
		return 1;
	}
	else{
		
		char temp[65];

		sodium_bin2hex(temp,sizeof(temp),a_publicKey,crypto_kx_PUBLICKEYBYTES);
		fprintf(fp, "Alice's Public Key:\n%s\n",temp);

		sodium_bin2hex(temp,sizeof(temp),b_publicKey,crypto_kx_PUBLICKEYBYTES);
		fprintf(fp, "Bob's Public Key:\n%s\n",temp);

		sodium_bin2hex(temp,sizeof(temp),a_secretKey,crypto_scalarmult_BYTES);
		fprintf(fp, "Shared Secret (Alice):\n%s\n",temp);

		sodium_bin2hex(temp,sizeof(temp),b_secretKey,crypto_scalarmult_BYTES);
		fprintf(fp, "Shared Secret (Bob):\n%s\n",temp);

		if(crypto_verify_32(a_secretKey,b_secretKey)!=0){
			fprintf(fp, "Encryption keys do not match!\n");	
		}else{
			fprintf(fp, "Encryption keys match!\n");	
		}

		sodium_bin2hex(temp,sizeof(temp),a_encryptionKey,crypto_kdf_KEYBYTES);
		fprintf(fp, "Derived Encryption Key (Alice):\n%s\n",temp);

		sodium_bin2hex(temp,sizeof(temp),b_encryptionKey,crypto_kdf_KEYBYTES);
		fprintf(fp, "Derived Encryption Key (Bob):\n%s\n",temp);

		if(crypto_verify_32(a_encryptionKey,b_encryptionKey)!=0){
			fprintf(fp, "Encryption keys do not match!\n");	
		}else{
			fprintf(fp, "Encryption keys match!\n");	
		}

		sodium_bin2hex(temp,sizeof(temp),a_macKey,crypto_kdf_KEYBYTES);
		fprintf(fp, "Derived MAC Key (Alice):\n%s\n",temp);

		sodium_bin2hex(temp,sizeof(temp),b_macKey,crypto_kdf_KEYBYTES);
		fprintf(fp, "Derived MAC Key (Bob):\n%s\n",temp);

		if(crypto_verify_32(a_macKey,b_macKey)!=0){
			fprintf(fp, "Encryption keys do not match!\n");	
		}else{
			fprintf(fp, "Encryption keys match!\n");	
		}
		
		fclose(fp);
	}

	sodium_memzero(a_newPrivateKey,sizeof(a_newPrivateKey));
	sodium_memzero(b_newPrivateKey,sizeof(b_newPrivateKey));
	sodium_memzero(a_secretKey,sizeof(a_secretKey));
	sodium_memzero(b_secretKey,sizeof(b_secretKey));
	sodium_memzero(a_encryptionKey,sizeof(a_encryptionKey));
	sodium_memzero(b_encryptionKey,sizeof(b_encryptionKey));
	sodium_memzero(a_macKey,sizeof(a_macKey));
	sodium_memzero(b_macKey,sizeof(b_macKey));

	return 0;
}