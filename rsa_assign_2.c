#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gmp.h>
#include <time.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <openssl/sha.h>

long get_peak_memory_kb() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss; 
    }
    return 0;
}

void helpMessage(){
	printf("-i path\tPath to the input file\n-o path\tPath to the output file\n-k path\tPath to the key file\n-g lenght\tPerform RSA key-pair generation given a key length\n-d\tDecrypt input and store results to output\n-e\tEncrypt input and store results to output\n-s\tSign input file and store signature to output\n-v path\tVerify signature (path to signature file) against input file\n-a\tPerformance analysis with three key lengths (1024, 2048, 4096)\n-h\tThis help message\n");
}

int RsaGenerate(int key_length,const char* privateKey_file,const char* publicKey_file){
	mpz_t p, q,n,lambda,p1,q1,e,gcd_val,mod_val,d;
    gmp_randstate_t state;
    bool check=false;
   
    mpz_init(p);
	mpz_init(q);
	mpz_init(n);
	mpz_init(lambda);
	mpz_init(p1);
	mpz_init(q1);
	mpz_init(e);
	mpz_init(gcd_val);
	mpz_init(mod_val);
	mpz_init(d);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    //check key_length
    if(key_length != 1024 && key_length != 2048 && key_length != 4096){
        printf("Key length must be 1024, 2048, or 4096\n");
        return -1;
    }
    

    mpz_urandomb(p, state, key_length/2);
    if(mpz_probab_prime_p(p, 20) == 0){
        mpz_nextprime(p, p);
    }
    
    mpz_urandomb(q, state, key_length/2);
    if(mpz_probab_prime_p(q, 20) == 0){
        mpz_nextprime(q, q);
    }
    
    mpz_mul(n, p, q);

    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lambda, p1, q1);
    
    mpz_set_ui(e,65537);
    mpz_gcd(gcd_val,e,lambda);
	mpz_mod(mod_val,e,lambda);
    if(mpz_cmp_ui(gcd_val,1)!=0 || mpz_cmp_ui(mod_val,0)==0){
	    do{
	        mpz_urandomb(e, state, key_length/2);
	        if(mpz_probab_prime_p(e, 20) == 0)
	            mpz_nextprime(e, e);
	        	mpz_mod(mod_val, e, lambda);
	        	mpz_gcd(gcd_val, e, lambda);
	        if (mpz_cmp_ui(mod_val, 0) != 0 && mpz_cmp_ui(gcd_val, 1) == 0) //compare an mtz number
	            check=true;
	    }while (!check);
    }

    if (mpz_invert(d, e, lambda) == 0) {
        printf("Cannot compute modular inverse.");
        return -1;
    }
    
    FILE* fpPub = fopen(publicKey_file, "w");
    if (fpPub == NULL) {
        printf("Cannot create Public Key file");
        return -1;
    }
    gmp_fprintf(fpPub, "%Zx %Zx", n, e);  // Hex format
    fclose(fpPub);

    
    FILE *fpPriv = fopen(privateKey_file, "w");
    if (fpPriv == NULL) {
        printf("Cannot create Private Key file");
        return -1;
    }
    gmp_fprintf(fpPriv, "%Zx %Zx", n, d);  // Hex format
    fclose(fpPriv);

    mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(lambda);
	mpz_clear(p1);
	mpz_clear(q1);
	mpz_clear(e);
	mpz_clear(gcd_val);
	mpz_clear(mod_val);
	mpz_clear(d);
    gmp_randclear(state);
    
    return 0;
}

int RsaEncrypt(const char* inputFilePath, const char* outputFilePath, const char* keyFilePath){

    FILE* fpKey= fopen(keyFilePath,"r");
	FILE* fpInput= fopen(inputFilePath,"rb");
	FILE* fpOutput= fopen(outputFilePath,"w");

	if(!fpKey || !fpInput || !fpOutput){
		if(fpKey){
			fclose(fpKey);
			printf("Cannot find Key File");
		} 
		if(fpInput){
			fclose(fpInput);
			printf("Cannot find Input File");
		} 
		if(fpOutput){
			fclose(fpOutput);
			printf("Cannot find Output File");
		}
		return -1;
	}

    mpz_t n,e ,plainText, cipherText;
    unsigned char *info;
    long input_file_size;

    mpz_init(n);
	mpz_init(e);
	mpz_init(plainText);
	mpz_init(cipherText);
    
    if (mpz_inp_str(n, fpKey, 16) == 0) {
        printf("Cannot get n");
        return -1;
    }

    if (mpz_inp_str(e, fpKey, 16) == 0) {
        printf("Cannot get e");
        return -1;
    }
    fclose(fpKey);

    fseek(fpInput, 0, SEEK_END);
    input_file_size = ftell(fpInput);
    fseek(fpInput, 0, SEEK_SET);
    
    info = malloc(input_file_size);
    if (info == NULL) {
        printf("Error: Memory allocation failed\n");
        fclose(fpInput);
		fclose(fpOutput);
		mpz_clear(n);
		mpz_clear(e);
		mpz_clear(plainText);
		mpz_clear(cipherText);
        return -1;
    }

    fread(info, 1, input_file_size, fpInput);
    fclose(fpInput);
    
    mpz_import(plainText, input_file_size, 1, 1, 0, 0, info);

    mpz_powm (cipherText, plainText, e, n);

    if (fpOutput == NULL) {
        printf("Error: Cannot write in output file\n");
        return -1;
    }

    gmp_fprintf(fpOutput, "%Zx\n", cipherText);  // Hex format
    fclose(fpOutput);

    mpz_clear(n);
	mpz_clear(e);
	mpz_clear(plainText);
	mpz_clear(cipherText);
    free(info);
    
    return 0;
}

int RsaDecrypt (const char* inputFilePath, const char* outputFilePath, const char* keyFilePath)
{   
    FILE* fpKey= fopen(keyFilePath,"r");
	FILE* fpInput= fopen(inputFilePath,"r");
	FILE* fpOutput= fopen(outputFilePath,"wb");

	if(!fpKey || !fpInput || !fpOutput){
		if(fpKey){
			fclose(fpKey);
			printf("Cannot find Key File");
		} 
		if(fpInput){
			fclose(fpInput);
			printf("Cannot find Input File");
		} 
		if(fpOutput){
			fclose(fpOutput);
			printf("Cannot find Output File");
		}
		return -1;
	}

    mpz_t n,d,plainText, cipherText;

    mpz_init(n);
	mpz_init(d);
	mpz_init(plainText);
	mpz_init(cipherText);
    
    if (mpz_inp_str(n, fpKey, 16) == 0) {
    	printf("Cannot get n");
    	return -1;
    }

    if (mpz_inp_str(d, fpKey, 16) == 0) {
        printf("Cannot get d");
        return -1;
    }

    fclose(fpKey);

    while(mpz_inp_str(cipherText, fpInput, 16) != 0) {
        
        mpz_powm (plainText, cipherText, d, n);
        size_t bytes_written;
        unsigned char * plaintext_buff = mpz_export(NULL,&bytes_written,1,1,0,0,plainText);
        fwrite(plaintext_buff, 1, bytes_written, fpOutput);
        free(plaintext_buff);
    }
    
    fclose(fpInput);
    fclose(fpOutput);

   	mpz_clear(n);
	mpz_clear(d);
	mpz_clear(plainText);
	mpz_clear(cipherText);
   
    return 0;

}

int RsaSign(const char* inputFilePath,const char* outputFilePath,const char* keyFilePath){
	FILE* fpKey= fopen(keyFilePath,"r");
	FILE* fpInput= fopen(inputFilePath,"rb");
	FILE* fpOutput= fopen(outputFilePath,"w");

	if(!fpKey || !fpInput || !fpOutput){
		if(fpKey){
			fclose(fpKey);
			printf("Can not find Key File");
		} 
		if(fpInput){
			fclose(fpInput);
			printf("Can not find Input File");
		} 
		if(fpOutput){
			fclose(fpOutput);
			printf("Can not find Output File");
		}
		return -1;
	}

	mpz_t n,d,signature,hash_num;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX hash_ctx;
	long input_file_size;

	mpz_init(n);
	mpz_init(d);
	mpz_init(signature);
	mpz_init(hash_num);

    if (mpz_inp_str(n, fpKey, 16) == 0)
    {
    	printf("Cannot get n");
        return -1;
    }

    if (mpz_inp_str(d, fpKey, 16) == 0)
    {
    	printf("Cannot get d");
        return -1;
    }
    fclose(fpKey);

    fseek(fpInput, 0, SEEK_END);
    input_file_size = ftell(fpInput);
    fseek(fpInput, 0, SEEK_SET);
    
    SHA256_Init(&hash_ctx);

    unsigned char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fpInput)) > 0)
    {
      SHA256_Update(&hash_ctx, buffer, bytes_read);
    }
    
    SHA256_Final(hash, &hash_ctx);
    mpz_import(hash_num, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_powm (signature, hash_num, d, n);
	gmp_fprintf(fpOutput, "%Zx\n", signature);
	
	fclose(fpOutput);
    fclose(fpInput);
	
	mpz_clear(n);
	mpz_clear(d);
	mpz_clear(signature);
	mpz_clear(hash_num);

  	return 0;
}

int RsaVerify(const char* inputFilePath,const char* keyFilePath,const char* signatureFilePath,int skip){
	FILE* fpKey= fopen(keyFilePath,"r");
	FILE* fpInput= fopen(inputFilePath,"rb");
	FILE* fpSignature= fopen(signatureFilePath,"r");

	if(!fpKey || !fpInput || !fpSignature){
		if(fpKey){
			fclose(fpKey);
			printf("Can not find Key File");
		} 
		if(fpInput){
			fclose(fpInput);
			printf("Can not find Input File");
		} 
		if(fpSignature){
			fclose(fpSignature);
			printf("Can not find Signature File");
		}
		return -1;
	}

	mpz_t n,e,signature,hash_num,hash1;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX hash_ctx;
	long input_file_size;

	mpz_init(n);
	mpz_init(e);
	mpz_init(signature);
	mpz_init(hash1);
	mpz_init(hash_num);

    if (mpz_inp_str(n, fpKey, 16) == 0)
    {
        printf("Cannot get n");
    	return -1;
    }

    if (mpz_inp_str(e, fpKey, 16) == 0)
    {
        printf("Cannot get e");
    	return -1;
    }
    fclose(fpKey);

    if (mpz_inp_str(signature, fpSignature, 16) == 0) {
        printf("Cannot get signature\n");
        return -1;
    }

    fseek(fpInput, 0, SEEK_END);
    input_file_size = ftell(fpInput);
    fseek(fpInput, 0, SEEK_SET);

    SHA256_Init(&hash_ctx);

    unsigned char buffer[4096];
    size_t bytes_read;
 

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fpInput)) > 0)
    {
    	SHA256_Update(&hash_ctx, buffer, bytes_read);
    }

    SHA256_Final(hash, &hash_ctx);
    mpz_import(hash_num, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_powm (hash1,signature, e, n);
    
    fclose(fpInput);
    fclose(fpSignature);

    if(skip==1){
    	if (mpz_cmp(hash_num, hash1) == 0)
    		{
    			printf("Signature is VALID");
    	}else{
    		printf("Signature is INVALID");
    	}
    }
    
    mpz_clear(n);
	mpz_clear(e);
	mpz_clear(signature);
	mpz_clear(hash_num);
	mpz_clear(hash1);

    return 0;
}

void PerformanceAnalysis(const char* performanceFilePath,const char* privateKey_file,const char* publicKey_file){
	int key_lenghts[]={1024,2048,4096};
	clock_t start,end;
	long memory_before,memory_after;
	char encryptTestfile[50];
	char decryptTest_file[50];
	char signTest_file[50];

	FILE* fpPerfAnalysis= fopen(performanceFilePath,"w");
	if(fpPerfAnalysis==NULL){
		printf("Can not find Performance File");
	}

	FILE* fpTest=fopen("plainText.txt","w");
	fprintf(fpTest,"This is a test sentence for our file. It is meant to be the subject of the Test that will be run in a bit.");
	fclose(fpTest);

	for(int i=0;i<=2;i++){
		sprintf(privateKey_file, "private_%d.key", key_lenghts[i]);
        sprintf(publicKey_file, "public_%d.key", key_lenghts[i]);
		RsaGenerate(key_lenghts[i],privateKey_file,publicKey_file);
	}
	for(int i=0;i<=2;i++){
		sprintf(privateKey_file, "private_%d.key", key_lenghts[i]);
        sprintf(publicKey_file, "public_%d.key", key_lenghts[i]);
        fprintf(fpPerfAnalysis, "\nKey Length:%d bits \n", key_lenghts[i]);
        sprintf(encryptTestfile, "encryption_%d.txt", key_lenghts[i]);
        sprintf(decryptTest_file, "decryption_%d.txt", key_lenghts[i]);
        sprintf(signTest_file, "signing_%d.txt", key_lenghts[i]);

        start=clock();
        RsaEncrypt("plainText.txt",encryptTestfile,publicKey_file);
        end= clock();
        fprintf(fpPerfAnalysis,"Encryption Time: %.4fs\n",((double)end-start)/CLOCKS_PER_SEC);
        
        start=clock();
        RsaDecrypt(encryptTestfile,decryptTest_file,privateKey_file);
        end= clock();
        fprintf(fpPerfAnalysis,"Decryption Time: %.4fs\n",((double)end-start)/CLOCKS_PER_SEC);
        
        start=clock();
        RsaSign("plainText.txt",signTest_file,privateKey_file);
        end= clock();
        fprintf(fpPerfAnalysis,"Signing Time: %.4fs\n",((double)end-start)/CLOCKS_PER_SEC);
		
		start=clock();
        RsaVerify("plainText.txt",publicKey_file,signTest_file,0);
        end= clock();
        fprintf(fpPerfAnalysis,"Verification Time: %.4fs\n",((double)end-start)/CLOCKS_PER_SEC);

        fprintf(fpPerfAnalysis,"\n");

        memory_before=get_peak_memory_kb();
        RsaEncrypt("plainText.txt",encryptTestfile,publicKey_file);
        memory_after = get_peak_memory_kb();
        fprintf(fpPerfAnalysis, "Peak Memory Usage(Encryption): %ld KB\n", memory_after-memory_before);
        
        memory_before=get_peak_memory_kb();
        RsaDecrypt(encryptTestfile,decryptTest_file,privateKey_file);
        memory_after = get_peak_memory_kb();
        fprintf(fpPerfAnalysis, "Peak Memory Usage(Decryption): %ld KB\n", memory_after-memory_before);
        
        memory_before=get_peak_memory_kb();
        RsaSign("plainText.txt",signTest_file,privateKey_file);
        memory_after = get_peak_memory_kb();
        fprintf(fpPerfAnalysis, "Peak Memory Usage(Signing): %ld KB\n", memory_after-memory_before);
        
        memory_before=get_peak_memory_kb();
  		RsaVerify("plainText.txt",publicKey_file,signTest_file,0);
        memory_after = get_peak_memory_kb();
        fprintf(fpPerfAnalysis, "Peak Memory Usage(Verification): %ld KB\n", memory_after-memory_before);

        fprintf(fpPerfAnalysis,"\n");
	}
	fclose(fpPerfAnalysis);
}

int main(int argc,char* argv[]){
	int opt;
	char* inputFilePath=NULL;
	char* outputFilePath=NULL;
	char* keyFilePath=NULL;
	char* signatureFilePath=NULL;
	char* performanceFilePath=NULL;
	int key_lenght=0;
	bool encrypt=false,decrypt=false,sign=false;
	char privateKey_file[50];
	char publicKey_file[50];


	while((opt=getopt(argc,argv,"i:o:k:g:desv:a:h"))!=-1){
		switch(opt){
			case 'i':
				inputFilePath=optarg;
				break;
			case 'o':
				outputFilePath=optarg;
				break;
			case 'k':
				keyFilePath=optarg;
				break;
			case 'g':
				key_lenght=atoi(optarg);
				break;
			case 'd':
				decrypt=true;
				break;
			case 'e':
				encrypt=true;
				break;
			case 's':
				sign=true;
				break;
			case 'v':
				signatureFilePath=optarg;
				break;
			case 'a':
				performanceFilePath=optarg;
				break;
			case '?':
				return 1;
		}
	}

	if(performanceFilePath!=NULL){
		PerformanceAnalysis(performanceFilePath,privateKey_file,publicKey_file);
		return 0;
	}

	if (key_lenght>0)
	{
		sprintf(privateKey_file,"private_%d.key",key_lenght);
		sprintf(publicKey_file,"public_%d.key",key_lenght);
		return RsaGenerate(key_lenght,privateKey_file,publicKey_file);
	}
	if (decrypt)
	{
		if (inputFilePath==NULL || outputFilePath==NULL || keyFilePath==NULL)
		{
			printf("Missing file paths for decryption\n");
			return 1;
		}
		else{
			return RsaDecrypt(inputFilePath,outputFilePath,keyFilePath);
		}
	}

	if (encrypt)
	{
		if (inputFilePath==NULL || outputFilePath==NULL || keyFilePath==NULL)
		{
			printf("Missing file paths for ecryption\n");
			return 1;
		}
		else{
			return RsaEncrypt(inputFilePath,outputFilePath,keyFilePath);
		}
	}

	if (sign)
	{
		if (inputFilePath==NULL || outputFilePath==NULL || keyFilePath==NULL)
		{
			printf("Missing file paths for signing\n");
			return 1;
		}
		else{
			return RsaSign(inputFilePath,outputFilePath,keyFilePath);
		}
	}

	if (signatureFilePath!=NULL)
	{
		if (inputFilePath==NULL || keyFilePath==NULL || signatureFilePath==NULL)
		{
			printf("Missing file paths for verification\n");
			return 1;
		}
		else{
			return RsaVerify(inputFilePath,keyFilePath,signatureFilePath,1);
		}
	}

	printf("No valid operation chosen.Use -h for help\n");
	return 1;
}