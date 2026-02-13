#############################Assignment 02 ###################################
##############################################################################
#############################Assignment 02 - Task 1###########################

##############################################################################
Description of Project:
This project implements a command-line tool that performs Elliptic Curve Diffie-Hellman (ECDH) key exchange with key derivation functionality using libsodium. The program generates cryptographic key pairs , performs secure key exchange and derives encryption and MAC keys from the shared secret.

##############################################################################

Features:
**Key Generation**:
Checks if private keys have been provided and if not generates private keys for Alice and Bob with the use of:crypto_kx_keypair(a_publicKey,a_newPrivateKey).
**Public Key computation**:Computes public keys from the corresponding private keys, since Public=Private*G, which in code is crypto_scalarmult_base(b_publicKey,b_newPrivateKey).
**Shared secret computation**:Performs ECDH to compute shared secrets, since Secret=puclic*private, which in code is crypto_scalarmult(a_secretKey,a_newPrivateKey,b_publicKey);
**Secret Verification**:Verifies the shared secret by checking if they match with the help of crypto_verify_32().
**Key Derivation**:Derives two symmetric keys (Encryption Key and MAC Key) using crypto_kdf_derive_from_key()
**File Output**:Outputs all keys and shared secrets to a specified file
**Security**:Wipes all sensitive data

##############################################################################

Usage:
To use this tool it is essential to have installed the libsodium library. That can be managed by running the following command: 
sudo apt-get install libsodium-dev
Following this step, the next one is to compile the program wich can be done with:
gcc -o ecdh_assign_2 ecdh_assign_2.c -lsodium
Having done all the preparation we can start running the program with the command displayed below:
./ecdh_assign_2 -o output file -a Alice's private key -b Bob's private key -c content string -h help message
From all of the options displayed above only the output file is required. The rest, if not provided, the tool will generate it's own keys and set its own context.
The program, will save in the provided output file all public keys, shared secrets, encryption Keys and MAC keys.

##############################################################################

Output Format:
The output file will look like:
Alice's Public Key:
<Her key, in hexadecimal format>
Bob's Public Key:
<His key, in hexadecimal format>
Shared Secret (Alice):
<The shared secret she computed, in hexadecimal format>
Shared Secret (Bob):
<The shared secret he computed, in hexadecimal format>
<Confirmation or Negative response based on if the two secrets match>
Derived Encryption Key (Alice):
<The Encryption key she derived to, in hexadecimal format>
Derived Encryption Key (Bob):
<The Encryption key he derived to, in hexadecimal format>
<Confirmation or Negative response based on if the two encryption keys match>
Derived MAC Key (Alice):
<The MAC key she derived to, in hexadecimal format>
Derived MAC Key (Bob):
<The MAC key she derived to, in hexadecimal format>
<Confirmation or Negative response based on if the two mac keys match>

############################################################################################################################################################

#############################Assignment 02 - Task 2###########################

##############################################################################

Description of Project:

This project implements a The RSA (Rivest–Shamir–Adleman) algorithm. In more detail this program has 6 key functions: key generation, encryption, decryption, Signature making and Verification we also do a Performance analysis for different key lengths. The program creates keys and variables by using prime numbers. Then we use these keys to encrypt/decrypt our data. After this, we use the hash function to create and verify the signature of the key.


##############################################################################


Features:

**Key Generation**: We generate random prime numbers by creating a random number and the increase it until we find a prime. This is accomplished by the usage of the Miller-Rabin Primality Test. Which is a probabilistic estimation that our number is a prime. We repeat this prosses many times: mpz_urandomb(pstate,half_length); while(mpz_probab_prime_p(p,50)>0 && tries_for_p<1000).Having generated our prime numbers we calculate the rest of the variables n,d,e,lambda.
n=p * q
lambda=(p - 1) * (q - 1)
e: is a prime number that e % lambda!= 0 AND gcd(e, lambda)==1
d: is the modular inverse of e

Finally we save our two keys, the public one(n,e) and the private one(n,d) in two different files.

** Encryption**:
We encrypt our data by with the following line of code mpz_powm(ciphertext, plaintext, e, n). In more detail we read the public key file which contains (n,e) by opening the public key file and then by using the fuction: mpz_inp_str(n, fpKey, 16).Simillarly for e. After this we open the input file and read the context and we transform it into a mpz hex form : mpz_import(plainText, input_file_size, 1, 1, 0, 0, info). This is needed for the calculation of the ciphertext because we can't do the calculation directly. At last we save the ciphertext to an output file: gmp_fprintf(fpOutput, "%Zx\n", cipherText).

**Decryption** :
In Decryption we use similar methods. First of all, we read the private keys (n,d) from their file the same way as before. We also read the input file the exact same way the only difference is that we do a different calculation: mpz_powm (plainText, cipherText, d, n).

** Signature**:
For singing we need to use the hash function. The hash function is a function which takes any input of any size and turns it to an unique 256 bit sting of text(letters and numbers). This process is not reversable, that’s why we use it for creating a unique signature. In more detail our signing function reads the keys the same way as before. After this we read the input file and with the usage of the hash function we transform our input to an hash number : SHA256_Final(hash, &hash_ctx). After that, we make the singature using: mpz_powm (signature, hash_num, d, n).Lastly, we save the signature to an output File.

** Verification**
Verification is the reverse process of the signing method.Like before, we read the private keys(n,e), then we read the singnature wuth the use of: mpz_inp_str(signature, fpSignature, 16).Having done that, we calculate mpz_powm (hash1,signature, e, n), wich gives us the hash.Finally, we compare the two hashes and the hash of the input if (mpz_cmp(hash_num, hash1) == 0 ).Depending on the equallity or not we print the right message(Signature is VALID or Signature is INVALID).

** Performance analysis**
The Performance analysis calls the whole too from generation to Verification and we calculate the time and memory needed to complete the tasks.

############################################################################

Usage:
To use this tool it is essential to have installed the gmp and crypto library. That can be managed by running the following command: 
sudo apt-get install libgmp-dev
sudo apt-get install libcrypto-dev
Following this step, the next one is to compile the program wich can be done with:
gcc -o rsa_assign_2 rsa_assign_2.c -lgmp -lcrypto
Or just using our Makefile and writing in the terminal:
make
Having done all the preparation we can start running the program with the command displayed below:
./rsa_assign_2 <options>

-i path Path to the input file
-o path Path to the output file
-k path Path to the key file
-g length Perform RSA key-pair generation given a key length "length"
-d Decrypt input and store results to output
-e Encrypt input and store results to output
-s Sign input file and store signature to output
-v path Verify signature (path to signature file) against input file
-a Performance analysis with three key lengths (1024, 2048, 4096)
-h This help message

From all of the options displayed above the arguments "i", "o", and "k" are always required when using "e", "d", or "s".
Also, when using "-v", you need "-i" (plaintext), "-k" (public key), and the path after "-v".
