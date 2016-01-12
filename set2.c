#include "matasano.h"

void problem9(void){
		printsint(PKCS7PadString(newString("YELLOW SUBMARINEYELLOW", 0),20));
		PRINTNL;
}

void problem10(void){
	char *inputChars=malloc(sizeof(char)*100);
	string cipher;
	FILE *fp;
	int c, i;
	string out;
	string IV = newString(NULL,16);
	string key = newString("YELLOW SUBMARINE",0);
	string redecoded; //for testing the CBC routines

	fp=fopen(FILE10, "r");
	i=0;
	while((c=fgetc(fp))!=EOF){
		if(c=='\n') continue;
		inputChars[i++]=c;
		if(i%100==0){
			inputChars=realloc(inputChars, sizeof(char)*(i+100));
		}
	}

	inputChars=realloc(inputChars, sizeof(char)*(i+1));
	inputChars[i]='\0';
	cipher = PKCS7PadString(base64Decode(newString(inputChars,i)), 16);
	free(inputChars);
	
	printf("Decoded:\n");
	out = stripPKCS7Padding(AES128DecodeCBC(cipher, key, IV));
	prints(out); PRINTNL;
	
	//test whether encryption-decryption works as it should:
	redecoded = stripPKCS7Padding(AES128DecodeCBC(AES128EncodeCBC(out, key,  IV),key,IV));
	
	printf("\nTesting CBC routines...");
	if(stringComp(redecoded, out)==1){
		printf("CBC routines check out.\n");
	}
	else {
		printf("CBC routines failed.\n");
	}
}

void problem11(void){
	/* An ECB/CBC detection oracle*/
	int ans;
	ans=breakOracleECBCBC(encryptionOracleECBCBC);
	if(ans==1)printf("Detected ECB mode.\n");
	if(ans==2)printf("Detected CBC mode.\n");
}

void problem12(void){
	/* Byte-at-a-time ECB decryption*/
	string ans;
	int blocksize;
	
	extern string oracleAppendPlaintext;
	extern string oracleAppendKey;


	oracleAppendPlaintext=base64Decode(newString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga"
			"GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQp"
			"EaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",0));
	oracleAppendKey=randString(16);;
	printf("The encryption oracle's block size is: %i\n", blocksize=findEncryptionBlockSize(encryptionOracleAppend));
	printf("Is the oracle encrypting in ECB mode?\n");
	ans=encryptionOracleAppend(newString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",0));
	if(blockRepeats(ans,16)){
			printf("\tYES...now we can BREAK it!\n\n");
			ans=breakOracleAppend(encryptionOracleAppend);
			if(!H4XX0R)prints(ans);
	}else printf("\tNO. BYE.\n");
	PRINTNL;
}

void problem13(void){
	/*      ECB cut-and-paste
	 *
	 *      This solution relies on foreknowledge of the fact that the last entry is "role=user".
	 *
	 *      we just push it out until the last block is only "user", and replace it with the cipher for "admin".
	 *
	 *      how to find out what the encoded profiles look like if you can't input & or = ?
	 *      Personally, I consider this solution incomplete, as it requires more knowledge than it seems
	 *      	the attacker actually has....
	 */
	string userCipher, adminCipher;
	string padding;
	
	extern string p13Key;
	extern int offset;
	H4XX0R=1;

	p13Key=randString(16);

	//get a cipher so that the last block contains 'user0xc0xc0xc....'
	//so the profile is email=0000000000 000&uid=10&role= user
	offset=findOffset(profileForEncrypt);
	padding=newString("utrust@me.com", 0);
	userCipher=profileForEncrypt(padding);

	//get rid of the last block:
	userCipher=newString(userCipher.c, userCipher.len-16);

	//get a cipher so that the second block contains 'admin0xB0xB0xB...'
	//so the profile being encrypted is email=0000000000 admin0xB0xB0xB0xB0xB0xB0xB0xB0xB0xB0xB &uid=10&role=user
	padding=stringCat(newString("AAAAAAAAAAAAAAAA", 16-(offset-1)),PKCS7PadString(newString("admin",0),16));
	adminCipher=profileForEncrypt(padding);

	//append the second block to the end of the userCipher:
	adminCipher=stringCat(userCipher, newString(&(adminCipher.c[16]),16));

	//and now check that it decrypts to an admin profile:
	printf("The following profile has been created: \n");
	prints(stripPKCS7Padding(decodeProfile(adminCipher)));
	PRINTNL;
}

void problem14(void){
	/*
	 *      Byte-at-a-time ECB decryption (harder)
	 *		Using the 32-byte plaintext BBB...B, record the 2nd block of the ciphertext.
	 *      Write a wrapper oracle function which uses prefixes 17 B's (assuming 0-15 random characters are
	 *      prefixed) and waits until the second block of the cipher is all B's (by comparing to the block recorded
	 *      above), and then returns the rest of the ciphertext. Note that B is used because the byte-at-a-time
	 *      decryptor uses all A's, so if A's were used then the wrapper would be tricked into thinking there are
	 *      more A's than there actually are, and would return the wrong ciphertext.
	 *      For completeness, we should first figure out what the max length of the random prefix is... this is
	 *      not mathematically difficult but pretty tedious, especially in C, so I'm just going to let
	 *      the length vary 0-15.
	 */
	extern string oracleAppendPlaintext;
	extern string oracleAppendKey;
	extern string encryptedBBlock;

	oracleAppendPlaintext=base64Decode(newString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga"
			"GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQp"
			"EaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",0));
	oracleAppendKey=randString(16);
	H4XX0R=1;

	encryptedBBlock=newString(&(encryptionOracleAppend(newString("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",0)).c[16]),16);
	breakOracleAppend(oracleRandomPrefixWrapper);
}

void problem15(void){
	string test;
	char asdf[]={0x2, 0x5, 0x02, 0x02};
	test=newString(asdf,4);
	printf("Is "); printsint(test); printf(" correctly padded?\n");
	printf("Answer: ");
	if(validatePKCS7Padding(test))printf("YES.\n"); else printf("NO.\n");

	test=PKCS7PadString(test,16);
	printf("And is\n"); printsint(test); printf("\n? Let's strip the padding: \n");
	printsint(stripPKCS7Padding(test));
	PRINTNL;
}

void problem16(void){
	string cipher;
	extern string p16Key;
	p16Key=randString(16);

	//cipher=problem16function1(newString(";admin=true",0));
	//printf("%i\n", isAdmin(cipher));
	cipher=createAdmin(problem16function1);

	if(isAdmin(cipher)){
		printf("Admin profile created!\n");
	}
}

