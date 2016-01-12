#include "matasano.h"

/***** PROBLEM 11 ******/

string encryptionOracleECBCBC(string str){
	int mode = rand()%2;
	int numChars1=5+rand()%6;
	int numChars2=5+rand()%6;
	string key = randString(16);
	int i;

	string newStr=newString(NULL, str.len+numChars1+numChars2);

	for(i=0; i<numChars1; i++){
		newStr.c[i]=(char)rand()%256;
	}
	for(i=numChars1; i<numChars1+str.len; i++){
		newStr.c[i]=str.c[i-numChars1];
	}
	for(i=numChars1+str.len; i<newStr.len; i++){
		newStr.c[i]=(char)rand()%256;
	}

	if(mode==0){
		printf("Encrypting with ECB...\n");
		return AES128EncodeECB(newStr,key);
	}

	else printf("Encrypting with CBC...\n");
	return AES128EncodeCBC(newStr, key, randString(16));
}

int breakOracleECBCBC(string (*oracle)(string)){
	string plaintext=newString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0);
	string cipher = (*oracle)(plaintext);
	if(blockRepeats(cipher,16)) return 1;

	return 2;
}

/***** Problm 12 ******/

string oracleAppendPlaintext;
string oracleAppendKey;
int H4XX0R = 1;

string encryptionOracleAppend(string prefix){
	string str;

	str=stringCat(prefix, oracleAppendPlaintext);
	str=PKCS7PadString(str,16);

	return AES128EncodeECB(str, oracleAppendKey);
}

int findEncryptionBlockSize(string (*oracle)(string)){
	int len, newlen;
	string text=newString("A",0);

	len=(*oracle)(text).len;
	newlen=len;

	while(newlen==len){
		text=stringCat(text, newString("A",0));
		newlen=(*oracle)(text).len;
	}
	return newlen-len;
}

string breakOracleAppend(string (*oracle)(string)){
	string cipher=(*oracle)(newString(NULL,0));
	string ans = newString(NULL, 0);
	string block=newString(NULL, 0);
	string shiftedCipher;
	string testCipher;
	string As;
	int i;
	unsigned char k;

	printf("The encrypted hex-encoded ciphertext is: \n\n");fflush(stdout);
	printsint(cipher);
	printf("\n\nWith access to the ECB oracle, we can decode it one byte at a time as follows:\n\n");

	for(i=0; i<cipher.len; i++){
		if(i%16==0){
			As=newString("AAAAAAAAAAAAAAAA",0);
			block=stringCat(As,ans);/*length is j+(i-1), exactly one more byte needed to make a block*/
		}
		stripLeadingByte(&block);
		stripLeadingByte(&As);
		shiftedCipher=(*oracle)(As);
		block=stringCat(block, newString(NULL, 1)); /*create the extra byte at the end to loop over*/

		for(k=0; k<=CHAR_MAX; k++){
			block.c[block.len-1]=k;
			testCipher=(*oracle)(block);
			if (stringCompN(testCipher, shiftedCipher, block.len)){
				if (H4XX0R) {printf("%c", (char)k);fflush(stdout);}
				ans=stringCat(ans, newString((char *)(&k), 1));
				break;
			}
			if(k==CHAR_MAX){
				//this will happen at the end of the ciphertext, because the padding
				//changes with each trial, so it won't decrypt properly.
				//fprintf(stderr, "Impossible value k=%02x, i=%i and cipher.len=%i at line %d in file %s.\n.", k,i, cipher.len, __LINE__, __FILE__);
				//exit(1);
				continue;
			}

		}
	}
	return ans;
}

void stripLeadingByte(string *str){
	int i;
	for(i=0; i<str->len-1; i++){
		str->c[i]=str->c[i+1];
	}
	str->c[i]='\0';
	str->len--;
}

/********** Problem 13 ************/
string p13Key;

char AMPERSAND=-1;
char EQUALS=-2;
int offset=-1;

keyvalue_t parseKeyValue(string in){
	keyvalue_t r;
	int flag;
	int i;
	int l=0;
	char c;

	for(i=0; i<in.len; i++){
		if(in.c[i]=='=') l++;
	}
	r.n=l;
	r.keys=(string *)calloc(l, sizeof(string));
	r.vals=(string *)calloc(l, sizeof(string));

	r.keys[0]=NULLSTRING;
	r.vals[0]=NULLSTRING;
	flag=0;
	l=0;
	for(i=0; i<in.len; i++){
		c=in.c[i];
		if(c==AMPERSAND || c==EQUALS)
			continue;
		if(c=='='){
			flag=1;
			continue;
		}
		if(c=='&'){
			++l;
			r.keys[l]=newString("",0);
			r.vals[l]=newString("",0);
			flag=0;
			continue;
		}
		if(flag==0) r.keys[l]=stringCat(r.keys[l],newString(&(in.c[i]),1));
		if(flag==1) r.vals[l]=stringCat(r.vals[l],newString(&(in.c[i]),1));
	}
	r.encoded=newString(in.c, in.len);
	return r;
}

keyvalue_t profileFor(string email){
	string cleanEmail=newString(NULL, email.len);
	string in;
	int i,j=0;
	//remove ampersands and equal signs from email address
	for(i=0; i<email.len; i++){
		if(email.c[i]=='&' || email.c[i]=='=') continue;
		cleanEmail.c[j++]=email.c[i];
	}
	cleanEmail = newString(cleanEmail.c, j);
	in=stringCat(newString("email=",0),cleanEmail);
	in=stringCat(in, newString("&uid=10&role=user",0));
	//prints(in);printf("\n");
	return parseKeyValue(in);
}

string profileForEncrypt(string email){
	string s = PKCS7PadString(profileFor(email).encoded, 16);
	return AES128EncodeECB(s, p13Key);
}

string decodeProfile(string p){
	return AES128DecodeECB(p, p13Key);
}

int findOffset(string (*oracle)(string)){
	int len, newlen;
	string text=newString(NULL,0);

	len=(*oracle)(text).len;
	newlen=len;

	while(newlen==len){
		text=stringCat(text, newString("A",0));
		newlen=(*oracle)(text).len;
	}
	return 16-text.len;
}

/********* Problem 14 *********/

string p14Plaintext;
string p14Key;
string encryptedBBlock;

string encryptionOracleAppendRandomPrefix(string text){
	string prefix=newString(NULL,rand()%16);
	int i=0;
	while(i<prefix.len){
		prefix.c[i++]=(char)rand()%128;
	}
	return encryptionOracleAppend(stringCat(prefix,text));
}

string oracleRandomPrefixWrapper(string text){
	string newText=stringCat(newString("BBBBBBBBBBBBBBBBB",0),text); //len=32-15=17
	string block2;
	string cipher;
	do{
		cipher=encryptionOracleAppendRandomPrefix(newText);
		block2=newString(&(cipher.c[16]),16);
	}while(stringCompN(block2,encryptedBBlock,16)==0);
	return newString(&(cipher.c[32]),cipher.len-32);
}

/************* Problem 16 ************/
string p16Key;

string problem16function1(string in){
	string s1=newString("comment1=cooking%20MCs;userdata=",0);
	string s2=newString(";comment2=%20like%20a%20pound%20of%20bacon",0);
	string text=in;
	text=stripChars(text, newString("=;",0));
	text=stringCat(s1, text);
	text=stringCat(text, s2);
	text=PKCS7PadString(text, 16);
	return AES128EncodeCBC(text, p16Key, newString(NULL,16));
}

int isAdmin(string cipher){
	string text = AES128DecodeCBC(cipher, p16Key,newString(NULL,16));
	int i;
	string admin=newString(";admin=true;",0);
	for(i=0; i<text.len-admin.len; i++){
		if(text.c[i]!=admin.c[0]) continue;
		if(stringCompN(newString(&(text.c[i]), admin.len), admin, admin.len)) return 1;
	}
	return 0;
}

string createAdmin(string (*oracle)(string)){
	/*
	 * the character ':' has value 00111010
	 * the character ';' has value 00111011
	 *
	 * '<' is also even while '=' = '<'+1
	 * so we create a nonsense block, and put :admin<true: in the next block.
	 * encode the whole thing, and in the cipher, add 1 to the positions of the colons-16
	 * to ensure that the colons get changed to semicolons.
	 * Then we can delete the nonsense block (if we want, doesn't really matter).
	 *
	 * Problem: since we don't know the offset in the input, we can't be sure that ':admin=true:
	 * 	isn't getting broken up into two different blocks. To solve this, try 12 different
	 * 	nonsense-block lengths, and return the first one that decrypts to an admin profile.
	 */
	string fakeInput=newString("AAAAAAAAAAAAAAAA:admin<true:",0);
	string cipher;
	int colPos1=16, colPos2=27, eqPos=22;
	do{
		cipher=(*oracle)(fakeInput);
		cipher.c[32+colPos1-16]^=0x1;
		cipher.c[32+colPos2-16]^=0x1;
		cipher.c[32+eqPos-16]^=0x1;

		fakeInput=stringCat(newString("A",1),fakeInput);
		++colPos1; ++colPos2; ++eqPos;
	}while(!isAdmin(cipher));
	return cipher;
}


