#include "matasano.h"

/********** Problem 17 CBC Padding Oracle ********/

string paddingOracleKey;
string paddingOracleIV;

string problem17func1(string *tenStrings){
	string plaintext;

	plaintext = PKCS7PadString(base64Decode(tenStrings[rand()%10]),16);
	return AES128EncodeCBC(plaintext, paddingOracleKey, paddingOracleIV);
}

int paddingOracle(string cipher){
	return validatePKCS7Padding(AES128DecodeCBC(cipher, paddingOracleKey, paddingOracleIV));
}

string breakPaddingBlock(string prevBlock, string block, int (*oracle)(string)){
	string fakeCipher=stringCat(newString(NULL,16),block);
	string plaintext=newString(NULL, 16);
	string intermediate=newString(NULL, 16);
	int i,j;
	char padding;

	for(i=15; i>=0; i--){
		padding=16-i;
		for(j=1;j<padding;j++){
			fakeCipher.c[16-j] = (padding) ^ (intermediate.c[16-j]);
		}

		/*
		 * We start with fakeCipher.c[i] instead of 0 in case we have to jump back a character and continue where
		 * we left off, in the case of a false positive on padding validation.
		 *
		 * Note that newString(NULL, n) memsets all characters to (char)0.
		 */
		for(j=fakeCipher.c[i]; j<UCHAR_MAX; j++){
			fakeCipher.c[i]=(unsigned char)j;
			if(oracle(fakeCipher)==1) break;
		}

		intermediate.c[i] = fakeCipher.c[i] ^ padding;
		plaintext.c[i] = prevBlock.c[i] ^ intermediate.c[i];
		
		if(j==UCHAR_MAX){
			/*
			 * sometimes, the wrong previous character can lead to a false positive on padding validation.
			 * In this case, just jump back to the last character and continue checking where you left off.
			 */
			i=MIN(i+2,16);
			continue;
		}
		if(H4XX0R){
			printsprint(plaintext);
			printf("\r");
		}

	}
	return plaintext;
}

string breakPaddingOracle(string cipher, int (*oracle)(string)){
	string plaintext=newString(NULL,0);
	int numBlocks=cipher.len/16;
	string *blocks=blockString(cipher, 16);
	int i;

	for(i=1; i<numBlocks; i++){
		plaintext = stringCat(plaintext, breakPaddingBlock(blocks[i-1], blocks[i], oracle));
		if(H4XX0R){
			prints(stripPKCS7Padding(plaintext));
			printf("\r");
		}
	}
	if(H4XX0R){
		PRINTNL;
	}

	return plaintext;
}

/***** Problem 18 break CTR with fixed-nonce by substition ******/
string breakFixedNonceCTRAsRepeatedXOR(string *ciphers, int numCiphers){
	int blockLen; //shortest block length
	int i;
	string masterCipher; //concatenated shortest-block-length truncated ciphertexts
	string *cipherBlocks;
	string key;
	string range;

	//find shortest block length
	blockLen=ciphers[0].len;
	for(i=0; i<numCiphers; i++){
		if(ciphers[i].len<blockLen) blockLen=ciphers[i].len;
	}

	//concatenate shortest-block-length pieces into one
	masterCipher=newString(NULL, 0);
	for(i=0; i<numCiphers; i++){
		masterCipher=stringCat(masterCipher, newString(ciphers[i].c, blockLen));
	}

	//set range to all UCHARs for fixed-XOR breaking
	range=newString(NULL, UCHAR_MAX+1);
	for(i=0; i<UCHAR_MAX; i++){
		range.c[i]=(unsigned char)i;
	}

	//do the whole fixed single-char XOR thing
	cipherBlocks=invertBlocks(masterCipher, blockLen);
	key=newString(NULL,blockLen);
	for(i=0; i<blockLen; i++){
		key.c[i]=breakFixedXOR(cipherBlocks[i], range)[0].key.c[0];
	}

	return key;
}

string modifyKey(string keystream, string *ciphers, int numCiphers){
	int i;
	int ind1, ind2;
	char c;

	while(1){
		printf("The current keystream gives the following plaintexts:\n");
		printXORedCiphers(keystream, ciphers, numCiphers);

		printf("enter cipher number:\n");
		scanf("%i", &ind1);

		for(i=0; i<keystream.len; i++){
			printf("%i",i%10);
		}
		printf("\n");
		prints(newString(stringXOR(ciphers[ind1],keystream).c,MIN(ciphers[ind1].len,keystream.len)));
		printf("\n");

		printf("enter character number, and what that character should be\n");
		scanf("%i %c",&ind2,&c);

		if(ind2>=keystream.len){
			keystream=newString(keystream.c,ind2+1);
		}

		keystream.c[ind2]=c^ciphers[ind1].c[ind2];
	}
	return keystream;
}

void printXORedCiphers(string keystream, string *ciphers, int numCiphers){
	
	int i,l;
	for(i=0; i<numCiphers; i++){
		l=MIN(ciphers[i].len, keystream.len);
		printf("%02i: ",i);
		prints(newString(stringXOR(ciphers[i],keystream).c,l));
		printf("\n");
	}
}

/**** Problem 22 ******/

/*Understanding untempering:
 * This is the tempering routine:
 * 	a=MT[indexMT];

	b = a ^ (a >> 11)
	c = b ^ ((b<<7) & 0x9D2C5680UL);
	d = c ^ ((c<<15) & 0xEFC60000UL);
	e = d ^ (d>>18);

	To untemper:
			d ^ d>>18 only affects the rightmost 14 digits of d, so e>>18 == d>>18, so

	** d = e ^ (e>>18)

		Now,
		0xEFC60000 in binary is 11101111110001100000000000000000. The rightmost 17 digits are all 0, so the
		rightmost 17 digits of d are the same as the rightmost 17 digits of c.

		Let's look at the leftmost 15 digits:

		 d = c ^((c<<15) & 11101111110001100000000000000000)
		 	 	 	  c ^ (Cp Cq Cr Cs Ct Cu Cv Cw Cx Cy Cz C0 C1 C2 C3 ... &
		 	 	 	  	   1  1  1  0  1  1  1  1  1  1  0  0  0  1  1  ...)
		 	 =c ^ (Cp  Cq  Cr  0  Ct  Cu  Cv  Cw  Cx  Cy  0  0  0  C2  C3  ... )=
		 	 = Cap Cbq Ccr Cd Cet Cfu Cgv Chw Cix Cjy Ck Cl Cm Cn2 Co3
		     = Da  Db  Dc  Dd De  Df  Dg  Dh  Di  Dj  Dk Dl Dm Dn  Do Cp Cq Cr Cs Ct Cu Cv Cw Cx Cy Cz C0 C1 C2 C3 C4 C5



		So:
		Da = Ca ^ Cp => Da ^ Dp = Ca
		C = (D & 1110111111000110000000000000000) ^ ((D & 00000000000000011101111110001100)<<15)
		  ^ (D & 0001000000111001111111111111111)
	** c = (d & 0xEFC60000) ^ ((d<<15) & 0xEFC60000) ^ (d & (~0xEFC60000))

		To compute b from c:
		0x9D2C5680 = 0b10011101001011000101011010000000

		Ba Bb Bc Bd Be Bf Bg Bh Bi Bj Bk Bl Bm Bn Bo Bp Bq Br Bs Bt Bu Bv Bw Bx By Bz B0 B1 B2 B3 B4 B5
		1  0  0  1  1  1  0  1  0  0  1  0  1  1  0  0  0  1  0  1  0  1  1  0  1  0  0  0  0  0  0  0
		Bh 0  0  Bk Bl Bm 0  Bo 0  0  Br 0  Bt Bu 0  0  0  By 0  B0 0  B2 B3 0  B5 0  0  0  0  0  0  0

	C = Bah Bb Bc Bdk Bel Bfm Cg Ch Ci Cj Ck Cl Bmn Bnu Co Cp Cq Cr Bs Bt0 Bu Bv2 Bw3 Bx By5 Cz C0 C1 C2 C3 C4 C5
		Bah
		Ca=Ba^Bh=Ba^Bh^Bo^Bo=Ba^Ch^Co so Ba=Ca^Ch^Co
		Cd=Bd^Bk=Bd^Bk^Br^Br=Bd^Ck^Cr^Cy so Bd = Cd^Ck^Cr^Cy
		Cf=Bf^Bm^Bt^Bt^Bm^Bm
		Ct=Bt0=Bt^C0

		Cm=Bm^Bt^B0^B0=Bm^Ct^C0
		Cn^Cu = Bn
		Co = Bo
	Have to break the mask into blocks of size 7:

	b=0
	b |= (c & 1111111)
	b |= ((c>>7 & 001111111)<<7) ^ ((c & 0101101) << 7)
	b |= (c>>14 & 1111111)<<14 ^ ((c>>7 & 0110001) << 14 ) ^ (c & 0101101 & 0110001) << 14
	b |= (c>>21 & 1111111)<<21 ^ ((c>>14 & 1101001) << 21) ^ ((c>>7 & 1101001 & 0110001) <<21) ^
			(c & 1101001 & 0101101 & 0110001) << 21
	b |= (c>>28 & 1111) << 28 ^ (c >> 21 & 1001) << 28 ^ ((c>>14) & (1001) << 28 ^ (c>>7) &1 <<28 ^ c &1 <<28

	and finally,

	a = 0
	a |= b & (11111111111000000000000000000000)
	a |= (b) ^ ((b >> 11) & (111111111110000000000))
	a |= b ^ (b >>11) ^ b>>22 & (1111111111)
 */

uint32_t untemper(uint32_t y){
	uint32_t x;
	y= y ^ (y>>18);

	y=(y & 0xEFC60000) ^ ((y<<15) & 0xEFC60000) ^ (y & (~0xEFC60000));

	/*
	 * ok this could (should?) probably be written as bit-by-bit right-to-left inversion, but this'll do.
	 */
	x=0;
	x |= y &0x7F;
	x |= (((y >> 7) & 0x7F) ^ (y & 0x2D)) << 7;
	x |= (((y >> 14) & 0x7F) ^ ((y >> 7) & 0x31) ^ (y & 0x21)) << 14;
	x |= (((y >> 21) & 0x7F) ^ ((y >> 14) & 0x69) ^ ((y >> 7) & 0x21) ^	(y & 0x21)) << 21;
	x |= (((y >> 28) & 0xF) ^ ((y >> 21) & 0x9) ^ ((y >> 14) & 0x9) ^ ((y >> 7) & 0x1) ^ (y & 0x1)) << 28;

	y=0;
	y |= x & 0xFFE00000;
	y |= (x ^ (x >> 11)) & 0x1FFC00;
	y |= (x ^ (x >> 11) ^ (x >> 22)) & 0x3FF;
	return y;
}

void twistMTState(uint32_t *MTState){
	uint32_t i;
	uint32_t x;
	uint32_t xA;

	for(i=0; i<624; i++){
		x =(MTState[i] & 0x80000000) + (MTState[(i+1)%624] & 0x7fffffff);
		xA = x>>1;
		if (0x1 & x){
			xA^= 0x9908B0DF;
		}
		MTState[i]=MTState[(i+397) % 624] ^ xA;
	}
}

uint32_t MTRNGClone(uint32_t *MTState, uint32_t i){
	uint32_t y;

	if (i==624){
		twistMTState(MTState);
		i=0;
	}
	i=i%624;

	y=MTState[i];

	y ^= y>>11;
	y ^= (y<<7) & 0x9D2C5680UL;
	y ^= (y<<15) & 0xEFC60000UL;
	y ^= (y>>18);

	return y;
}

uint32_t temperTEST(uint32_t y){
	y ^= y>>11;
	y ^= (y<<7) & 0x9D2C5680;
	y ^= (y<<15) & 0xEFC60000;
	y ^= (y>>18);
	return y;
}

/************** Problem 24*************/
string MTCipher(string plaintext, uint16_t key){
	int i;
	unsigned char c;
	uint32_t rnum;
	string keystream=newString(NULL,0);
	//seed with the key
	MTRNGSeed(key & 0xffff);

	//generate keystream
	for(i=0; i<plaintext.len; i++){
		if(i%4==0){
			rnum=MTRNGNumber();
		}
		c = (rnum >> ( 8*(3-(i%4)))) & 0xFF;
		keystream = stringCat(keystream, newString((char *)(&c),1));
	}

	return stringXOR(plaintext, keystream);
}

string MTCipherWithPrefix(string plaintext, uint16_t key){
	MTRNGSeed(time(NULL));
	//append 5-10 chars before the plaintext
	plaintext=stringCat(randString(MTRNGNumber()%6+5),plaintext);
	return MTCipher(plaintext, key);

}

uint16_t breakMTCipher(string plaintext, string cipher){
	int i,j;
	int padLen = cipher.len-plaintext.len;
	int startPT = padLen + (4-padLen%4)%4;
	string randResult=stringXOR(newString(&(cipher.c[startPT]),4), newString(&(plaintext.c[startPT-padLen]),4));
	uint32_t rand = (((uint32_t)((unsigned char)randResult.c[0]))<<24) |
							 (((uint32_t)((unsigned char)randResult.c[1]))<<16) |
							 (((uint32_t)((unsigned char)randResult.c[2]))<<8)  |
							 (uint32_t)((unsigned char)randResult.c[3]);

	for(i=0; i<=0xFFFF; i++){
		MTRNGSeed(i);
		for(j=0; j<startPT/4; j++) MTRNGNumber();
		if(rand == MTRNGNumber()){
			return (uint16_t)(i & 0xFFFF);
		}
	}
	return -1;
}

string generatePasswordToken(void){
	MTRNGSeed(time(NULL));
	return MTCipher(newString(NULL, 5+MTRNGNumber()%6),time(NULL)&0xffff);
}

int checkTokenIsTime(string token){
	string zeros=newString(NULL,token.len);
	string check=MTCipher(zeros,time(NULL)&0xffff);
	return stringComp(token,check);
}
