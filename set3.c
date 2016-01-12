#include "matasano.h"

void problem17(void){
	 /*The CBC padding oracle*/
	string cipher;
	string plaintext;
	extern string paddingOracleKey;
	extern string paddingOracleIV;
	

	char * tenStringsRaw[10]={"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"};
	string tenStrings[10];
	
	paddingOracleKey=randString(16);
	paddingOracleIV=randString(16);

	for(int i=0; i<10; i++) tenStrings[i]=newString(tenStringsRaw[i],0);

	printf("Demonstrating the CBC padding oracle. Ctrl+C to stop.\n\n");
	while(1){
	cipher=problem17func1(tenStrings);
	plaintext=stripPKCS7Padding(breakPaddingOracle(cipher, paddingOracle));
	if(!H4XX0R){prints(plaintext);printf("\n");}
	}
}

void problem18(void){
	/* Implement CTR, the stream-cipher mode.*/
	string cipher=base64Decode(newString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",0));
	string key=newString("YELLOW SUBMARINE",0);
	string nonce=newString(NULL,8);
	string plaintext=AES128CTR(cipher, key, nonce);
	printf("The CTR-mode encrypted cipher \n"); printsint(cipher);printf("\ndecrypts to \n");prints(plaintext);printf("\n");
}

void problem19(void){
	/*Break fixed-nonce CTR mode using substitions
	 * 
	 *  I didn't want to do it using substitutions because it was a pain in the ass, so I did it using fixed-XOR
	 *  with a fixed keylength... which turned out to be how you're supposed to do the next problem? Oh well.
	 *  Spoiler: solutions are:
	 *      00: i have met them at close of day
	 * 		01: coming with vivid faces
	 *		02: from counter or desk among grey
	 *		03: eighteenth-century houses.
	 *		04: i have passed with a nod of the head
	 *		05: or polite meaningless words,
	 *		06: or have lingered awhile and said
	 *		07: polite meaningless words,
	 *		08: and thought before I had done
	 *		09: of a mocking tale or a gibe
	 *		10: to please a companion
	 *		11: around the fire at the club,
	 *		12: being certain that they and I
	 *		13: but lived where motley is worn:
	 *		14: all changed, changed utterly:
	 *		15: a terrible beauty is born.
	 *		16: that woman's days were spent
	 *		17: in ignorant good will,
	 *		18: her nights in argument
	 *		19: until her voice grew shrill.
	 *		20: what voice more sweet than hers
	 *		21: when young and beautiful,
	 *		22: she rode to harriers?
	 *		23: this man had kept a school
	 *		24: and rode our winged horse.
	 *		25: this other his helper and friend
	 *		26: was coming into his force;
	 *		27: he might have won fame in the end,
	 *		28: so sensitive his nature seemed,
	 *		29: so daring and sweet his thought.
	 *		30: this other man I had dreamed
	 *		31: a drunken, vain-glorious lout.
	 *		32: he had done most bitter wrong
	 *		33: to some who are near my heart,
	 *		34: yet I number him in the song;
	 *		35: he, too, has resigned his part
	 *		36: in the casual comedy;
	 *		37: he, too, has been changed in his turn
	 *		38: transformed utterly:
	 *		39: a terrible beauty is born.
	 */

	char * cipherListRaw[40]={
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
	};

	string ciphers[40];
	int i;
	string p19Key=randString(16);
	string keystream;

	for(i=0; i<40; i++){
		ciphers[i]=AES128CTR(base64Decode(newString(cipherListRaw[i],0)), p19Key, newString(NULL,8));
	}

	keystream=breakFixedNonceCTRAsRepeatedXOR(ciphers, 40);
	keystream=modifyKey(keystream, ciphers, 40);
}

void problem20(void){
	string *ciphers;
	string keystream;
	int numCiphers;
	int i;
	char *line;
	FILE *fp;
	numCiphers=0;

	fp = fopen(FILE20, "r");
	for(i=0; !feof(fp); ) if(fgetc(fp)=='\n') i++;
	fclose(fp);
	numCiphers=++i;

	ciphers=malloc(sizeof(string)*(numCiphers));

	fp=fopen(FILE20, "r");

	line=malloc(sizeof(char)*(161));
	for(i=0; i<numCiphers; i++){
		fscanf(fp, "%s", line);
		ciphers[i]=base64Decode(newString(line,0));
	}
	fclose(fp);

	keystream=breakFixedNonceCTRAsRepeatedXOR(ciphers, numCiphers);
	keystream=modifyKey(keystream, ciphers, numCiphers);
}

void problem21(void){
	//Implement the MT19937 Mersenne Twister RNG
	int i;
	printf("Ten random numbers with seed 10:\n");
	MTRNGSeed(10);
	for(i=0; i<10; i++){
		printf("A random number: %u\n", MTRNGNumber());
	}
	printf("Take two:\n");
	MTRNGSeed(10);
	for(i=0; i<10; i++){
		printf("A random number: %u\n", MTRNGNumber());
	}
	printf("Now seeded with 11:\n");

	MTRNGSeed(11);
	for(i=0; i<10; i++){
		printf("A random number: %u\n", MTRNGNumber());
	}
}

void problem22(void){
	 /*Crack an MT19937 seed*/
		//Simulating time
	uint32_t i;
	uint32_t currtime=(uint32_t)time(NULL);
	uint32_t rand;
	int seed=(int)(currtime-(40+(MTRNGNumber()%960)));
	printf("Seeding with %i.\n", seed);
	MTRNGSeed(seed);
	rand=MTRNGNumber();

	printf("Cracking seed...\n");
	for(i=currtime; i>currtime-1000; i--){
		MTRNGSeed(i);
		if(MTRNGNumber()==rand){
			printf("The seed was %u.\n",i);
			break;
		}
	}

}

void problem23(void){
	//Clone an MT19937 RNG from its output -- the untempering routine is explained in comments in set3Utils.c
	uint32_t MTState[624];
	int i;

	MTRNGNumber();

	MTRNGSeed((uint32_t)time(NULL));

	for(i=0; i<624; i++){
		MTState[i]=untemper(MTRNGNumber());
	}

	//lazy testing, the chances of the next two numbers being the same on accident is astronomically small...
	if(MTRNGNumber()==MTRNGClone(MTState, i++)){
		if(MTRNGNumber()==MTRNGClone(MTState, i++)){
			printf("Clone successful!\n");
		}
		else printf("Something failed...\n");
	}
	else printf("Something failed...\n");
}

void problem24(void){
	//Create the MT19937 stream cipher and break it

	string plaintext=newString("AAAAAAA",0);
	string cipher;
	uint16_t key;
	uint16_t brokenKey;

	MTRNGSeed((uint32_t)time(NULL));
	key=MTRNGNumber() & 0xffff;
	printf("Encrypting with key %i.\n", key);

	cipher=MTCipherWithPrefix(plaintext, key);
	brokenKey=breakMTCipher(plaintext, cipher);

	if(brokenKey==key){
		printf("The key was successfully cracked and found to be %i.\n", brokenKey);
	}
	else{
		printf("The key was not found!\n");
	}

	printf("Verifying that a token was generated from the current time:\n");
	if(checkTokenIsTime(generatePasswordToken())){
		printf("And so it was.\n");
	} else{
		printf("I guess it wasn't?\n");
	}
}

