#include "matasano.h"

void problem1(void){
	/*Convert hex to base-64*/
	string in=newString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", 0);
	printf("Converting the hex number to base64:\n");
	prints(in);PRINTNL;
	printf("The base-64 number is:\n");
	prints(base64Encode(base16Decode(in)));
	PRINTNL;
}

void problem2(void){
	/* Fixed XOR*/
	string in1, in2;

	in1=base16Decode(newString("1c0111001f010100061a024b53535009181c", 0));
	in2=base16Decode(newString("686974207468652062756c6c277320657965", 0));
	printf("XORing the following strings: \n");
	printsint(in1); printf(" ^ \n");
	printsint(in2); printf(" = \n");
	printsint(stringXOR(in1, in2));PRINTNL;
}

void problem3(void){
	/* Single-byte XOR cipher 
	 * IDEA:
	 * cipher and set of chars to xor against (range) are sent to singleCharXORDecode.
	 * This function XORs the cipher against each, and evaluates the likelihood that the result is plaintext english by computing
	 * the character frequency using the function computeCharFreq, and comparing this to the ETAOINSHRDLU frequencies by calling
	 * compareCharFreq. A lower score is better.
	 * The result of all the XORing is stored in a scoredStr_t[].
	 * The scoredStr_t[] is sorted with best (lowest) scoring results first.
	 */
	string cipher;
	code_t *answers;

	cipher=newString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",0);
	answers=breakFixedXOR(base16Decode(cipher), newString(NULL,0));

	printf("The key is %s and the answer is is\n\t\"%s\"\nwith a score of %f. The next best string has a score of %f.", answers[0].key.c, answers[0].plaintext.c, answers[0].score, answers[1].score);
	PRINTNL;
}

void problem4(void){
	/*Detect single-character XOR*/
	FILE *fp;
	int min;
	string *ciphers;
	string fileLoc=newString(FILE4,0);
	code_t **broken;
	char *line;
	int i, fileLen;
	extern int cipherLength;

	/* Get the number of lines in the file i.e. the number of ciphers. */
	fp = fopen(fileLoc.c, "r");
	for(i=0; !feof(fp); ) if(fgetc(fp)=='\n') i++;
	fclose(fp);
	fileLen=++i;
	ciphers = calloc(fileLen, sizeof(string));
	broken = calloc(fileLen, sizeof(code_t *));
	fp=fopen(fileLoc.c, "r");

	/* Read the ciphers from the file and break them one by one. */
	line=calloc(cipherLength+1,sizeof(char));
	for(i=0; i<fileLen; i++){
		fscanf(fp, "%s", line);
		ciphers[i]=newString(line,0);
		broken[i] = breakFixedXOR(base16Decode(ciphers[i]), newString(NULL,0));
	}
	fclose(fp);

	/*Find the broken plaintext with the best (lowest) score*/
	min=0;
	for(i=0; i<fileLen; i++){
		if(broken[i][0].score<broken[min][0].score) min=i;
	}

	printf("The cipher encoded with fixed single-character XOR is:\n"
			"%i: %s\nThe key is %s and it deciphers to \n", min, base16Encode(broken[min][0].cipher).c, broken[min][0].key.c);
	prints(broken[min][0].plaintext);
	PRINTNL;
}

void problem5(void){
	 /* Implement repeating-key XOR*/
	 string delimeter, filename;
	FILE *fp;
	code_t data;

	printf("Enter the delimiter which will act as an EOF, or enter \"FILE\" to encrypt data from a file, or hit enter to use the default test case:\n");
	delimeter = readLine();

	if(delimeter.len){
		if(!strcmp(delimeter.c, "FILE")){
			printf("Enter the filename:\n");
			filename=readLine();
			if((fp=fopen(filename.c, "r"))==NULL){
				printf("Failed to open the file.\n");
				exit(1);
			}
			data.plaintext=readInputFromFile(fp);
			fclose(fp);
		}
		else{
			printf("Enter plaintext, followed by the delimeter when you are done:\n");
			data.plaintext=readInput(delimeter);
			printf("The data is: \n%s\n", data.plaintext.c);
		}
		printf("Enter the key to encrypt with (on one line):\n");
		data.key=readLine();
	}

	else{
		data.plaintext=newString("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",0);
		data.key=newString("ICE",0);
		printf("Encrypting plaintext: \n\"%s\"\nwith key\n\"%s\"\n", data.plaintext.c, data.key.c);
	}

	data.cipher=base16Encode(stringXOR(data.plaintext, data.key));

	printf("Result: \n%s\n", data.cipher.c);
}

void problem6(void){
	/* BREAK REPEATING-KEY XOR
	 *	This doesn't use the Hamming distance as suggested, as the correct key only came up as the sixth best, and that was when
	 *	averaging over all six combinations of the first four blocks (averaging over other numbers of blocks gave an even worse result).
	 *  Instead, each keysize is scored by taking ONE transposed block breaking solving single-byte XOR, and taking the keysize which
	 *	gives the best single-byte XOR decryption histogram. This is only a fraction of a second slower than the Hamming distance method,
	 *	but the correct keysize comes out on top by a long shot.
	 */
	 
	char *inputChars=malloc(sizeof(char)*100);
	string cipher;
	code_t *broken;
	FILE *fp;
	int c, i;


	fp=fopen(FILE6, "r");
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
	cipher = base64Decode(newString(inputChars,i));
	free(inputChars);



	broken=breakRepeatingXOR(cipher, 40, 1);
	printf("\tThe key is\n\"%s\"\n\tand the plaintext is\n\n", broken[0].key.c);
	prints(broken[0].plaintext);PRINTNL;

}

void problem7(void){
	/* AES in ECB mode*/
	char *inputChars=calloc(100,sizeof(char));
	string cipher;
	FILE *fp;
	int c, i;
	string out;

	fp=fopen(FILE7, "r");
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
	cipher = base64Decode(newString(inputChars,i));
	free(inputChars);

	out=AES128DecodeECB(cipher, newString("YELLOW SUBMARINE",0));

	prints(out);
	PRINTNL;
}

void problem8(void){
	/* DETECT AES IN ECB MODE*/
	FILE *fp;
	int i;
	int fileLen=0;
	string fileLoc = newString(FILE8,0);
	string *ciphers;
	char *line;
	int cipherLength=320;


	fp = fopen(fileLoc.c, "r");
	for(i=0; !feof(fp); ) if(fgetc(fp)=='\n') i++;
	fclose(fp);
	fileLen=++i;

	ciphers=malloc(sizeof(string)*(fileLen));

	fp=fopen(fileLoc.c, "r");

	line=malloc(sizeof(char)*(cipherLength+1));
	for(i=0; i<fileLen; i++){
		fscanf(fp, "%s", line);
		ciphers[i]=newString(line,0);
	}
	fclose(fp);

	for(i=0; i<fileLen; i++){
		if(blockRepeats(base16Decode(ciphers[i]),16)){
			printf("This string has repeating blocks and may have been encoded with AES-128 in ECB mode: \n%i: %s\n", i, ciphers[i].c);
		}
	}
}
