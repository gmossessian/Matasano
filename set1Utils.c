#include "matasano.h"

/********* PROBLEM 3 **********/

int numAttempts = UCHAR_MAX;
int charFreqDepth = 11; //How many of the most popular letters to actually evaluate on. MUST be between 1 and 27 inclusive.

charFreq_t avgCharFreq[27]=	{{' ',19.12,0}, {'a', 6.52, 3}, {'b', 1.24, 20}, {'c', 2.17, 13},
							{'d', 3.49, 10}, {'e', 10.41, 1}, {'f', 1.97, 15}, {'g',1.59, 18}, {'h', 4.93, 9},
							{'i', 5.58, 5}, {'j', 0.09, 25}, {'k', .51, 22}, {'l', 3.31, 11}, {'m', 2.02, 14},
							{'n', 5.65, 6}, {'o', 5.96, 4}, {'p', 1.37, 19}, {'q', 0.09, 24}, {'r', 4.97, 8},
							{'s', 5.16, 7}, {'t', 7.29, 2}, {'u', 2.25, 12}, {'v', 0.83, 21}, {'w', 1.71, 17},
							{'x', 0.14, 23}, {'y', 1.46, 16}, {'z', 0.07, 26}
};

code_t *breakFixedXOR(string cipher, string range){
	code_t *res;
	code_t temp;
	string key;
	int i,j;

	/*
	 * default range of characters to XOR against is all char values 0-127
	 */
	if(range.len==0){
		range=newString(NULL, numAttempts);
		for(i=0; i<numAttempts; i++) range.c[i]=(char)i;
	}
	res = malloc(range.len*sizeof(code_t));

	/*
	 * go through and XOR the cipher  against every char value in range.
	 * Score each of them according to scoreString(char *) and save the key.
	 */
	key=newString(NULL,1);
	for(i=0; i<range.len; i++){
		key.c[0]=range.c[i];
		res[i].cipher=newString(cipher.c,0);
		res[i].plaintext=stringXOR(cipher, key);
		res[i].score=scoreString(res[i].plaintext);
		res[i].key=newString(NULL,1);
		res[i].key.c[0]=range.c[i];
	}

	/*
	 * Sort the results, best/lowest-scoring first
	 */
	for(i=0; i<range.len-1; i++){
		for(j=0; j<range.len-i-1; j++){
			if(res[j].score>res[j+1].score){
				temp=res[j+1];
				res[j+1]=res[j];
				res[j]=temp;
			}
		}
	}
	return res;
}

charFreq_t *computeCharFreq(string str){
	charFreq_t *charFreq = (charFreq_t *)malloc(27*sizeof(charFreq_t));
	int *letters = (int*)malloc(27*sizeof(int));
	int total; //The total number of alphabetical letters in str, including spaces but not counting other characters
	int i,j;
	int maxInd;
	float max=0.0;
	memset(letters, 0, sizeof(int)*27);

	//set letters[i] to the number of times the i'th letter appears in str, where 0 is ' ', 1 is 'a', etc.
	total=0;
	for(i=0; i<str.len; i++) {
		if(isalpha(str.c[i])){
			letters[tolower(1+str.c[i])-'a']++;
			total++;
		}
		if(str.c[i]==' '){
			letters[0]++;
			total++;
		}
	}

	if(total==0) total=1;
	//set the character and frequency of charFreq[i]
	//first for ' ' and then for the rest of the characters
	charFreq[0]=(charFreq_t){.c=' ', .f=((float)(letters[0]))/((float)total), .r=-1};
	for(i=1; i<27; i++){
		charFreq[i]=(charFreq_t){.c='a'+i-1, .f=((float)(letters[i]))/((float)total), .r=-1};
	}
	free(letters);

	//rank them
	for(j=0; j<27; j++){
		max=0.0;
		for(i=0; i<27; i++){
			if (charFreq[i].r==-1 && charFreq[i].f>=max){
				max=charFreq[i].f;
				maxInd=i;
			}
		}
		charFreq[maxInd].r=j;
	}
	return charFreq;
}

/*
 * The scoring mechanism -- a lower score is better!
 */
float scoreString(string str){
	float score = 0.0;
	charFreq_t *charFreq=computeCharFreq(str);
	int i,j=0;
	/*
	 * For each letter, it has a rank of appearance in str, and on average in English.
	 * Take Abs(difference).
	 * If the letter is very common, a difference in ranks is very bad, so multiply by the frequency.
	 * Add them all up.
	 */
	for(i=0; i<charFreqDepth; i++){
		score+=ABS(charFreq[i].r-avgCharFreq[i].r) * avgCharFreq[i].f;
	}

	/*Now, divide by the actual number of letters and spaces, so if there are a lot of non-alphanumberic symbols, this is bad.
	 * Normalize this for the length of the string.  */
	for(i=0;i<str.len;i++)if(isalnum(str.c[i]) || str.c[i]==' ') j++;
	return str.len*score/(float)j;
}


/****** PROBLEM 4 *********/

int cipherLength=60; //in the matasano data file, only 60 characters per cipher (at most: cipher 93 only has 58...)

/****** PROBLEM 6 *********/

typedef struct keysize_t{
	int ks;
	float score;
} keysize_t;

code_t *breakRepeatingXOR(string cipher, int maxKey, int depth){
	/*
	 * maxKey: the maximum key length to try. if(maxKey<=1) maxKey=40;
	 * depth: how many keylengths (starting from highest-scoring) to try. if(depth<=0) depth=1;
	 */
	keysize_t *ks;
	keysize_t temp;
	code_t *ans;
	code_t t;
	string *keys;
	string *cipherBlocks;
	int i,j;

	if(maxKey<=1) maxKey=40;
	if(depth<=0) depth=1;
	if(depth>maxKey-1) depth=maxKey-1;

	ks=malloc(sizeof(keysize_t)*(maxKey-1));
	ans=malloc(sizeof(code_t)*(maxKey-1));

	for(i=0;i<maxKey-1; i++){
		ks[i].ks=i+2;
		ks[i].score=scoreKeysize(cipher, ks[i].ks);
	}

	for(i=0; i<maxKey-1; i++){
		for(j=i+1; j<maxKey-1; j++){
			if(ks[i].score>ks[j].score){
				temp=ks[j];
				ks[j]=ks[i];
				ks[i]=temp;
			}
		}
	}

	keys = malloc(sizeof(string)*(depth));
	for(i=0; i<depth; i++){
		keys[i]=newString(NULL,ks[i].ks);
		printf("%i: %f\n", ks[i].ks, ks[i].score);
		for(j=0; j<ks[i].ks; j++){
			cipherBlocks=invertBlocks(cipher, ks[i].ks);
			//c=breakFixedXOR(cipherBlocks[j], newString(NULL, 0))[0].key.c[0];
			keys[i].c[j]=breakFixedXOR(cipherBlocks[j], newString(NULL, 0))[0].key.c[0];
		}
		ans[i].plaintext=newString(stringXOR(cipher, keys[i]).c,0);
		ans[i].key=newString(keys[i].c,0);
		ans[i].cipher=newString(cipher.c,0);
		ans[i].score=scoreString(ans[i].plaintext);
	}

	for(i=0; i<depth-1; i++){
		for(j=i+1; j<depth; j++){
			if(ans[i].score>ans[j].score){
				t=ans[i];
				ans[i]=ans[j];
				ans[j]=t;
			}
		}
	}

	return ans;
}

float scoreKeysize(string str, int ks){
	string block=newString(NULL, str.len/ks);
	int i;
	for(i=0; i<str.len/ks; i++)block.c[i]=str.c[i*ks];
	return breakFixedXOR(block, newString(NULL, 0))[0].score;
}

