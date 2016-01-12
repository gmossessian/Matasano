#include "matasano.h"

string savedKey;

/**********Problem 25 ********/
string makeCipherText(void){
	char *inputChars=calloc(100, sizeof(char));
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
	cipher = PKCS7PadString(base64Decode(newString(inputChars,i)), 16);
	free(inputChars);
	out = AES128DecodeECB(cipher, newString("YELLOW SUBMARINE",0));
	savedKey=randString(16);
	return AES128CTR(out, savedKey, NULLSTRING);
}

string edit(string cipher, string newText, int offset){
	return CTRSeek(cipher, savedKey, newText, offset);
}

string CTRSeek(string cipher, string key, string newText, int offset){
	string pt=AES128CTR(cipher, key, newString(NULL,0));
	pt=stringReplace(pt,newText,offset);
	return AES128CTR(pt,key,newString(NULL,0));
}

string stringReplace(string old, string new, int offset){
	int i;

	if(old.len < offset+new.len) return old;

	string r=newString(old.c,old.len);
	for(i=0; i<new.len; i++){
		r.c[i+offset]=new.c[i];
	}
	return r;
}

/**** Problem 26 ********/
string problem26function1(string in){
	string s1=newString("comment1=cooking%20MCs;userdata=",0);
	string s2=newString(";comment2=%20like%20a%20pound%20of%20bacon",0);
	string text=in;
	text=stripChars(text, newString("=;",0));
	text=stringCat(s1, text);
	text=stringCat(text, s2);

	return AES128CTR(text,savedKey,newString(NULL,0));
}

int isCTRAdmin(string cipher){
	string text=AES128CTR(cipher, savedKey,newString(NULL,0));
	string admin=newString(";admin=true;",0);
	for(int i=0; i<text.len-admin.len; i++){
		if(text.c[i]!=admin.c[0]) continue;
		if(stringCompN(newString(&(text.c[i]), admin.len), admin, admin.len)) return 1;
	}
	return 0;
}

string injectAdmin(string (*oracle)(string)){
	/* the character ':' has value 00111010
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
	int offset;
	string 	adminCipher = (*oracle)(newString(":admin<true:",0));
	string s1,s2;

	//figure out where the text is being inserted
	offset=0;
	s1=(*oracle)(newString(NULL,0));
	s2=(*oracle)(newString("a",1));
	while(s1.c[offset]==s2.c[offset])offset++;

	//flip those bits

	adminCipher.c[offset]^=0x1;
	adminCipher.c[offset+6]^=0x1;
	adminCipher.c[offset+11]^=0x1;

	return adminCipher;
}

/**********Problem 27 ********/
string problem27function1(string in){
	string s1=newString("comment1=cooking%20MCs;userdata=",0);
	string s2=newString(";comment2=%20like%20a%20pound%20of%20bacon",0);
	string text=LOCALSTRING(in);
	text=stripChars(text, newString("=;",0));
	text=stringCat(s1, text);
	text=stringCat(text, s2);

	//encrypt under CBC mode with IV = key.
	return AES128EncodeCBC(text, savedKey, savedKey);
}

string checkASCIICompliance(string cipher){
	//returns NULLSTRING if ASCII is OK. Otherwise returns the plaintext.
	string ptext=AES128DecodeCBC(cipher, savedKey, savedKey);
	printsint(ptext); PRINTNL; fflush(stdout);
	for(int i=0; i<ptext.len; i++){
		if(!isprint(ptext.c[i])) return ptext;
	}
	return NULLSTRING;
}

/*****Problem 28***/
string SHA1Key;

string SHA1MAC(string data){
	return SHA1(stringCat(getSHA1Key(), data));
}

int validateSHA1MAC(string message, string MAC){
	//printf("Message: "); printsint(SHA1MAC(message));PRINTNL;
	//printf("Digest : "); printsint(MAC); PRINTNL;PRINTNL;
	return stringComp(SHA1MAC(message), MAC);
}

string getSHA1Key(){ return SHA1Key; }
void setSHA1Key(){ SHA1Key=randString(5+rand()%10); }

/******** Problem 28 *******/

string computePadding(string message){
	string padding;
	char tempChar;
	string t;
	uint64_t ml=8*message.len;
	int i;

	//append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	tempChar = 0x80;
	padding=newString(&tempChar,1);


	//append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
	//	is congruent to −64 ≡ 448 (mod 512)4
	i=((56-(message.len+padding.len))%64);
	if(i<0) i+=64;
	padding=stringCat(padding,newString(NULL, i));

	//append ml, in a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
	t=newString(NULL,8);
	for(i=0; i<8; i++){
		t.c[i] = (ml >> ((7-i)*8)) & 0xFF;
	}
	return stringCat(padding,t);
}

uint32_t *breakSHA1DigestIntoRegisters(string digest){
	uint32_t *registers = malloc(sizeof(uint32_t)*5);
	string *blocks = blockString(digest,4);
	int i;
	for(i=0; i<5; i++){
		registers[i]=stringToUint32(blocks[i]);
	}
	return registers;
}

string *forgeSHA1Digest(string message, string extension){
	//returns {forgedMessage, forgedDigest}.
	int keyLen;
	uint32_t *registers = breakSHA1DigestIntoRegisters(SHA1MAC(message));
	string forgedMessage;
	string forgedDigest;
	string *ret = malloc(sizeof(string)*2);
	string padding;

	for(keyLen=0; keyLen<64; keyLen++){
		padding = computePadding(stringCat(newString(NULL, keyLen), message));
		forgedMessage = stringCat(stringCat(message,padding),extension);

		padding = computePadding(stringCat(newString(NULL,keyLen),forgedMessage));


		setSHA1Registers(registers[0], registers[1], registers[2], registers[3], registers[4]);
		forgedDigest = SHA1Digest(stringCat(extension,padding));

		if(validateSHA1MAC(forgedMessage, forgedDigest)){
			printf("Keylen was %i\n", keyLen);
			break;
		}

	}
	ret[0]=forgedMessage;
	ret[1]=forgedDigest;
	return ret;
}

/***** Problem 30 ***********/
string MD4Key;

string MD4MAC(string data){
	return MD4(stringCat(getMD4Key(), data));
}

int validateMD4MAC(string message, string MAC){
	return stringComp(MD4MAC(message), MAC);
}

string getMD4Key(){
	return MD4Key;
}

void setMD4Key(){
	MD4Key=randString(5+rand()%10);
}

string computeMD4Padding(string message){
	string padding;
	char tempChar;
	uint64_t ml=message.len;
	int i;

	//append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
	tempChar = 0x80;
	padding=newString(&tempChar,1);


	//append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
	//	is congruent to −64 ≡ 448 (mod 512)4
	i=((56-(message.len+padding.len))%64);
	if(i<0) i+=64;
	padding=stringCat(padding,newString(NULL, i));

	//append ml, in a 64-bit integer. Thus, the total length is a multiple of 512 bits.
	//reverse the endianness of the message length, so that when the forged
	//message gets digested, the message length winds up big-endian
	padding=stringCat(padding,uint32ToString(changeEndianness((ml<<3)&0xFFFFFFFF)));
	padding=stringCat(padding,uint32ToString(changeEndianness((ml>>29)&0xFFFFFFFF)));

	return padding;
}

uint32_t *breakMD4DigestIntoRegisters(string digest){
	uint32_t *registers = calloc(4, sizeof(uint32_t));
	string *blocks = blockString(digest,4);
	int i;
	for(i=0; i<4; i++){
		registers[i]=changeEndianness(stringToUint32(blocks[i]));
	}
	return registers;
}

string *forgeMD4Digest(string message, string extension){
	//returns {forgedMessage, forgedDigest}.
	int keyLen;
	uint32_t *registers;
	uint32_t *hash;
	string forgedMessage;
	string forgedDigest;
	string *ret = malloc(sizeof(string)*2);
	string padding;
	uint32_t* w;
	int i,wlen;

	//get the starting point for faking the MD4 of the extended message
	registers = breakMD4DigestIntoRegisters(MD4MAC(message));

	for(keyLen=5; keyLen<15; keyLen++){

		//compute padding as if there's a key in front of the message
		padding = computeMD4Padding(stringCat(newString(NULL, keyLen), message));

		//message | fake padding | extension
		forgedMessage = stringCat(stringCat(message,padding),extension);

		//get the padding for the faked message.
		//since <extension> starts a new block in forgedMessage, you can just
		//stick this on the end of the extension
		padding = computeMD4Padding(stringCat(newString(NULL,keyLen),forgedMessage));

		setMD4Registers(registers[0], registers[1], registers[2], registers[3]);

		extension=stringCat(extension, padding);

		w = calloc(extension.len/4, sizeof(uint32_t));
		for(i=0; i<extension.len/4; i++){
			w[i]=stringToUint32(newString(&(extension.c[4*i]), 4));
		}

		wlen=i;

		//change endianness, this time also for the message length, since computePadding changed it to
		//little-endian.
		for(i=0; i<wlen; i++){
			w[i]=changeEndianness(w[i]);
		}
		hash = MD4Digest(w,wlen);

		forgedDigest = NULLSTRING;
		for(i=0; i<4; i++){
			hash[i]=changeEndianness(hash[i]);
			forgedDigest=stringCat(forgedDigest,uint32ToString(hash[i]));
		}

		if(validateMD4MAC(forgedMessage, forgedDigest)){
			printf("Keylen was %i\n", keyLen);
			break;
		}

	}
	ret[0]=forgedMessage;
	ret[1]=forgedDigest;
	return ret;
}

/****** Problem 31 *********/
pid_t startServer(string url, string command, int *infp, int *outfp) {
	pid_t pid;

	pid = runExternalScript(command, infp, outfp);

	if (waitForServer(url, 5000L) != 1) {
		printf("Timed out waiting for server to start!\n");
		killPid(pid);
	}

	return pid;
}

int curlRequest(string url) {
	CURL *curl;
	CURLcode res;
	long http_code=-1;

	curl = curl_easy_init();
	if (curl){
		curl_easy_setopt(curl, CURLOPT_URL, url.c);

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
		//else printf("Request OK!");
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		/* always cleanup */
		curl_easy_cleanup(curl);
	}
	return http_code;
}

long int *timeRequest(string url, int num) {
	CURL *curl;
	CURLcode res;
	struct timeval t1, t2;
	int i;
	long int *times;

	times=malloc(sizeof(long int)*num);

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c);

		/* Perform the request, res will get the return code */
		for(i=0; i<num; i++){
			gettimeofday(&t1, NULL);
			res = curl_easy_perform(curl);
			gettimeofday(&t2, NULL);
			times[i] = (t2.tv_sec - t1.tv_sec) * MILLION + (t2.tv_usec - t1.tv_usec);
		}
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
		//else printf("Request OK!");

		/* always cleanup */
		curl_easy_cleanup(curl);
	}
	return times;
}

int waitForServer(string url, long int timeOutms) {
	CURL *curl;
	long sockextr;
	CURLcode res;
	curl_socket_t sockfd; /* socket */
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c);
		curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
		do {
			res = curl_easy_perform(curl);
		} while (CURLE_OK != res);
		curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &sockextr);
		sockfd = sockextr;
		printf("Waiting...");
		fflush(stdout);
		if (!wait_on_socket(sockfd, 0, timeOutms)) {
			printf("Error: timeout.\n");
			return 1;
		}
	}
	//printf("Done!\n");
	curl_easy_cleanup(curl);
	return 1;
}

pid_t runExternalScript(string command, int *infp, int *outfp) {
	int p_stdin[2], p_stdout[2];
	pid_t pid;

	if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
		return -1;

	pid = fork();

	if (pid < 0)
		return pid;
	else if (pid == 0) {
		close(p_stdin[1]);
		dup2(p_stdin[0], 0);
		close(p_stdout[0]);
		dup2(p_stdout[1], 1);

		execlp(command.c, "", (char *) NULL);
		perror("execlp");
		exit(1);
	}

	if (infp == NULL)
		close(p_stdin[1]);
	else
		*infp = p_stdin[1];

	if (outfp == NULL)
		close(p_stdout[0]);
	else
		*outfp = p_stdout[0];

	return pid;
}

int killPid(pid_t pid) {
	int r;
	char *command = malloc(sizeof(char) * 20);
	sprintf(command, "kill %i", pid);
	r = system(command);
	free(command);
	return r;
}

/* Auxiliary function that waits on the socket. */
/* Taken from http://curl.haxx.se/libcurl/c/sendrecv.html */
int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms) {
	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);

	FD_SET(sockfd, &errfd);
	/* always check for error */

	if (for_recv) {
		FD_SET(sockfd, &infd);
	} else {
		FD_SET(sockfd, &outfd);
	}

	/* select() returns the number of signalled sockets or -1 */
	res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
	return res;
}

int longintcompare(const void *a, const void *b) {
	long int A = *((long int *) a);
	long int B = *((long int *) b);
	if (A < B)
		return -1;
	if (A == B)
		return 0;
	return 1;
}

string findHMAC(string url_base, string file, int numAttempts, struct timeval delay) {
	//recommended value for numAttempts is at least 3, to trim some outliers
	string HMAC = newString(NULL, 40);
	long int *times[16];
	long int avgTimes[16];
	long int maxTimes[HMAC.len];
	int i, j, k;
	int jmax;
	string url;
	long int delay_usec;
	int oneThird;
	int updated;
	string falsePositives[HMAC.len];

	for (i = 0; i < HMAC.len; i++) {
		HMAC.c[i] = '0';
		falsePositives[i] = NULLSTRING;
	}

	if (delay.tv_usec == 0 && delay.tv_sec == 0) { //default to 50 msec
		delay.tv_usec = 50000;
	}

	delay_usec = delay.tv_sec * MILLION + delay.tv_usec;

	if (numAttempts == 0) { //by default, there should be, say, two-tenths of a second difference for a correct letter?
		if (delay_usec < MILLION)
			numAttempts = (int) ((float) MILLION / delay_usec + 0.5);
		else
			numAttempts = 4;
	}
	oneThird = numAttempts / 4;

	for (i = 0; i < 16; i++) {
		times[i] = malloc(sizeof(long int) * numAttempts);
	}

	//printf("Finding the HMAC by early-exit string timing: delay =  %li usec, multiplied by %i.\n", delay_usec, numAttempts);
	//fflush(stdout);

	url_base = stringCat(url_base, newString("?file=", 0));
	url_base = stringCat(url_base, file);
	url_base = stringCat(url_base, newString("&delay=", 0));
	url_base = stringCat(url_base, timevalToString(delay, MILLION));
	url_base = stringCat(url_base, newString("&signature=", 0));

	//cheat and peek at the real digest
	url = stringCat(url_base, newString("ShowMeTheMoney",0));
	curlRequest(url);

	maxTimes[0]=0;

	for (i = 0; i < HMAC.len; i++) { //for each character in the hex-encoded sha1 digest
		updated=0;
		maxTimes[i] = maxTimes[MAX(i-1,0)];//+i*delay_usec*(numAttempts-2*oneThird);
		if(falsePositives[i].len==16){
			falsePositives[i] = NULLSTRING;
		}
		for (j = 0; j < 16; j++) { //time each possible character
			for (k = 0; k <= i; k++) {
				if(k==0) printf("Hacking: ");
				printf("%c", HMAC.c[k]);
			}
			printf("\r"); fflush(stdout);
			HMAC.c[i] = BASE16[j];
			url = stringCat(url_base, HMAC);
			times[j] = timeRequest(url, numAttempts);
			qsort(times[j], numAttempts, sizeof(long int), longintcompare);
			avgTimes[j] = 0;
			for (k = oneThird; k < numAttempts - oneThird; k++) {
				avgTimes[j] += times[j][k];
			}
			if (avgTimes[j] >= maxTimes[i] && strchr(falsePositives[i].c, BASE16[j])==NULL) {
				jmax = j;
				maxTimes[i] = avgTimes[jmax];
				updated=1;
			}
		}
		//if there was a false positive, go back a character
		if(updated==0 && i>0){// || (i>0 && maxTimes[i] < (i+1)*delay_usec*(numAttempts-2*oneThird))){
			falsePositives[i-1] = stringCat(falsePositives[i-1], newString(&HMAC.c[i-1],1));
			i-=2;
			continue;
		}
		//maxTimes[i+1]=maxTimes[i];
		HMAC.c[i] = BASE16[jmax];
		//printf("%02x",jmax);fflush(stdout);
	}
	return HMAC;
}

string timevalToString(struct timeval tv, int nsec) {
	/*converts timeval to a string, where the unit of minimum time is nsec.*/
	char *ts = malloc(sizeof(char) * (tv.tv_sec / 10 + 10)); //bigger than necessary
	long int nano = tv.tv_sec * MILLION + tv.tv_usec;
	sprintf(ts, "%f", (double) nano / (double) nsec);
	return newString(ts, 0);
}
