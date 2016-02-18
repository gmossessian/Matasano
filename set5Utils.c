#include "matasano.h"

static string DH_p;
static string DH_g;

void setDH_p(string p){DH_p = p;}
void setDH_g(string g){DH_g = g;}
string getDH_p(void){return DH_p;}
string getDH_g(void){return DH_g;}

//string DHPublicKey(string a){ return bigIntModExp(DH_g, a, DH_p); }

void DHSetKeys(person_t *p){
	p->privateKey = bigIntDivide(randString(DH_p.len+1),DH_p)[1];
	p->publicKey = bigIntModExp(DH_g,p->privateKey,DH_p);
}

void DHSetSharedKey(person_t *A, string publicKey){
	A->sharedKey = bigIntModExp(publicKey,A->privateKey,DH_p);
}

string getPublicKey(person_t p){
	return p.publicKey;
}

string DHGetEncyptedMessage(person_t A){
	string key = SHA1(A.sharedKey);
	string IV = randString(16);
	string m = AES128EncodeCBC(A.secret, newString(key.c,16), IV);
	return stringCat(m, IV);
}

string DHDecryptMessage(person_t A, string message){
	string IV = newString(&message.c[message.len-16],16);
	string m = newString(message.c, message.len-16);
	string key = SHA1(A.sharedKey);
	return stripPKCS7Padding(AES128DecodeCBC(m, newString(key.c,16), IV));
}
