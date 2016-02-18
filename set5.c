#include "matasano.h"

#define TESTPRIME base16Decode(newString("29bb3920ef5e958b9",0))
 
void problem33(void){ //Implement Diffie-Hellman.
	//string p1 = charToS(0x25);
	//string p2 = base16Decode(newString("29bb3920ef5e958b9",0));
	string p3 = base16Decode(newString("444291e51b3ea5fd16673e95674b01e7b",0));
	//string p4 = base16Decode(newString("fb49eeac4dedd15d82be164ee3b0cbb22f7d79377",0));
	//my crappy old little laptop isn't powerful enough to do bigger primes than this...
	//string p5 = base16Decode(newString("6322dee2816b379bfd622fee57862827e9a941e5921f571e5d",0));
	//string p6 = base16Decode(newString("efd19f2e8e87c453b59401661bb58f97b1ea71949ea3ae7b31359bfc34e7739c6776eedea9771ce830d8185e20d",0));
	//The math department computers were able to handle up to here. Interestingly, it doesn't take appreciably more *time* to compute these modexps, just more memory...
	//string p7 = base16Decode(newString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",0));
	//string g0 = charToS(0x05);
	string g1 = charToS(0x02); 
	
	setDH_p(p3);
	setDH_g(g1);
	
	printf("Testing Diffie-Hellman with parameters\n");
	printf("p = ");printsint(getDH_p());PRINTNL;
	printf("g = ");printsint(getDH_g());PRINTNL;
	string a = bigIntDivide(randString(getDH_p().len+1),getDH_p())[1];
	printf("\trandom a mod p = ");printsint(a);PRINTNL;fflush(stdout);
	string A = bigIntModExp(getDH_g(),a,getDH_p());
	printf("\tA = g ** a mod p = ");printsint(A);PRINTNL;fflush(stdout);
	string b = bigIntDivide(randString(getDH_p().len+1),getDH_p())[1];
	printf("\trandom b mod p = ");printsint(b);PRINTNL;fflush(stdout);
	string B = bigIntModExp(getDH_g(),b,getDH_p());
	printf("\tB = g ** b mod p = ");printsint(B);PRINTNL;fflush(stdout);
	string s1 = bigIntModExp(B,a,getDH_p());
	printf("s1 = B ** a mod p = ");printsint(s1);PRINTNL;fflush(stdout);
	string s2 = bigIntModExp(A,b,getDH_p());
	printf("s2 = A ** b mod p = ");printsint(s2);PRINTNL;fflush(stdout);
	if(bigIntComp(s1,s2)==0){
		printf("Diffie-Hellman works!\n");
	}
	else{
		printf("Check your modExp, you fool.\n");
	}
}

void problem34(void){ //Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

	setDH_p(TESTPRIME);
	setDH_g(charToS(0x02));
	
	person_t Alice;
	person_t Bob;
	person_t Eve;
	
	printf("Testing the protocol. Can Alice decrypt Bob's secret?\n");
	Alice.secret = newString("This is Alice's secret.",0);
	Bob.secret = newString("This is Bob's secret.",0);
	
	DHSetKeys(&Alice);
	DHSetKeys(&Bob);
	
	DHSetSharedKey(&Alice, getPublicKey(Bob));
	DHSetSharedKey(&Bob, getPublicKey(Alice));
	
	string bobSecret = DHGetEncyptedMessage(Bob);
	printf("Alice reads Bob's secret message as: "); prints(DHDecryptMessage(Alice, bobSecret));
	PRINTNL;
	
	printf("Now, I am Eve.\n");
	printf("Giving Alice a fake key instead of Bob's.\n");
	DHSetSharedKey(&Alice, getDH_p());
	printf("Giving Bob a fake key instead of Alice's.\n");
	DHSetSharedKey(&Bob, getDH_p());
	
	printf("Decrypting their respective juicy secrets:\n");
	string aliceSecret = DHGetEncyptedMessage(Alice);
	bobSecret = DHGetEncyptedMessage(Bob);
	Eve.sharedKey = charToS(0x00);
	prints(DHDecryptMessage(Eve, aliceSecret));PRINTNL;
	prints(DHDecryptMessage(Eve, bobSecret));PRINTNL;
}

void problem35(void){ //Implement DH with negotiated groups, and break with malicious "g" parameters

	person_t Alice;
	person_t Bob;
	person_t Eve;
	
	Alice.secret = newString("My name is Alice, and I have a secret.",0);
	Bob.secret = newString("My name is Bob, and my secret is better than yours.",0);
	
	//Go through the  protocol:
	printf("Going through the protocol.\n");
	//as A, set p, g.
	printf("Alice is setting p and g.\n");
	setDH_p(TESTPRIME);
	setDH_g(charToS(0x02));
	printf("\tp = ");printsint(getDH_p());PRINTNL;
	printf("\tg = ");printsint(getDH_g());PRINTNL;
	
	printf("Bob acknowledges: \n");
	printf("\tp = ");printsint(getDH_p());PRINTNL;
	printf("\tg = ");printsint(getDH_g());PRINTNL;
	
	printf("Alice sends her public key:\n");
	DHSetKeys(&Alice);
	printf("\tA = ");printsint(getPublicKey(Alice));PRINTNL;
	
	printf("Bob sends his public key:\n");
	DHSetKeys(&Bob);
	printf("\tB = ");printsint(getPublicKey(Bob));PRINTNL;
	
	printf("Alice and Bob go into their corners and set their shared key...\n");
	DHSetSharedKey(&Alice, getPublicKey(Bob));
	DHSetSharedKey(&Bob, getPublicKey(Alice));
	
	printf("Bob reads Alice's message: \n\t");
	prints(DHDecryptMessage(Bob, DHGetEncyptedMessage(Alice)));PRINTNL;
	printf("And Alice reads Bob's message: \n\t");
	prints(DHDecryptMessage(Alice, DHGetEncyptedMessage(Bob)));PRINTNL;PRINTNL;
	
	printf("Now, Eve will intercept messages and modify g.");
/*
A->B
    Send "p", "g"
B->A
    Send ACK
A->B
    Send "A"
B->A
    Send "B"
A->B
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
    Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

Do the MITM attack again, but play with "g". What happens with:

    g = 1
    g = p
    g = p - 1

Write attacks for each. */
}
