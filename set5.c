#include "matasano.h"

/*
 * Implement Diffie-Hellman

For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.
Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
Do the same for "b" and "B".
"A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
Do the same with A**b, check that you come up with the same "s".
To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).
Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:

p:
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
 
g: 2*/
void problem33(void){
	extern string DH_p; 
	//DH_p = charToS(0x25);
	DH_p = base16Decode(newString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",0));
	extern string DH_g;  
	DH_g = charToS(0x02);
	printf("generating A\n");fflush(stdout);
	string a = randString(5);//bigIntDivide(randString(5),DH_p)[1];
	string A = bigIntModExp(DH_g,a,DH_p);
	string b = randString(5);//bigIntDivide(randString(168),DH_p)[1];
	string B = bigIntModExp(DH_g,b,DH_p);
	string s1 = bigIntModExp(B,a,DH_p);
	string s2 = bigIntModExp(A,b,DH_p);
	if(bigIntComp(s1,s2)==0){
		printf("Diffie-Hellman works!\n");
	}
	else{
		printsint(s1);PRINTNL;
		printsint(s2);PRINTNL;
		printf("Check your modExp, you fool.\n");
	}
}
