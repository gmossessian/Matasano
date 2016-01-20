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
	//DH_p = base16Decode(newString("29bb3920ef5e958b9",0));
	//DH_p = base16Decode(newString("444291e51b3ea5fd16673e95674b01e7b",0));
	//DH_p = base16Decode(newString("7fffffffffffffffffffffffffffffff",0));
	DH_p = base16Decode(newString("fb49eeac4dedd15d82be164ee3b0cbb22f7d79377",0));
	//my crappy old little laptop isn't powerful enough to do bigger primes than this...
	//DH_p = base16Decode(newString("6322dee2816b379bfd622fee57862827e9a941e5921f571e5d",0));
	//DH_p = base16Decode(newString("efd19f2e8e87c453b59401661bb58f97b1ea71949ea3ae7b31359bfc34e7739c6776eedea9771ce830d8185e20d",0));
	//DH_p = base16Decode(newString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",0));
	extern string DH_g;  
	DH_g = charToS(0x02);
	printf("Testing Diffie-Hellman with parameters\n");
	printf("p = ");printsint(DH_p);PRINTNL;
	printf("g = ");printsint(DH_g);PRINTNL;
	string a = bigIntDivide(randString(DH_p.len+1),DH_p)[1];
	printf("\trandom a mod p = ");printsint(a);PRINTNL;fflush(stdout);
	string A = bigIntModExp(DH_g,a,DH_p);
	printf("\tA = g ** a mod p = ");printsint(A);PRINTNL;fflush(stdout);
	string b = bigIntDivide(randString(DH_p.len+1),DH_p)[1];
	printf("\trandom b mod p = ");printsint(b);PRINTNL;fflush(stdout);
	string B = bigIntModExp(DH_g,b,DH_p);
	printf("\tB = g ** b mod p = ");printsint(B);PRINTNL;fflush(stdout);
	string s1 = bigIntModExp(B,a,DH_p);
	printf("s1 = B ** a mod p = ");printsint(s1);PRINTNL;fflush(stdout);
	string s2 = bigIntModExp(A,b,DH_p);
	printf("s2 = A ** b mod p = ");printsint(s2);PRINTNL;fflush(stdout);
	if(bigIntComp(s1,s2)==0){
		printf("Diffie-Hellman works!\n");
	}
	else{
		printf("Check your modExp, you fool.\n");
	}
}
