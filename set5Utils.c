#include "matasano.h"

string DH_p;
string DH_g;

string DHPublicKey(string a){
	return bigIntModExp(DH_g, bigIntDivide(a,DH_p)[1], DH_p);
}
