/*
 * main.c
 *
 *  Created on: Jan 10, 2016
 *      Author: George Mossessian
 */

#include "matasano.h"

int main(int argc, char **argv){
	char *problem;
	if(argc>1){
		problem = argv[1];
	}
	else{
		printf("Which problem to solve? Enter, e.g., \"3.4\" for problem 4 in set 3.\n");
		problem=readLine().c;
	}
	srand(time(NULL));
	
	H4XX0R=1;
	
	if     (!strcmp(problem, "1.1") || !strcmp(problem, "1")) problem1();
	else if(!strcmp(problem, "1.2") || !strcmp(problem, "2")) problem2();
	else if(!strcmp(problem, "1.3") || !strcmp(problem, "3")) problem3();
	else if(!strcmp(problem, "1.4") || !strcmp(problem, "4")) problem4();
	else if(!strcmp(problem, "1.5") || !strcmp(problem, "5")) problem5();
	else if(!strcmp(problem, "1.6") || !strcmp(problem, "6")) problem6();
	else if(!strcmp(problem, "1.7") || !strcmp(problem, "7")) problem7();
	else if(!strcmp(problem, "1.8") || !strcmp(problem, "8")) problem8();
	else if(!strcmp(problem, "2.1") || !strcmp(problem, "9")) problem9();
	else if(!strcmp(problem, "2.2") || !strcmp(problem, "10")) problem10();
	else if(!strcmp(problem, "2.3") || !strcmp(problem, "11")) problem11();
	else if(!strcmp(problem, "2.4") || !strcmp(problem, "12")) problem12();
	else if(!strcmp(problem, "2.5") || !strcmp(problem, "13")) problem13();
	else if(!strcmp(problem, "2.6") || !strcmp(problem, "14")) problem14();
	else if(!strcmp(problem, "2.7") || !strcmp(problem, "15")) problem15();
	else if(!strcmp(problem, "2.8") || !strcmp(problem, "16")) problem16();
	else if(!strcmp(problem, "3.1") || !strcmp(problem, "17")) problem17();
	else if(!strcmp(problem, "3.2") || !strcmp(problem, "18")) problem18();
	else if(!strcmp(problem, "3.3") || !strcmp(problem, "19")) problem19();
	else if(!strcmp(problem, "3.4") || !strcmp(problem, "20")) problem20();
	else if(!strcmp(problem, "3.5") || !strcmp(problem, "21")) problem21();
	else if(!strcmp(problem, "3.6") || !strcmp(problem, "22")) problem22();
	else if(!strcmp(problem, "3.7") || !strcmp(problem, "23")) problem23();
	else if(!strcmp(problem, "3.8") || !strcmp(problem, "24")) problem24();
	else if(!strcmp(problem, "4.1") || !strcmp(problem, "25")) problem25();
	else if(!strcmp(problem, "4.2") || !strcmp(problem, "26")) problem26();
	else if(!strcmp(problem, "4.3") || !strcmp(problem, "27")) problem27();
	else if(!strcmp(problem, "4.4") || !strcmp(problem, "28")) problem28();
	else if(!strcmp(problem, "4.5") || !strcmp(problem, "29")) problem29();
	else if(!strcmp(problem, "4.6") || !strcmp(problem, "30")) problem30();
	else if(!strcmp(problem, "4.7") || !strcmp(problem, "31")) problem31();
	else if(!strcmp(problem, "4.8") || !strcmp(problem, "32")) problem32();
	else if(!strcmp(problem, "5.1") || !strcmp(problem, "33")) problem33();
	else if(!strcmp(problem, "5.2") || !strcmp(problem, "34")) problem34();
	else if(!strcmp(problem, "5.3") || !strcmp(problem, "35")) problem35();
	else if(!strcmp(problem, "HMAC")){
		printsint(SHA1HMAC(base16Decode(newString(argv[2],0)), newString(argv[3],0))); //HMAC(key,message);
		PRINTNL;
		return 0;
	}
	else printf("No such option.\n");
	//else if(!strcmp(problem, "5.1")) problem33();
	return 0;
}

