CC = clang

MAIN = main.c
UTILS = matasanoUtils.c set1Utils.c set2Utils.c set3Utils.c set4Utils.c set5Utils.c
PROBLEMS = set1.c set2.c set3.c set4.c set5.c
HFILES = matasano.h
CFILES = $(MAIN) $(UTILS) $(PROBLEMS)

AESDIR = ../AES128
STRINGDIR = ../CStringUtils
MTRNGDIR = ../MTRNG
SHA1DIR = ../SHA1
MD4DIR = ../MD4

CFLAGS = -g -Wall -std=c99
LIBS= -lcurl -lCStringUtils -lMD4 -lAES128 -lMTRNG -lSHA1 -lMD4
IFLAGS = -I$(STRINGDIR) -I$(AESDIR) -I$(MTRNGDIR) -I$(SHA1DIR) -I$(MD4DIR)
LFLAGS = -L$(STRINGDIR) -L$(AESDIR) -L$(MTRNGDIR) -L$(SHA1DIR) -L$(MD4DIR)

#OBJS = $(patsubst %.c,%.o,$(FILES) $(AESC) $(MTRNGC))
build: $(CFILES) $(HFILES) 
	$(CC) $(CFILES) $(LFLAGS) $(LIBS) $(IFLAGS) $(CFLAGS) -o matasano 

#build: AES MTRNG Matasano 

#CStringUtils: $(STRING)$(STRINGC) $(STRING)$(STRINGH)
#	$(CC) -c $(STRING)$(STRINGC) 

#AES: $(AES)$(AESC) $(AES)$(AESH)
#	$(CC) -c $(AES)$(AESC)

#MTRNG: $(MTRNG)$(MTRNGC) $(MTRNG)$(MTRNGC)
#	$(CC) -c $(MTRNG)$(MTRNGC)

#SHA1: $(SHA1)$(SHA1C) $(SHA1)$(SHA1H)
#	$(CC) -c $(SHA1)$(SHA1C) -I$(STRING)

#MD4: $(MD4)$(MD4C) $(MD4)$(MD4H) 
#	$(CC) -c $(MD4)$(MD4C) -I$(STRING)

#Matasano: $(FILES) $(LIBFILES) $(DEPS)
#	$(CC) -c $(IFLAGS) $(FILES) $(CFLAGS) 
#	$(CC) -o matasano $(LFLAGS) $(OBJS)


clean: 
	rm -f %.o
