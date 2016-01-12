CC = clang

MAIN = main.c
UTILS = matasanoUtils.c set1Utils.c set2Utils.c set3Utils.c set4Utils.c
PROBLEMS = set1.c set2.c set3.c set4.c
FILES = $(MAIN) $(UTILS) $(PROBLEMS)
 
OBJS  = %.o

AES = ../AES128/
AESC = aes128.c
AESH = aes128.h

STRING = ../CStringUtils/
STRINGC = CStringUtils.c
STRINGH = CStringUtils.h

MTRNG = ../MTRNG/
MTRNGC = MTRNG.c
MTRNGH = MTRNG.h

SHA1 = ../SHA1/
SHA1C = sha1.c
SHA1H = sha1.h

MD4 = ../MD4/
MD4C = MD4.c
MD4H = MD4.h

LIBFILES = $(AES)$(AESC) $(STRING)$(STRINGC) $(MTRNG)$(MTRNGC) $(SHA1)$(SHA1C) $(MD4)$(MD4C)
DEPS = matasano.h $(AES)$(AESH) $(STRING)$(STRINGH) $(MTRNG)$(MTRNGH) $(SHA1)$(SHA1H) $(MD4)$(MD4H)

CFLAGS = -g -Wall
LIBS=-lm
IFLAGS = -I$(AES) -I$(STRING) -I$(MTRNG) -I$(SHA1) -I$(MD4)
LFLAGS = -lcurl

OBJS = $(patsubst %.c,%.o,$(FILES) $(STRINGC) $(AESC) $(MTRNGC) $(SHA1C) $(MD4C))

build: CStringUtils AES MTRNG SHA1 MD4 Matasano 

CStringUtils: $(STRING)$(STRINGC) $(STRING)$(STRINGH)
	$(CC) -c $(STRING)$(STRINGC) 

AES: $(AES)$(AESC) $(AES)$(AESH)
	$(CC) -c $(AES)$(AESC)

MTRNG: $(MTRNG)$(MTRNGC) $(MTRNG)$(MTRNGC)
	$(CC) -c $(MTRNG)$(MTRNGC)

SHA1: $(SHA1)$(SHA1C) $(SHA1)$(SHA1H)
	$(CC) -c $(SHA1)$(SHA1C) -I$(STRING)

MD4: $(MD4)$(MD4C) $(MD4)$(MD4H) 
	$(CC) -c $(MD4)$(MD4C) -I$(STRING)

Matasano: $(FILES) $(LIBFILES) $(DEPS)
	$(CC) -c $(IFLAGS) $(FILES) $(CFLAGS) 
	$(CC) -o matasano $(LFLAGS) $(OBJS)


clean: 
	rm -f $(OBJS)
