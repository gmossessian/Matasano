#include "matasano.h"

string AES128EncodeBlock(string in, string key){
	if(in.len!=16 || key.len!=16) return NULLSTRING;
	return newString((char *)AES128Encode((unsigned char *)in.c,(unsigned char *)key.c),16);
}

string AES128DecodeBlock(string in, string key){
		if(in.len!=16 || key.len!=16) return NULLSTRING;
		return newString((char *)AES128Decode((unsigned char *)in.c,(unsigned char *)key.c),16);
}

string AES128EncodeECB(string in, string key){
	if(key.len!=16) return NULLSTRING;
	if(!validatePKCS7Padding(in)){
		in = PKCS7PadString(in, 16);
	}
	string out = NULLSTRING;
	for(int i=0; i<in.len; i+=16){
		out = stringCat(out, AES128EncodeBlock(newString(&in.c[i],16),key));
	}
	return out;
}

string AES128DecodeECB(string in, string key){
	if(in.len%16){
		return NULLSTRING;
	}
	string out = NULLSTRING;
	for(int i=0; i<in.len; i+=16){
		out = stringCat(out, AES128DecodeBlock(newString(&in.c[i],16),key));
	}
	return out;
}

string AES128EncodeCBC(string in, string key, string IV){
	string out = NULLSTRING;
	if(!validatePKCS7Padding(in)){
		in = PKCS7PadString(in, 16);
	}
	string *blocks = blockString(in, 16);
	int num = numBlocks(in, 16);
	for(int i=0; i<num; i++){
		if(i==0){
			blocks[0] = stringXOR(blocks[0], IV);
		}else{
			blocks[i] = stringXOR(blocks[i], newString(&out.c[(i-1)*16],16));
		}
		out = stringCat(out, AES128EncodeBlock(blocks[i], key));
	}
	return out;
}

string AES128DecodeCBC(string in, string key, string IV){
	if(in.len%16){
		return NULLSTRING;
	}
	string out = NULLSTRING;
	string *blocks = blockString(in, 16);
	int num = numBlocks(in, 16);
	for(int i=num-1; i>=0; i--){
		blocks[i] = AES128DecodeBlock(blocks[i],key);
		if(i==0){
			out = stringCat(stringXOR(blocks[i], IV), out);
		} else{
			out = stringCat(stringXOR(blocks[i-1], blocks[i]),out);
		}
	}
	return out;
}

string AESEncryptCTR(string in, string key, string nonce){
	string cipher=newString(NULL, in.len);
	string keystream;
	string counter=newString(NULL,8);
	int i,j,n;
	n=numBlocks(in,16);

	if (nonce.len!=8){
		nonce=newString(NULL,8);
	}

	j=0;
	for(i=0; i<n; i++){
		keystream=AES128EncodeBlock(stringCat(nonce, counter), key);
		do{
			if(j<in.len){
				cipher.c[j]=keystream.c[j%16] ^ in.c[j];
				j++;
			}
			else break;
		}while(j%16);
		littleEndianIncrement(&counter);
	}
	return cipher;
}
string AES128CTR(string in, string key, string nonce){
	string cipher=newString(NULL, in.len);
	string keystream;
	string counter=newString(NULL,8);
	int i,j,n;
	n=numBlocks(in,16);

	if (nonce.len!=8){
		nonce=newString(NULL,8);
	}

	j=0;
	for(i=0; i<n; i++){
		keystream=AES128EncodeBlock(stringCat(nonce, counter), key);
		do{
			if(j<in.len){
				cipher.c[j]=keystream.c[j%16] ^ in.c[j];
				j++;
			}
			else break;
		}while(j%16);
		littleEndianIncrement(&counter);
	}
	return cipher;
}

void littleEndianIncrement(string *counter){
	int i;

	if((unsigned char)counter->c[counter->len-1]==0xFF){
		*counter=newString(NULL,counter->len);
		return;
	}

	i=0;
	while((unsigned char)counter->c[i]==0xFF){
		counter->c[i]=0;
		i++;
	}
	counter->c[i]++;
}

