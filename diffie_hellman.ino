#include "mbedtls/md.h"
#include <sstream>


///////////////////////////////////////////////////////
// Diffie Hellman configuration credit to DevMomo    //
// https://github.com/DevMomo/Diffie-Hellman-Arduino //
///////////////////////////////////////////////////////

//public variable representing the shared secret key.
//note that a uint32_t size key is suceptable to brute force attacks, consider a different data type of at least 1024 bits
uint32_t Ka, Kb; 
//prime number 
const uint32_t prime = 2147483647;
//generator
const uint32_t generator = 16807;  

//generates our 8 bit private secret 'a'.
uint32_t keyGen(){
  return random(1, prime);
}

//code to compute the remainder of two numbers multiplied together.
uint32_t mul_mod(uint32_t a, uint32_t b, uint32_t m){


  uint32_t result = 0; //variable to store the result
  uint32_t runningCount = b % m; //holds the value of b*2^i

  for(int i = 0 ; i < 32 ; i++){

    if(i > 0) runningCount = (runningCount << 1) % m;
    if(bitRead(a,i)){
      result = (result%m + runningCount%m) % m; 

    } 

  }
  return result;
}

//The pow_mod function to compute (b^e) % m that was given in the class files  
uint32_t pow_mod(uint32_t b, uint32_t e, uint32_t m)
{
  uint32_t r;  // result of this function

  uint32_t pow;
  uint32_t e_i = e;
  // current bit position being processed of e, not used except for debugging
  uint8_t i;

  // if b = 0 or m = 0 then result is always 0
  if ( b == 0 || m == 0 ) { 
    return 0; 
  }

  // if e = 0 then result is 1
  if ( e == 0 ) { 
    return 1; 
  }

  // reduce b mod m 
  b = b % m;

  // initialize pow, it satisfies
  //    pow = (b ** (2 ** i)) % m
  pow = b;

  r = 1;

  // stop the moment no bits left in e to be processed
  while ( e_i ) {
    // At this point pow = (b ** (2 ** i)) % m

    // and we need to ensure that  r = (b ** e_[i..0] ) % m
    // is the current bit of e set?
    if ( e_i & 1 ) {
      // this will overflow if numbits(b) + numbits(pow) > 32
      r= mul_mod(r,pow,m);//(r * pow) % m; 
    }

    // now square and move to next bit of e
    // this will overflow if 2 * numbits(pow) > 32
    pow = mul_mod(pow,pow,m);//(pow * pow) % m;

    e_i = e_i >> 1;
    i++;
  }

  // at this point r = (b ** e) % m, provided no overflow occurred
  return r;
}

void setup() {
  Serial.begin(115200);

  
}

void loop() {
  uint32_t a = keyGen();
  uint32_t A = pow_mod(generator, a, prime);
  Serial.println("Shared index is: ");
  Serial.println(A);

  uint32_t b = keyGen();
  uint32_t B = pow_mod(generator, b, prime);
  Serial.print("Shared index is: ");
  Serial.println(B);

  Ka = pow_mod(B, a, prime);
  Kb = pow_mod(A, b, prime);

  Serial.print("Shared Key A: ");
  Serial.println(Ka);
  Serial.print("Shared Key B: ");
  Serial.println(Kb);

  //Hashing SHA-2
  //char *sKa;
  char *payload;
  //memset(payload, Ka, sizeof(Ka));
  //sprintf(sKa, "%u", Ka);
  //strcpy(payload, sKa);
  byte shaResult[32];

  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(payload);
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
  
  Serial.print("Hash: ");

  for(int i=0; i < sizeof(shaResult); i++) {
    char str[3];
    sprintf(str, "%02X", (int)shaResult[i]);
    Serial.print(str);
  }
  delay(5000);
  }
