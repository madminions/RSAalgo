/************************************************************
Implementation of RSA algorithm using C programming.
Developed by: Ashok Kumar Das
Department of Computer Science and Engineering
IIT Kharagpur
**************************************************************/

#include "headers.h"

int mul_inverse=0;
int gcd_value;
stack s;
int print_flag=0;
int print_flag1=0;

int gcd(int a, int b)
{
	int r;
	if(a < 0) a = -a;
	if(b < 0) b = -b;if(b == 0)
	return a;
	r = a mod b;
	// exhange r and b, initialize a = b and b = r;
	a = b;
	b = r;
	return gcd(a,b);
}
void extended_euclid(int A1, int A2, int A3, int B1, int B2,int B3)
{
	int Q;
	int T1,T2,T3;
if(B3 == 0){
	gcd_value = A3;
	mul_inverse = NOT_EXIST;
	return;
}

if(B3 == 1){
	gcd_value = B3;
	mul_inverse = B2;
	return;
}
	Q = (int)(A3/B3);

	T1 = A1 - Q*B1;
	T2 = A2 - Q*B2;
	T3 = A3 - Q*B3;

	A1 = B1;
	A2 = B2;
	A3 = B3;
	B1 = T1;
	B2 = T2;
	B3 = T3;
	extended_euclid(A1,A2,A3,B1,B2,B3);
}

boolean MillerRobinTest(long int n, int iteration)
{
	// n is the given integer and k is the given desired
	// number of iterations in this primality test algorithm.
	// Return true if all the iterations test passed to give
	// the higher confidence that n is a prime, otherwise
	// return false if n is composite.
	long int m, t;
	int i,j;
	long int a, u;
	int flag;
	if(n mod 2 == 0)
		return false;
	m = (n-1) div 2;
	t = 1;
	// n is composite.while( m mod 2 == 0)
	{
		m = m div 2;
		t = t + 1;
	// repeat until m is even
	}
	for (j=0; j < iteration; j++) { // Repeat the test for MAX_ITERATION times
		flag = 0;
		srand((unsigned int) time(NULL));
		a = random() mod n + 1; // select a in {1,2,......,n}
		u = ModPower(a,m,n);
		if (u == 1 || u == n - 1)
		flag = 1;
		for(i=0;i<t;i++)
		{
			if(u == n - 1)
				flag = 1;
			u = (u * u) mod n;
		}
		if ( flag == 0 )
			return false; // n is composite
	}
	return true; // n is prime.
} // end of MillerRobinTest().


//KEY GENERATION ALGORITHM IN RSA CRYPTOSYSTEM.
int KeyGeneration(key *pub_key, key *pvt_key)
{
	long int p,q;
	long int n;
	long int phi_n;
	long int e;
	// Select p and q which are primes and p<q.
	if(print_flag1)
		printf("\n selecting p->\n\r");
	
	while(1)
	{
		srand((unsigned int) time(NULL));
		p = random() % LARGE;
		if(p<=1)continue;
		/* test for even number */
		if ( p & 0x01 == 0 ) continue;
		if(MillerRobinTest(p, MAX_ITERATION))
			break;
	}
	if(print_flag1)
	printf("\n selecting q->\n\r");
	while(1)
	{
		srand((unsigned int) time(NULL));
		q=random() % LARGE;
		if(q<=1)continue;
		if( q == p)
		{
			srand((unsigned int) time(NULL));
			q = random() % LARGE;
			continue;
		}
		if(MillerRobinTest(q, MAX_ITERATION))
			break;
	}
	// Compute n.
	if (verify_prime(p) && verify_prime(q) )
		printf("p = %ld, q = %ld are primes\n", p, q);
	else {
		printf("p = %ld, q = %ld are composite\n", p, q);
		//----------md
		return 0;//if not found prime nos
		//exit(0);
	}
	printf("p = %ld, q = %ld\n", p, q);
	n = p * q;
	// Compute Euler's phi(totient) function
	phi_n = (p-1)*(q-1);
	// Compute e such that gcd(e,phi_n(n))=1.
	if(print_flag1)
		printf("\n selcting e->\n\r");
	while(1)
	{
		e = random()%phi_n;
		if(gcd(e, phi_n)==1)
		break;
	}
	// Compute d such that ed=1(mod phi_n(n)).
	if(print_flag1)
	printf("\n selceting d->\n\r");
	extended_euclid(1, 0, phi_n, 0, 1, e);
	if(mul_inverse <0) {
	mul_inverse = - mul_inverse;
	mul_inverse = ((phi_n - 1 ) * mul_inverse) mod phi_n;
	}
	if(print_flag1)
	printf("\n phi_n= %ld\n\n",phi_n);
	// Put Public Key and Private Key.
	pub_key->public_key.n = n;
	pub_key->public_key.e = e;
	pvt_key->private_key.n = n;
	pvt_key->private_key.d = mul_inverse;

	return 1;//if successfull
} // end of KeyGeneraion()

boolean verify_prime(long int p)
{
	long int d;
	// Test for p;
	for(d = 2; d <= (long int) sqrt(p); d++ )
	if ( p % d == 0 ) return false;
	return true;
}
// Encryption Algorithm(E)
long int EncryptionAlgorithm(long int M, key pub_key)
{
	// Alice computes ciphertext as C := M^e(mod n) to Bob.
	long int C;
	if(print_flag1)
	printf("\n Encryption keys= ( %ld,%ld)\n\r",pub_key.public_key.n,pub_key.public_key.e);
	C = ModPower(M, pub_key.public_key.e, pub_key.public_key.n);
	return C;
}

// Decryption Algorithm(D)
long int DecryptionAlgorithm(long int C, key pvt_key)
{
	// Bob retrieves M as M := C^d(mod n)
	long int M;
	if(print_flag1)
	printf("\n Decryption keys= ( %ld,%ld)\n\r",pvt_key.private_key.n,pvt_key.private_key.d);
	M = ModPower(C, pvt_key.private_key.d, pvt_key.private_key.n);
	return M;
}


void decimal_to_binary(long int n,char str[])
{
	// n is the given decimal integer.
	// Purpose is to find the binary conversion
	// of n.
	// Initialise the stack.
	int r;
	s.top = 0;
	while(n != 0)
	{
		r = n mod 2;
		s.top++;
		if(s.top >= STACK_SIZE)
		{
		printf("\nstack overflown!\n");
		return;
		}
		s.c[s.top] = r + 48;
		if(print_flag)
		printf("\n s.c[%d]= %c\n", s.top, s.c[s.top]);
		n = n div 2;
	}
	while(s.top)
	{
		*str++ = s.c[s.top--];
	}
	*str='\0';
	return;
}

// Algorithm: reverse a string.
void reverse_string(char x[])
{
	int n = strlen(x)-1;
	int i = 0;
	char temp[STACK_SIZE];
	for(i = 0; i<=n; i++)
	temp[i] = x[n-i];
	for(i=0; i<=n; i++)
	x[i] = temp[i];
}

// Algorithm: Modular Power: x^e(mod n).
long int ModPower(long int x, long int e, long int n)
{// To calculate y:=x^e(mod n).
	//long y;
	long int y;
	long int t;
	int i;
	int BitLength_e;
	char b[STACK_SIZE];
	//printf("e(decimal) = %ld\n",e);
	decimal_to_binary(e,b);
	if(print_flag)
	printf("b = %s\n", b);
	BitLength_e = strlen(b);
	y = x;
	reverse_string(b);
	for(i = BitLength_e - 2; i >= 0 ; i--)
	{
		if(print_flag)
		printf("\nb[%d]=%c", i, b[i]);
		if(b[i] == '0')
		t = 1;
		else t = x;
		y = (y * y) mod n;
		if ( y < 0 ) {
			y = -y;
			y = (y - 1) * (y mod n) mod n;
			printf("y is negative\n");
		}
		y = (y*t) mod n;
		if ( y < 0 ) {
			y = -y;
			y = (y - 1) * (y mod n) mod n;
			printf("y is negative\n");
		}
	}
	if ( y < 0 ) {
		y = -y;
		y = (y - 1) * (y mod n) mod n;
		printf("y is negative\n");
	}
	return y;
} // end of ModPower().


/*int main()
{
	char str[STACK_SIZE];
	int x, e;
	char ch;
	key pub_key, pvt_key;
	long int plaintext, ciphertext, deciphertext;
	//getchar();
	print_flag=print_flag1=0;						//md
	
	while(!KeyGeneration(&pub_key, &pvt_key));
	
	printf("\n Public Key of Alice is (n,e): (%ld , %ld)\n\r", pub_key.public_key.n, pub_key.public_key.e);
	printf("\n Private key of Alice is (n,d): (%ld , %ld)\n\r", pvt_key.private_key.n,pvt_key.private_key.d);
	printf("\n\r Enter plaintext (in non-negative integers only): ");
	scanf("%ld", &plaintext);
	
	ciphertext = EncryptionAlgorithm(plaintext, pub_key);
	
	printf("\n\r The ciphertext produced by Bob is : %ld \n\r", ciphertext);
	
	deciphertext = DecryptionAlgorithm(ciphertext, pvt_key);
	
	printf("\n\r The decipher text (recovered original plaintext) produced by Alice is : %ld\n\r",deciphertext);
	return 0;
}*/