
#include "headers.h"


/*Public Key and Private Key*/
key pub_key, pvt_key;

/* Function prototypes */
int serverConnect ( char * );
void Talk_to_server ( int );

/* Connect with the server: socket() and connect() */
int serverConnect ( char *sip )
{
   int cfd;
   struct sockaddr_in saddr;   /* address of server */
   int status;

   /* request for a socket descriptor */
   cfd = socket (AF_INET, SOCK_STREAM, 0);
   if (cfd == -1) {
      fprintf (stderr, "*** Client error: unable to get socket descriptor\n");
      exit(1);
   }

   /* set server address */
   saddr.sin_family = AF_INET;              /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);    /* Service port in network byte order */
   saddr.sin_addr.s_addr = inet_addr(sip);  /* Convert server's IP to short int */
   bzero(&(saddr.sin_zero),8);              /* zero the rest of the structure */

   /* set up connection with the server */
   status = connect(cfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Client error: unable to connect to server\n");
      exit(1);
   }

   fprintf(stderr, "Connected to server\n");

   return cfd;
}

/* Interaction with the server */
void Talk_to_server ( int cfd )
{
   char buffer[MAX_LEN];
   int nbytes, status;
   int src_addr, dest_addr;
   PubKeyMsg pubKey_msg;
   ReqMsg request_file;
   RepMsg recv_msg;

   dest_addr = inet_addr("DEFAULT_SERVER");
   src_addr = inet_addr("192.168.1.245");

   /* send the request message PUBKEY to the server */
   printf("Sending the request message PUBKEY to the server\n");
   printf("e=%ld n=%ld d=%ld\n",pub_key.public_key.e , pub_key.public_key.n ,pvt_key.private_key.d);
   pubKey_msg.hdr.opcode = PUBKEY;
   pubKey_msg.hdr.src_addr = src_addr;
   pubKey_msg.hdr.dest_addr = dest_addr;
   
   pubKey_msg.e = pub_key.public_key.e;
   pubKey_msg.n = pub_key.public_key.n;

   status = send(cfd, &pubKey_msg, sizeof(PubKeyMsg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send****\n");
      return;
    }

       /* send the request message REQ to the server */
   printf("Sending the request message REQ to the server\n");
   pubKey_msg.hdr.opcode = REQ;
   pubKey_msg.hdr.src_addr = src_addr;
   pubKey_msg.hdr.dest_addr = dest_addr;
   printf("Enter File Name to download\n");
   scanf("%s",pubKey_msg.FileName);
    //strcpy(pubKey_msg.FileName,"input.txt");

   status = send(cfd, &pubKey_msg, sizeof(PubKeyMsg), 0);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to send****\n");
      return;
    }


    int k=1;
  //while (k--) 
  {
  /* receive greetings from server */
    FILE *write = fopen("receivedTemp.txt","w");
   nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
	if (nbytes == -1)
		fprintf(stderr, "*** Client error: unable to receive\n");
  fputs(recv_msg.buff,write);
  recv_msg.hdr.opcode = 0;
   
   		while( recv_msg.hdr.opcode == REP )
	   {
		   fputs(recv_msg.buff,write);
		   recv_msg.hdr.opcode = 0;

		   nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
		   if (nbytes == -1)
				fprintf(stderr, "*** Client error: unable to receive\n");
	   	}
      fclose(write);
	   	printf("Got the File\n");
	   	decode();

      /* receive Digest file from server */
  write = fopen("receivedMD.txt","w");
   nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
  if (nbytes == -1)
    fprintf(stderr, "*** Client error: unable to receive\n");
  fputs(recv_msg.buff,write);
  recv_msg.hdr.opcode = 0;
   
     while( recv_msg.hdr.opcode == MD )
     {
       fputs(recv_msg.buff,write);
       recv_msg.hdr.opcode = 0;

       nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
       if (nbytes == -1)
        fprintf(stderr, "*** Client error: unable to receive\n");
      }

        fseeko(write,-1 ,SEEK_END);
        off_t position = ftello(write);
        ftruncate(fileno(write), position);

      fclose(write);
      printf("Got the digest File\n");
      if(checkMessageDigest("ReceivedFile.txt","receivedMD.txt")==1)
        printf("SHA Digest is correct\n");
      else
        {printf("SHA Digest is NOT correct\n");exit(0);}

      nbytes = recv(cfd, &recv_msg, sizeof(RepMsg), 0);
       if (nbytes == -1)
        fprintf(stderr, "*** Client error: unable to receive\n");

      if( recv_msg.hdr.opcode == REQCOMM )
      {
        printf("Sending DISCONNECT msg\n");
         pubKey_msg.hdr.opcode = DISCONNECT;
         pubKey_msg.hdr.src_addr = src_addr;
         pubKey_msg.hdr.dest_addr = dest_addr;
         status = send(cfd, &pubKey_msg, sizeof(PubKeyMsg), 0);
         return;
      }

 	}//while


}


int main(int argc,char *argv[])
{
	char sip[16];
	int cfd;

	char str[STACK_SIZE];
	int x, e;
	char ch;
	long int plaintext, ciphertext, deciphertext;
	//getchar();
	extern int print_flag;
	extern int print_flag1;
	print_flag=print_flag1=0;						//md
	
	printf("******* Generating public and private keys { (e,n) , (d,n) } ***** \n\n");
	while(!KeyGeneration(&pub_key, &pvt_key))
	{
		//if(pub_key.public_key.e==pvt_key.private_key.d)continue;
    /*pub_key.public_key.e=523;
    pub_key.public_key.n=623;
    pvt_key.private_key.n=623;
    pvt_key.private_key.d=211;*/
	}
	
	printf("\n Public Key of Alice is (n,e): (%ld , %ld)\n\r", pub_key.public_key.n, pub_key.public_key.e);
	printf("\n Private key of Alice is (n,d): (%ld , %ld)\n\r", pvt_key.private_key.n,pvt_key.private_key.d);
   
   strcpy(sip, (argc == 2) ? argv[1] : DEFAULT_SERVER);
   cfd = serverConnect(sip);
   Talk_to_server (cfd);
   close(cfd);

return 0;
}

void decode()
{
	char line[1000];
	long int index;
	char decoding[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
						,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
						,'0','1','2','3','4','5','6','7','8','9'
						,',','.','!'};
	FILE *fpRdRcvd,*fpWrRcvd;

	fpRdRcvd = fopen("receivedTemp.txt","r");
	if(fpRdRcvd==NULL){printf("Error opening file\n");exit(0);}

	fpWrRcvd = fopen("ReceivedFile.txt","w");
	if(fpWrRcvd==NULL){printf("Error opening write file\n");exit(0);}

  if(fgets(line,sizeof(line),fpRdRcvd)==NULL)printf("Empty File\n");

  fseek(fpRdRcvd,0,SEEK_SET);
	while(fgets(line,sizeof(line),fpRdRcvd)!=NULL)
	{
		if(line[0]=='\n')fputs(line,fpWrRcvd);
		else
		{
			index = atoi(line);
			index = DecryptionAlgorithm(index,pvt_key);
			fprintf(fpWrRcvd,"%c",decoding[index]);
		}
		
	}
/*  fseeko(fpWrRcvd,-6,SEEK_END);
  off_t position = ftello(fpWrRcvd);
  ftruncate(fileno(fpWrRcvd), position);*/

fclose(fpRdRcvd);
fclose(fpWrRcvd);

}

int checkMessageDigest(char ReceivedFile[],char receivedMD[])
{
  FILE *fpRcvd,*fpRcvdMD,*fpRcvdMDtemp;
  unsigned char hash[1000];
  unsigned char buff[1000];
  unsigned char buffMD[1000];
  unsigned char buffMDtemp[1000];
  
  messageDigest("ReceivedFile.txt","MDtemp");

 fpRcvdMD = fopen(receivedMD,"r");
  if(fpRcvdMD==NULL){printf("Error opening file\n");exit(0);}

  fpRcvdMDtemp = fopen("MDtemp","r");
  if(fpRcvdMDtemp==NULL){printf("Error opening file\n");exit(0);}

  unsigned char temp1[1000],temp2[1000];
  //comparing digests
  fflush(stdin);fflush(stdout);

  char ch,ch2;
  
  while((ch=fgetc(fpRcvdMD))!=EOF)
  {
    ch2=fgetc(fpRcvdMDtemp);
    if(ch!=ch2)
      return 0;
  }

  fclose(fpRcvdMD);
  fclose(fpRcvdMDtemp);

return 1;
}


void messageDigest(char inputFile[],char outputFile[])
{
  
  FILE *fptemp,*fpSha1;
  unsigned char hash[1000];
  unsigned char buff[1000];
  fptemp = fopen(inputFile,"r");
  if(fptemp==NULL){printf("Error opening file\n");exit(0);}
  fpSha1 = fopen(outputFile,"w");
  if(fpSha1==NULL){printf("Error opening file\n");exit(0);}

  memset(buff,'\0',sizeof(buff));
  memset(hash,'\0',sizeof(hash));

  fflush(stdin);fflush(stdout);
  while(fread(buff,sizeof(char),256,fptemp)>0)
  {
    SHA1(buff,sizeof(buff),hash);
    fputs(hash,fpSha1);
  }

  fclose(fptemp);
  fclose(fpSha1);

}
