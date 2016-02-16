
#include "headers.h"

key pub_key, pvt_key;

/* Start the server: socket(), bind() and listen() */
int startServer ()
{
   int sfd;                    /* for listening to port PORT_NUMBER */
   struct sockaddr_in saddr;   /* address of server */
   int status;


   /* Request for a socket descriptor */
   sfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sfd == -1) {
      fprintf(stderr, "*** Server error: unable to get socket descriptor\n");
      exit(1);
   }

   /* Set the fields of server's internet address structure */
   saddr.sin_family = AF_INET;            /* Default value for most applications */
   saddr.sin_port = htons(SERVICE_PORT);  /* Service port in network byte order */
   saddr.sin_addr.s_addr = INADDR_ANY;    /* Server's local address: 0.0.0.0 (htons not necessary) */
   bzero(&(saddr.sin_zero),8);            /* zero the rest of the structure */

   /* Bind the socket to SERVICE_PORT for listening */
   status = bind(sfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to bind to port %d\n", SERVICE_PORT);
      exit(2);
   }

   /* Now listen to the service port */
   status = listen(sfd,Q_SIZE);
   if (status == -1) {
      fprintf(stderr, "*** Server error: unable to listen\n");
      exit(3);
   }

   fprintf(stderr, "+++ Server successfully started, listening to port %hd\n", SERVICE_PORT);
   return sfd;
}


/* Accept connections from clients, spawn a child process for each request */
void serverLoop ( int sfd )
{
   int cfd;                    /* for communication with clients */
   struct sockaddr_in caddr;   /* address of client */
   int size;
   int k=1;

    while (1)
    {
      /* accept connection from clients */
      printf("Waiting for clients --------------\n");
      cfd = accept(sfd, (struct sockaddr *)&caddr, &size);
      printf("Accepted\n");
      if (cfd == -1)
      {
         fprintf(stderr, "*** Server error: unable to accept request\n");
         continue;
      }
      //--------------------------------------------------Seg Fault----------------------------------
     //printf("**** Connected with %s \n", inet_ntoa(caddr.sin_addr));
     
      /* fork a child to process request from client */
      if (!fork()) {
         Talk_to_client (cfd);
         //fprintf(stderr, "**** Closed connection with %s \n", inet_ntoa(caddr.sin_addr));
         close(cfd);
         exit(0);
      }

      /* parent (server) does not talk with clients */
      close(cfd);

      /* parent waits for termination of child processes */
      while (waitpid(-1,NULL,WNOHANG) > 0);
   }
}


/* Interaction of the child process with the client */
void Talk_to_client ( int cfd )
{
   int status;
   int nbytes;
   int src_addr, dest_addr;
   int chk1, chk2; 
   RepMsg send_msg;
   RepMsg md_msg;
   RepMsg disconnect_msg;
   PubKeyMsg recv_msg;


   dest_addr = inet_addr("192.168.1.245");
   src_addr = inet_addr("DEFAULT_SERVER");
 
  int k=3;
   while (k--) 
   {
   /* Receive response from server */
   nbytes = recv(cfd, &recv_msg, 6000, 0);//sizeof(PubKeyMsg)
   if (nbytes == -1) 
   {
      fprintf(stderr, "*** Server error: unable to receive\n");
      return;
   }
   
   switch ( recv_msg.hdr.opcode ) 
   {

  case PUBKEY : printf("Message:: Public Key of Client received \n");
              printf("Message:: with opcode %d (PUBKEY) received from client (%d)\n", recv_msg.hdr.opcode, recv_msg.hdr.src_addr);  
              printf("Received values in REQ message are: \n");
              printf("Public Key e = %d\n", recv_msg.e);
              printf("Public Key n = %d\n", recv_msg.n);
              pub_key.public_key.n = recv_msg.n;
              pub_key.public_key.e = recv_msg.e;
              break;

    
  case REQ : /* Request message */
              printf("Message:: with opcode %d (REQ) received from client (%d) FileName %s\n", recv_msg.hdr.opcode, 
                                              recv_msg.hdr.src_addr,recv_msg.FileName);
              printf("Sending the reply message REP to the client \n");

              encode(recv_msg.FileName);
              send_msg.hdr.opcode = REP;
              send_msg.hdr.src_addr = src_addr;        
              send_msg.hdr.dest_addr = dest_addr;

              FILE *fptemp;
              fptemp = fopen("temp","r");
              if(fptemp==NULL){printf("Error opening file\n");exit(0);}
              memset(send_msg.buff,'\0',sizeof(send_msg.buff));
              while(fread(send_msg.buff,sizeof(char),256,fptemp)>0)
              {
                status = send(cfd, &send_msg, sizeof(RepMsg), 0);
               if (status == -1) {
                fprintf(stderr, "*** Server error: unable to send\n");
                return;
                }
              }
              fclose(fptemp);
              printf("Send Requested FIle\n");
              printf("Sending Digest of File\n");

              //Sending Digest of original file
              md_msg.hdr.opcode = MD;
              md_msg.hdr.src_addr = src_addr;        
              md_msg.hdr.dest_addr = dest_addr;

              messageDigest("input.txt","md");
              FILE *fpSha1;
              fpSha1 = fopen("md","r");
              if(fpSha1==NULL){printf("Error opening file\n");exit(0);}

              while(fread(md_msg.buff,sizeof(char),256,fpSha1)>0)
              {
                status = send(cfd, &md_msg, sizeof(RepMsg), 0);
               if (status == -1) {
                fprintf(stderr, "*** Server error: unable to send\n");
                return;
                }
              }

              fclose(fpSha1);
              printf("Send Digest FIle\n");

              //Sending REQCOMM of original file
              printf("Sending Disconnect msg\n");
              disconnect_msg.hdr.opcode = REQCOMM;
              disconnect_msg.hdr.src_addr = src_addr;        
              disconnect_msg.hdr.dest_addr = dest_addr;
              status = send(cfd, &disconnect_msg, sizeof(RepMsg), 0);              
              break;

    case DISCONNECT : /* Disconnect */

              md_msg.hdr.opcode = DISCONNECT;
              md_msg.hdr.src_addr = src_addr;        
              md_msg.hdr.dest_addr = dest_addr;
              status = send(cfd, &md_msg, sizeof(RepMsg), 0); 
               if (status == -1) {
                fprintf(stderr, "*** Server error: unable to send\n");
                return;
                }

              exit(0);
              break;
    
    default: 
           printf("message received with opcode: %d\n", recv_msg.hdr.opcode);
           exit(0);  
 
   }//switch

 }//while

}

int main ()
{
   int sfd;
   sfd = startServer();   
   serverLoop(sfd);
}

/*** End of server.c ***/     

void encode(char file[])
{
  char ch;
  FILE *fpRead,*fpWrite;

  fpRead = fopen(file,"r");
  if(fpRead==NULL){printf("Error opening file\n");exit(0);}
  fpWrite = fopen("temp","w");
  if(fpWrite==NULL){printf("Error opening write file\n");exit(0);}

  while((ch=fgetc(fpRead))!=EOF)
  {
    if(ch>='A' && ch<='Z')fprintf(fpWrite,"%ld\n", EncryptionAlgorithm(ch-'A' +1 , pub_key));
    else if(ch>='a' && ch<='z')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(ch-'a'+27,pub_key));
    else if(ch>='0' && ch<='9')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(ch-'0'+53,pub_key));
    else if(ch==' ')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(0,pub_key));
    else if(ch==',')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(63,pub_key));
    else if(ch=='.')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(64,pub_key));
    else if(ch=='!')fprintf(fpWrite,"%ld\n",EncryptionAlgorithm(65,pub_key));
    else fprintf(fpWrite,"%c",ch);
  }
fclose(fpRead);
fclose(fpWrite);

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