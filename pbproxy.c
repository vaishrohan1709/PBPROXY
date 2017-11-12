
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <unistd.h> 
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <openssl/buffer.h> 
#include <fcntl.h>
#define BLOCK_LENGTH 4096

struct ctr_state {
    unsigned char ivec[16]; 
    unsigned int num;
    unsigned char ecount[16];
};

char * get_key(char *key_file);
void client_side(char *dest_host_name,int dest_port,char *key);
void server_side(int listen_port,int dest_port,char *dest_host_name, char *key);
int init_ctr(struct ctr_state *state, const unsigned char iv[8]);

int init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
    state->num = 0;
    memset(state->ecount, 0, 16);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
    return(0);
}

void server_side(int listen_port,int dest_port,char *dest_host_name, char *key){
    int socket_desc , client_sock , c ;
    struct sockaddr_in server;
    struct hostent *dest_host=0;
    if(!gethostbyname(dest_host_name)){
        printf("Could not find this host\n");
    }
    dest_host=gethostbyname(dest_host_name);

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if(socket_desc==-1)
    {
        printf("Could not create socket!");
    }
    //puts("Socket created!");

    bzero((char *) &server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(listen_port);
     
    if(bind(socket_desc,(struct sockaddr *)&server,sizeof(server))< 0)
    {
        
        perror("Bind failed. Error!");
        return ;
    }
    //puts("Bind Done!");
     
    if(listen(socket_desc , 3)<0){
        perror("Listening error!\n");
        return;
    }
    puts("Waiting for incoming connections");
    c = sizeof(server);
    client_sock = accept(socket_desc, (struct sockaddr *)&server, (socklen_t*)&c);
    if (client_sock < 0)
    {
        perror("Accept Failed!");
        return ;
    }
    puts("Connection Accepted!");



    struct sockaddr_in server2;
    int sock_server=socket(AF_INET , SOCK_STREAM , 0);
    if (sock_server == -1)
    {
        printf("Could not create server-server socket");
        return ;
    }
    //puts("Server-Server Socket created!");
    bzero((char *) &server2, sizeof(server2));
    server2.sin_addr.s_addr = ((struct in_addr *)(dest_host->h_addr))->s_addr;
    server2.sin_family = AF_INET;
    server2.sin_port = htons(dest_port);
    if (connect(sock_server , (struct sockaddr *)&server2 , sizeof(server2)) < 0)
    {
        perror("Server-server Connection Failed. Error!");
        return ;
    }    
    //puts("Server-server Connected\n");


    //Variables related  to connection <-- client
    char client_cipher_message[BLOCK_LENGTH];
    memset(client_cipher_message,0,BLOCK_LENGTH);
    char client_message[BLOCK_LENGTH];
    memset(client_message,0,BLOCK_LENGTH);
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);


    //Variables related to connection -->client
    unsigned char cipher_client[BLOCK_LENGTH];
    char server_reply2[BLOCK_LENGTH];
    memset(server_reply2,0,BLOCK_LENGTH);

    //making both sockets non-blocking
    fcntl(client_sock, F_SETFL, O_NONBLOCK);
    fcntl(sock_server, F_SETFL, O_NONBLOCK);

    int flag=0;
    int read_size=0;

    while(1)
    {     
        while(flag==1){
            puts("Waiting for incoming connections\n");
            client_sock=accept(socket_desc, (struct sockaddr *)&server, (socklen_t*)&c);
            if (client_sock < 0)
            {
                perror("Accept Failed!");
                return ;
            }
            puts("Connection Accepted!");



            struct sockaddr_in server2;
            int sock_server=socket(AF_INET , SOCK_STREAM , 0);
            if (sock_server == -1)
            {   
                printf("Could not create server-server socket");
                return ;
            }
            //puts("Server-Server Socket created!");
            bzero((char *) &server2, sizeof(server2));
            server2.sin_addr.s_addr = ((struct in_addr *)(dest_host->h_addr))->s_addr;
            server2.sin_family = AF_INET;
            server2.sin_port = htons(dest_port);
            if (connect(sock_server , (struct sockaddr *)&server2 , sizeof(server2)) < 0)
            {
                perror("Server-server Connection Failed. Error!");
                return ;
            }
            //puts("Server-server Connected\n");
            fcntl(client_sock, F_SETFL, O_NONBLOCK);
            fcntl(sock_server, F_SETFL, O_NONBLOCK);
            flag=0;
        }
        
        //receiving from client 
        while((read_size=read(client_sock , client_cipher_message , BLOCK_LENGTH))>=0 && flag==0){
            if (read_size == 0) {
                close(client_sock);
                close(sock_server);
                fprintf(stderr, "Proxy Server says - Client exiting\n");
                flag=1;
                break;
            }

            if (read_size > 0){
                //decrypting and sending to server
                struct ctr_state state;
                unsigned char iv[8];
                unsigned char client_message[read_size-8];
                memcpy(iv, client_cipher_message, 8);
                init_ctr(&state, iv);
                char *ptr=client_cipher_message;
                AES_ctr128_encrypt(ptr+8, client_message, read_size-8, &aes_key, state.ivec, state.ecount, &state.num);
                write(sock_server ,  client_message , read_size-8);
            }

            if (read_size < BLOCK_LENGTH)
                break;

        }
        //receiving from server
        while((read_size=read(sock_server , server_reply2 , BLOCK_LENGTH))>=0 &&flag==0){
            if (read_size == 0) {
                close(client_sock);
                close(sock_server);
                fprintf(stderr, "Proxy Server says -Server exiting\n");
            }

            if (read_size > 0){
                //encrypting and sending to client
                struct ctr_state state;
                unsigned char iv[8];
                unsigned char cipher_client[read_size];
                RAND_bytes(iv, 8);
                char *IVplusMessage = malloc(read_size + 8);
                memcpy(IVplusMessage, iv, 8);
                init_ctr(&state, iv);
                AES_ctr128_encrypt(server_reply2, cipher_client, read_size, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(IVplusMessage+8,cipher_client,read_size);
                write(client_sock , IVplusMessage ,read_size+8);
                free(IVplusMessage);
            }

            if (read_size < BLOCK_LENGTH)
                break;
        }
    }
}


void client_side(char *dest_host_name,int dest_port,char *key){
    struct hostent *dest_host=0;
    if(!gethostbyname(dest_host_name)){
        printf("Could not find this host\n");
    }
    dest_host=gethostbyname(dest_host_name);
    
    int sock;
    struct sockaddr_in server;
    bzero((char *) &server, sizeof(server));
    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
    {
        printf("Could not create socket");
        return ;
    }
    //puts("Socket created!");
    server.sin_addr.s_addr = ((struct in_addr *)(dest_host->h_addr))->s_addr;
    server.sin_family = AF_INET;
    server.sin_port = htons(dest_port);
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("Connection Failed. Error!");
        return ;
    }

    //puts("Connected!");
    
    //Variables about connection --> proxy server
    char message[BLOCK_LENGTH];
    memset(message,0,BLOCK_LENGTH);
    unsigned char cipher[BLOCK_LENGTH];
    memset(cipher,0,BLOCK_LENGTH);  
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    //Variables about connection <-- proxy server
    char server_message[BLOCK_LENGTH];
    memset(server_message,0,BLOCK_LENGTH);
    char server_reply[BLOCK_LENGTH];
    memset(server_reply,0,BLOCK_LENGTH);
    
    //making both sockets non-blocking
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    int read_size=0;

    while(1)
    {   
        //stdin->proxy server
        while((read_size=read(STDIN_FILENO, message, BLOCK_LENGTH))>=0){

            if(read_size==0){
                fprintf(stderr, "Client Exiting!\n");
                return;
            }
            if (read_size > 0){
                //encrypting and sending to proxy server
                struct ctr_state state;
                unsigned char iv[8];
                unsigned char cipher[read_size];
                RAND_bytes(iv, 8);
                char *IVplusMessage = malloc(read_size + 8);
                memset(IVplusMessage,0,read_size+8);
                memcpy(IVplusMessage, iv, 8);
                init_ctr(&state, iv);
                AES_ctr128_encrypt(message, cipher, read_size, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(IVplusMessage+8,cipher,read_size);
                write(sock,IVplusMessage, read_size+8);
                free(IVplusMessage);
            }

            if (read_size < BLOCK_LENGTH)
                break;
             
        }

        //proxy server->client->stdout      
        while((read_size=read(sock , server_reply , BLOCK_LENGTH))>=0){

            if (read_size == 0) {
                fprintf(stderr, "Client Exiting!\n");
                return;
            }
            if (read_size > 0){
                //receiving and decrypting to stdout
                struct ctr_state state;
                unsigned char iv[8];
                unsigned char server_message[read_size-8];
                memcpy(iv, server_reply, 8);
                init_ctr(&state, iv);
                AES_ctr128_encrypt(server_reply+8, server_message,read_size-8, &aes_key, state.ivec, state.ecount, &state.num);
                write(STDOUT_FILENO,server_message, read_size-8);
            }
            if (read_size < BLOCK_LENGTH)
                break;
        }
    }
}
char * get_key(char *key_file){
    long file_length=0;
    char *key;
    if(!fopen(key_file,"r")){
        printf("Key file could not be opened!\n");
        return 0;
    }
    FILE *file=fopen(key_file,"r");
    fseek(file,0,SEEK_END);
    file_length=ftell(file);
    fseek(file,0,SEEK_SET);
    if(!malloc(file_length)){
        printf("Memory problem!\n");
        return 0;
    }
    key=malloc(file_length);
    if(!fread(key,1,file_length,file)){
        printf("File read error!\n");
        return 0;
    }

    fclose(file);
    return key;
    
}

int main(int argc, char **argv)
{   
    struct hostent *dest_host=0;
    char c=0;
    int listen_port=0;
    int mode=0;
    char *key_file=0;
    int dest_arg=0;
    char *dest_host_name=0;
    int dest_host_port=0;
    char *key=0;
    while((c=getopt(argc,argv,"l:k:"))!=-1){
        switch(c){
            case 'l':
            listen_port = atoi(optarg);
            mode=1;
            break;
            
            case 'k':
            key_file = optarg;
            key=get_key(key_file);
            if(!key){
                printf("No key!\n");
            }
            break;

            case '?':
            if (optopt == 'k' || optopt == 'l')
              fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            
            else if (isprint (optopt))
              fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
              fprintf (stderr,
                       "Unknown option character `\\x%x'.\n",
                       optopt);
            return 1;
            break;

            default: break;
        }


    }
    for (int index = optind; index < argc; index++){
        if(dest_arg==0){
            dest_host_name=argv[index];
            dest_arg=1;
        }
        else if(dest_arg==1){
            dest_host_port=atoi(argv[index]);
            break;
        }
    }


    /*printf("Listening Port:%d\n",listen_port);
    printf("Key file:%s\n",key_file);
    printf("Destination Host:%s\n",dest_host_name);
    printf("Destination Host Port:%d\n",dest_host_port);
    printf("Key:%s\n",key);*/
    
    if(!mode){
        client_side(dest_host_name,dest_host_port,key);
    }
    else{
        server_side(listen_port,dest_host_port,dest_host_name,key);
    }
    return 0;
}