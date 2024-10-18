#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 2048

/* TODO: server()
 * Open socket and wait for client to connect
 * Print received message to stdout
 * Return 0 on success, non-zero on failure
 */
int server(char *server_port)
{
  int sockfd;
  struct sockaddr_in address;
  char recv_buffer[RECV_BUFFER_SIZE] = {0};
  int addr_len = sizeof(address);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket");
    return 1;
  }
  
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(atoi(server_port));

  if (bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind");
    return 1;
  }

  if (listen(sockfd, QUEUE_LENGTH) < 0)
  {
    perror("listen");
    return 1;
  }

  while (1)
  {
    struct sockaddr_in client_address;
    int child_socket;
    if ((child_socket = accept(sockfd, (struct sockaddr *)&client_address, (socklen_t *)&addr_len)) < 0)
    {
      perror("accept");
      return 1;
    }
    int bytes_received;
    while ((bytes_received = recv(child_socket, recv_buffer, RECV_BUFFER_SIZE, 0)) > 0)
    { 
      fwrite(recv_buffer, 1, bytes_received, stdout);
      fflush(stdout);
      memset(recv_buffer, 0, RECV_BUFFER_SIZE);
    }
  }

  return 0;
}

/*
 * main():
 * Parse command-line arguments and call server function
 */
int main(int argc, char **argv)
{
  char *server_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./server-c [server port]\n");
    exit(EXIT_FAILURE);
  }

  server_port = argv[1];
  return server(server_port);
}
