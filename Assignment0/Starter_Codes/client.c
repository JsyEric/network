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
#include <arpa/inet.h>
#define SEND_BUFFER_SIZE 2048

void send_data(int socket_fd) {
    char buffer[SEND_BUFFER_SIZE] = {0};
    ssize_t bytes_read;
    while ((bytes_read = fread(buffer, 1, SEND_BUFFER_SIZE, stdin)) > 0) {
        ssize_t bytes_sent = send(socket_fd, buffer, bytes_read, 0);
        if (bytes_sent < 0) {
            perror("send failed");
            return;
        }
        memset(buffer, 0, SEND_BUFFER_SIZE);
    }
    if (ferror(stdin)) {
        perror("fread from stdin failed");
    }
}
/* TODO: client()
 * Open socket and send message from stdin.
 * Return 0 on success, non-zero on failure
*/
int client(char *server_ip, char *server_port) {
  int sockfd;
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_port = htons(atoi(server_port));
  address.sin_addr.s_addr = inet_addr(server_ip);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return 1;
  }

  if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("connect");
    return 1;
  }

  send_data(sockfd);
  close(sockfd);

  return 0;
}

/*
 * main()
 * Parse command-line arguments and call client function
*/
int main(int argc, char **argv) {
  char *server_ip;
  char *server_port;

  if (argc != 3) {
    fprintf(stderr, "Usage: ./client-c [server IP] [server port] < [message]\n");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  server_port = argv[2];
  return client(server_ip, server_port);
}
