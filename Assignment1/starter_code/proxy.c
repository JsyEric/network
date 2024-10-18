#include "proxy_parse.h"
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
#include <netinet/tcp.h>

#define QUEUE_LENGTH 10
#define RECV_BUFFER_SIZE 4096
/* TODO: proxy()
 * Establish a socket connection to listen for incoming connections.
 * Accept each client request in a new process.
 * Parse header of request and get requested URL.
 * Get data from requested remote server.
 * Send data to the client
 * Return 0 on success, non-zero on failure
 */

int handle_client(char *recv_buffer, int bytes_received, int child_socket)
{
  int flag = 200;
  struct ParsedRequest *req = ParsedRequest_create();
  if (ParsedRequest_parse(req, recv_buffer, bytes_received) < 0)
  {
    perror("ParsedRequest_parse");
    flag = 400;
    goto end;
  }
  if (strcmp(req->version, "HTTP/1.1") == 0)
  {
    req->version = "HTTP/1.0";
  }

  if (strcmp(req->method, "GET") != 0)
  {
    flag = 501;
    goto end;
  }

  ParsedHeader_set(req, "Host", req->host);
  ParsedHeader_set(req, "Connection", "close");
  char *new_request_header = (char *)malloc(ParsedHeader_headersLen(req));
  if (ParsedRequest_unparse_headers(req, new_request_header, ParsedHeader_headersLen(req)) < 0)
  {
    perror("ParsedRequest_unparse_headers");
    return 1;
  }

  char *new_request = (char *)malloc(strlen(req->method) + strlen(req->path) + strlen(req->version) + strlen(new_request_header) + 4);
  strcat(new_request, req->method);
  strcat(new_request, " ");
  strcat(new_request, req->path);
  strcat(new_request, " ");
  strcat(new_request, req->version);
  strcat(new_request, "\r\n");
  strcat(new_request, new_request_header);
  strcat(new_request, "\r\n");
  free(new_request_header);

  // create a new socket to connect to the remote server
  int remote_socket;
  struct addrinfo hints, *remote_info;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(req->host, "80", &hints, &remote_info) != 0)
  {
    perror("getaddrinfo");
    return 1;
  }
  if ((remote_socket = socket(remote_info->ai_family, remote_info->ai_socktype, remote_info->ai_protocol)) < 0)
  {
    perror("socket");
    return 1;
  }
  if (connect(remote_socket, remote_info->ai_addr, remote_info->ai_addrlen) < 0)
  {
    perror("connect");
    return 1;
  }
  // send request to the remote server
  if (send(remote_socket, new_request, strlen(new_request), 0) < 0)
  {
    perror("send");
    return 1;
  }
  // read response from the remote server
  int bytes_received_remote;
  while ((bytes_received_remote = recv(remote_socket, recv_buffer, RECV_BUFFER_SIZE, 0)) > 0)
  {
    if (send(child_socket, recv_buffer, bytes_received_remote, 0) < 0)
    {
      perror("send");
      return 1;
    }
  }
  close(remote_socket);
  ParsedRequest_destroy(req);
  return 0;

end:
  if (flag == 501)
  {
    char *response = "HTTP/1.0 501 Not Implemented\r\n\r\n";
    if (send(child_socket, response, strlen(response), 0) < 0)
    {
      perror("send");
      return 1;
    }
    return 0;
  }
  else if (flag == 400)
  {
    char *response = "HTTP/1.0 400 Bad Request\r\n\r\n";
    if (send(child_socket, response, strlen(response), 0) < 0)
    {
      perror("send");
      return 1;
    }
    return 0;
  }
  return 1;
}

int proxy(char *proxy_port)
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
  address.sin_port = htons(atoi(proxy_port));

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
  // fork a new process for each client
  while (1)
  {
    struct sockaddr_in client_address;
    int child_socket;
    if ((child_socket = accept(sockfd, (struct sockaddr *)&client_address, (socklen_t *)&addr_len)) < 0)
    {
      perror("accept");
      return 1;
    }
    pid_t pid = fork();
    if (pid < 0)
    {
      perror("fork");
      return 1;
    }
    if (pid == 0)
    {
      // child process
      close(sockfd);
      // read request from client at a time
      int received_bytes;
      char request_buffer[8192] = {0};
      int total_received_bytes = 0;
      while ((received_bytes = recv(child_socket, recv_buffer, RECV_BUFFER_SIZE - 1, 0)) > 0)
      {
        recv_buffer[received_bytes] = '\0';
        strcat(request_buffer, recv_buffer);
        total_received_bytes += received_bytes;
        if (strstr(request_buffer, "\r\n\r\n") != NULL)
        {
          exit(handle_client(request_buffer, total_received_bytes, child_socket));
        }
      }
    }
    else
    {
      // parent process
      close(child_socket);
    }
  }

  return 0;
}

int main(int argc, char *argv[])
{
  char *proxy_port;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: ./proxy <port>\n");
    exit(EXIT_FAILURE);
  }

  proxy_port = argv[1];
  return proxy(proxy_port);
}
