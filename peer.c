/*
 * Warren Grugett, Nathan Ueberschaer
 * EECE 446 Introduction to Computer Networks
 * Fall 2026
 */

#include <stdint.h>
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

/* This code is based on an updated version of the sample code from "Computer
 * Networks: A Systems Approach," 5th Edition by Larry L. Peterson and Bruce S.
 * Davis. Some code comes from man pages, mostly getaddrinfo(3).
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Lookup a host IP address and connect to it using service. Arguments match the
 * first two arguments to getaddrinfo(3).
 *
 * Returns a connected socket descriptor or -1 on error. Caller is responsible
 * for closing the returned socket.
 */
int lookup_and_connect(const char *host, const char *service);
int sendall(int s, char *buf, int len);
int recvall(int s, char *buf, int len);

void printHex(char *buf, uint32_t count) {
  for (uint32_t i = 0; i < count; i++)
    printf("%02X|", (unsigned char)buf[i]);
  printf("\n");
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    printf("usage: %s <registry_location> <port> <id>\n", argv[0]);
    exit(1);
  }

  char *host = argv[1];
  char *port = argv[2];
  uint32_t id = atoi(argv[3]);
  if (id > 65534 || id < 1) {
    printf("Error: ID should be a positive integer less than 65,535\n");
    exit(1);
  }
  id = htonl(id);
  char buf[1201];
  int s;
  int reqlen; // signed int to hold request length of buffer

  /* Lookup IP and connect to server */
  if ((s = lookup_and_connect(host, port)) < 0)
    exit(1);

  while (1) {
    printf("Enter a command: ");
    scanf("%s", buf);
    if (!strcmp(buf, "JOIN")) {
      buf[0] = 0;
      memcpy(buf + 1, &id, 4);
      reqlen = 5;
      if (sendall(s, buf, reqlen) < reqlen) {
        printf("Error while sending request\n");
        close(s);
        exit(1);
      }
    } else if (!strcmp(buf, "PUBLISH")) {
      uint32_t count = 0;
      int offset = 5;
      int o;
      DIR *d;
      struct dirent *e;
      d = opendir("SharedFiles");
      if (!d) {
        printf("Error while opening folder SharedFiles/\n");
        close(s);
        exit(1);
      }
      while ((e = readdir(d)) != NULL)
        if (e->d_type == DT_REG) {
          o = strlen(e->d_name) + 1;
          if (offset + o > 1200)
            break;
          memcpy(buf + offset, e->d_name, strlen(e->d_name) + 1);
          offset += o;
          count++;
        }
      closedir(d);
      buf[0] = 1;
      count = htonl(count);
      memcpy(buf + 1, &count, 4);
      reqlen = offset;
      if (sendall(s, buf, reqlen) < reqlen) {
        printf("Error while sending request\n");
        close(s);
        exit(1);
      }
    } else if (!strcmp(buf, "SEARCH")) {
      char file[100];
      printf("Enter a file name: ");
      scanf("%s", file);
      buf[0] = 2;
      memcpy(buf + 1, file, strlen(file) + 1);
      reqlen = 2 + strlen(file);
      if (sendall(s, buf, reqlen) < reqlen) {
        printf("Error while sending request\n");
        close(s);
        exit(1);
      }
      if (recvall(s, buf, 10) == 10) {
        uint32_t pid, pport;
        char pip[INET_ADDRSTRLEN];
        memcpy(&pid, buf, 4);
        pid = ntohl(pid);
        inet_ntop(AF_INET, buf + 4, pip, sizeof(pip));
        pip[INET_ADDRSTRLEN - 1] = '\0';
        memcpy(&pport, buf + 8, 4);
        pport = ntohs(pport);
        if (!pid)
          printf("File not indexed by registry\n");
        else
          printf("File found at\nPeer %u\n%s:%d\n", pid, pip, pport);
      }
    } else if (!strcmp(buf, "EXIT")) {
      break;
    } else {
      printf("Please enter a valid command: {JOIN|SEARCH|EXIT}\n");
      continue;
    }
  }

  close(s);

  return 0;
}

// Modified from Beej's Guide to Network Programming
int sendall(int s, char *buf, int len) {
  int total = 0;       // how many bytes we've sent
  int bytesleft = len; // how many we have left to send
  int n;

  while (total < len) {
    n = send(s, buf + total, bytesleft, 0);
    if (n == -1)
      break;
    total += n;
    bytesleft -= n;
  }

  return total;
}

// Modified from Beej's Guide to Network Programming
int recvall(int s, char *buf, int len) {
  int total = 0;       // how many bytes we've read
  int bytesleft = len; // how many we have left to read
  int n;

  while (total < len) {
    n = recv(s, buf + total, bytesleft, 0);
    if (n < 1)
      break;
    total += n;
    bytesleft -= n;
  }
  return total;
}

int lookup_and_connect(const char *host, const char *service) {
  struct addrinfo hints;
  struct addrinfo *rp, *result;
  int s;

  /* Translate host name into peer's IP address */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  if ((s = getaddrinfo(host, service, &hints, &result)) != 0) {
    fprintf(stderr, "stream-talk-client: getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  /* Iterate through the address list and try to connect */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
      continue;
    }

    if (connect(s, rp->ai_addr, rp->ai_addrlen) != -1) {
      break;
    }

    close(s);
  }
  if (rp == NULL) {
    perror("stream-talk-client: connect");
    return -1;
  }
  freeaddrinfo(result);

  return s;
}
