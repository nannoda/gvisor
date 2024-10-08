// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char** argv) {
  int fd, conn;
  struct sockaddr_in addr;
  int opt = 1;
  int addrlen = sizeof(addr);
  short port = 9000;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(fd, 1) < 0) {
    perror("listen failed");
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < 10; i++) {
    conn = accept(fd, (struct sockaddr*)&addr, (socklen_t*)&addrlen);
    if (conn >= 0) {
      break;
    }
  }

  if (conn < 0) {
    perror("accept failed");
    exit(EXIT_FAILURE);
  }

  int n = 0;
  char send_buf[24] = "Hello!";
  n = write(conn, send_buf, strlen(send_buf));
  if (n < 0) {
    perror("ERROR writing to socket");
    exit(1);
  }

  char buffer[256];
  bzero(buffer, 256);
  n = read(conn, buffer, 255);
  if (n < 0) {
    perror("ERROR reading from socket");
    return n;
  }

  return 0;
}
