/****************************************************************************
 * apps/system/crtos_daemon/cRTOS_main.h
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/sched_note.h>

#include <sys/wait.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <syscall.h>

#include <nuttx/init.h>
#include <nuttx/sched.h>
#include <nuttx/mm/mm.h>
#include <arch/io.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "netutils/netlib.h"

#include "cRTOS.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

enum
{
  PING,
  PONG,
  RETURN,
  EXEC,
  TRASH,
  MAX_TYPE
};

struct packet_header
{
  uint16_t type;
  uint32_t attribute;
  uint32_t length;
} __attribute__((packed));

/****************************************************************************
 * External Functions
 ****************************************************************************/

extern long rexec(const char *, int, int, char **, char **, uint64_t);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void setup_network(void)
{
  uint8_t mac[IFHWADDRLEN];
  struct in_addr addr;

  printf("\ncRTOS Daemon: Initializing Network (%s)...\n",
         CONFIG_SYSTEM_CRTOS_DAEMON_NIC);

  mac[0] = 0x00;
  mac[1] = 0xe0;
  mac[2] = 0xde;
  mac[3] = 0xad;
  mac[4] = 0xbe;
  mac[5] = 0xef;
  netlib_setmacaddr(CONFIG_SYSTEM_CRTOS_DAEMON_NIC, mac);

  /* Set up our host address */

  addr.s_addr = HTONL(CONFIG_SYSTEM_CRTOS_DAEMON_IPADDR);
  netlib_set_ipv4addr(CONFIG_SYSTEM_CRTOS_DAEMON_NIC, &addr);

  /* Set up the default router address */

  addr.s_addr = HTONL(CONFIG_SYSTEM_CRTOS_DAEMON_DRIPADDR);
  netlib_set_dripv4addr(CONFIG_SYSTEM_CRTOS_DAEMON_NIC, &addr);

  /* Setup the subnet mask */

  addr.s_addr = HTONL(CONFIG_SYSTEM_CRTOS_DAEMON_NETMASK);
  netlib_set_ipv4netmask(CONFIG_SYSTEM_CRTOS_DAEMON_NIC, &addr);

  /* New versions of netlib_set_ipvXaddr will not bring the network up,
   * So ensure the network is really up at this point.
   */

  netlib_ifup(CONFIG_SYSTEM_CRTOS_DAEMON_NIC);
}

static void send_packet(int connfd, int type, void *data, int size)
{
  struct packet_header hdr;

  memset(&hdr, 0, sizeof(hdr));

  hdr.type = type;

  if ((data != NULL) && (size != 0))
      hdr.length = size;

  write(connfd, &hdr, sizeof(struct packet_header));

  if ((data != NULL) && (size != 0))
      write(connfd, data, size);
}

static int recv_packet(int connfd, struct packet_header *hdr)
{
  return read(connfd, hdr, sizeof(struct packet_header));
}

extern long rexec(const char *path, int policy, int priority,
                  char *argv[], char *envp[], uint64_t shadow_tcb);

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int cRTOS_main(int argc, FAR char *argv[])
{
  int i;
  int listenfd;
  int connfd;
  int ret;
  bool run = true;
  bool handling;

  sigset_t set;

  struct sockaddr_in servaddr;
  struct sockaddr_in cliaddr;
  socklen_t clilen;

  struct packet_header pkt;

  printf("\ncRTOS Daemon: Starting...\n");

  (void)sigemptyset(&set);
  (void)sigaddset(&set, SIGCHLD);
  (void)sigprocmask(SIG_BLOCK, &set, NULL);

  setup_network();

  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenfd < 0)
    {
      perror("ERROR: failed to create socket.\n");
      return ERROR;
    }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port        = htons(CONFIG_SYSTEM_CRTOS_DAEMON_PORT);

  ret = bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
  if (ret < 0)
    {
      perror("ERROR: failed to bind socket.\n");
      return ERROR;
    }

  ret = listen(listenfd, CONFIG_SYSTEM_CRTOS_DAEMON_BACKLOG);
  if (ret < 0)
    {
      perror("ERROR: failed to start listening\n");
      return ERROR;
    }

  printf("cRTOS: Initialized! port: %d\n", CONFIG_SYSTEM_CRTOS_DAEMON_PORT);

  while (run)
    {
      printf("\ncRTOS: Waiting for client\n");

      /* new client connection */

      clilen = sizeof(cliaddr);
      connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);

      printf("cRTOS: New incoming connection\n");

      if (connfd != -1)
          printf("cRTOS: Connection accepted\n");
      else
          perror("cRTOS: Connection dropped\n");

      handling = true;
      while (handling)
        {
          printf("\ncRTOS: Waiting for command\n");

          /* read command */

          if (recv_packet(connfd, &pkt) <= 0)
            {
              handling = false;

              printf("cRTOS: Client %d disconnected, escape\n", connfd);

              close(connfd);

              /* relax */

              usleep(100000);

              break;
            }

          switch (pkt.type)
            {
              case PING:
                  printf("cRTOS: got PING, sent PONG...\n");
                  send_packet(connfd, PONG, NULL, 0);
                  break;

              case PONG:
                  printf("cRTOS: got PONG...\n");
                  break;

              case EXEC:
                {
                  /* Read the argc and argv */

                  uint64_t *data_buffer = (uint64_t *)malloc(pkt.length);

                  if (data_buffer == NULL)
                    {
                      printf("Allocating temporary data buffer failed\n");
                      break;
                    }

                  printf("allocated: %x bytes\n", pkt.length);

                  read(connfd, data_buffer, pkt.length);

                  uint64_t path_length = (data_buffer)[0] & 0xffffffff;
                  int      policy      = ((data_buffer)[1] >> 32);
                  int      priority    = (data_buffer)[1] & 0xffffffff;
                  uint64_t shadow_tcb  = (data_buffer)[2];
                  int      cargc       = (data_buffer)[3];
                  int      envc        = (data_buffer)[4];
                  char    *path        = (char *)(data_buffer + 5);
                  char    *data_holder = path + path_length + 1;
                  uint16_t off;

                  printf("Remote exec: path: %s, priority: %d,"
                         " shadow_tcb: %llx, argc: %d\n",
                         path, priority, shadow_tcb, cargc);

                  /* Construct argv */

                  char **cargv =
                    (char **)malloc((cargc + 1) * sizeof(char *));
                  if (cargv == NULL)
                    {
                      printf("Allocating argv failed\n");
                    }

                  int tmp = 0;
                  for (i = 0; i < cargc; i++)
                    {
                      cargv[i] = data_holder + tmp + 2;
                      off = (uint8_t)data_holder[tmp + 1];
                      off <<= 8;
                      off |= (uint8_t)data_holder[tmp];
                      tmp += off + 3;
                    }

                  /* mandatory to be compliant to POSIX interface */

                  cargv[i] = NULL;

                  /* Construct envp */

                  char **envp = (char **)malloc((envc + 1) * sizeof(char *));
                  if (envp == NULL)
                    {
                      printf("Allocating argv failed\n");
                    }

                  for (i = 0; i < envc; i++)
                    {
                      envp[i] = data_holder + tmp + 2;
                      off = (uint8_t)data_holder[tmp + 1];
                      off <<= 8;
                      off |= (uint8_t)data_holder[tmp];
                      tmp += off + 3;
                    }

                  /* mandantory to compliant POSIX interface */

                  envp[i] = NULL;

                  send_packet(connfd, RETURN, NULL, 0);

                  close(connfd);

                  /* use the rexec to load the program */

                  rexec(path, policy, priority,
                        cargv, envp,
                        shadow_tcb);

                  /* Now we are clear to recycle the memory
                   * argv envp had been copied to application's stack
                   */

                  free(data_buffer);
                  free(cargv);
                  free(envp);

                  handling = false;
                  break;
                }

              default:
                  printf("WARNING: Got trash from host %4x\n", pkt.type);
                  send_packet(connfd, TRASH, NULL, 0);
                  break;
            }
        }
    }

  return 0;
}
