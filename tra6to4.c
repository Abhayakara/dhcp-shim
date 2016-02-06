/* tra6to4.c
 *
 * Copyright (c) Nominum, Inc 2013, 2016
 * All Rights Reserved
 *
 * This file is part of DHCP-Shim.
 *
 * DHCP-Shim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DHCP-Shim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DHCP-Shim.  If not, see <http://www.gnu.org/licenses/>.
 */

#define __APPLE_USE_RFC_3542 1 /* blrg */

#include <sys/errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <poll.h>

#define DHCPv4
#include "shim.h"

#define DHCPv4_SERVER_PORT		67
#define DHCPv4_CLIENT_PORT		68
#define	OPTION_CLIENT_IDENTIFIER	61
#define OPTION_RAI			82
#define SUBOPTION_CIRCUIT_ID		1
#define SUBOPTION_REMOTE_ID		2
#define OPTION_PORT_RANGE_MIN		240
#define OPTION_PORT_RANGE_MAX		241
#define OPTION_END			255
#define OPTION_PAD			0

#define GIADDR_OFFSET	24
#define OPTIONS_START	240

int sock6fd;	/* DHCP4over6 socket. */
int sock4fd;	/* DHCP4 socket. */
struct in_addr server_addr;
struct in6_addr listen_addr;
struct in_addr relay_addr;

/* Process a packet arricing from a DHCPv4 server for a 4over6 client. */

static int
v6_packet(void)
{
  u_int8_t inpacket[MAX_PACKET_SIZE];
  u_int8_t outpacket[MAX_PACKET_SIZE];
  size_t outp, *inpp;
  int client_id_p = 0;
  int client_id_l = 0;

  OS_VARS;

  int result;
  size_t inmax;
  struct sockaddr_in6 from;
  socklen_t fromlen = sizeof from;
  struct sockaddr_in dest;

  result = recvfrom(sock6fd, inpacket, sizeof inpacket, 0,
		    (struct sockaddr *)&from, &fromlen);
  if (result < 0)
    {
      /* Whenever certain Linux kernels get bogon ICMP port unreachable
       * or ICMP host unreachable packets that implicate the DHCP port,
       * the next recvfrom will return that error, even though there's
       * no way to connect it to anything.   If that happens, just return
       * and we'll loop again.
       */

      if (errno == EHOSTUNREACH || errno == ECONNREFUSED)
	return 0;

      /* If we got some other error, chances are we are hosed, so exit. */
      else
	{
	  syslog(LOG_CRIT, "Unhandled (fatal) error receiving packet: %m");
	  exit(1);
	}
    }

  /* If we get an 8k message, we're going to assume it's truncated--
   * we should never get a message even close to that size.
   */
  if (result == MAX_PACKET_SIZE)
    {
      syslog(LOG_INFO, "Dropping mobygram");
      return 0;
    }

  if (result < OPTIONS_START)
    {
      syslog(LOG_INFO, "Dropping packet with no options.");
      return 0;
    }
  inmax = result;

  /* Copy the entire BOOTP header. */
  memcpy(&outpacket[0], &inpacket[0], OPTIONS_START);

  /* Set giaddr to our IPv4 address. */
  memcpy(&outpacket[GIADDR_OFFSET], &relay_addr, 4);

  outp = OPTIONS_START;
  inpp = &outp;

  /* Iterate across the options. */
  OS_START;

  if (opcode == OPTION_CLIENT_IDENTIFIER)
    {
      /* Save the location of the client identifier, but don't
       * copy it into the output packet.
       */
      client_id_p = inp + OPHDR_LEN;
      client_id_l = oplen;
      inp += OPHDR_LEN + oplen;
    }
  else if (opcode == OPTION_END)
    {
      inp = inmax;
    }
  else
    {
      if ((sizeof outpacket) - outp < OPHDR_LEN + oplen)
	{
	noroom:
	  syslog(LOG_INFO, "dropping packet: no room in output buffer.");
	  return 0;
	}

      /* Straight copy. */
      memcpy(&outpacket[outp], &inpacket[inp], oplen + OPHDR_LEN);
      inp += OPHDR_LEN + oplen;
      outp += OPHDR_LEN + oplen;
    }

  /* Skip over the end option if it's at the end. */
  if (inp + 1 == inmax && (inpacket[inp] == OPTION_END ||
			   inpacket[inp] == OPTION_PAD))
    inp++;

  OS_FINISH;
  
  /* Now fake up a client identifier from the /56. */
  if ((sizeof outpacket) - outp < OPHDR_LEN + 8)
    goto noroom;
  ophdr_store(&outpacket[outp], OPTION_CLIENT_IDENTIFIER);
  ophdr_store(&outpacket[outp + OPCODE_LEN], 8);
  outpacket[outp + OPHDR_LEN] = 1;
  memcpy(&outpacket[outp + OPHDR_LEN + 1], &from.sin6_addr, 7);
  outp += OPHDR_LEN + 8;

  /* Now fake up the relay agent information option. */
  if ((sizeof outpacket) - outp < (OPHDR_LEN + client_id_l +
				   OPHDR_LEN + IPV6_ADDR_SIZE +
				   OPHDR_LEN))
    goto noroom;
  if ((OPHDR_LEN + client_id_l + OPHDR_LEN + IPV6_ADDR_SIZE) > 255)
    goto noroom;
  ophdr_store(&outpacket[outp], OPTION_RAI);
  ophdr_store(&outpacket[outp + OPCODE_LEN],
	      (OPHDR_LEN + client_id_l + OPHDR_LEN + IPV6_ADDR_SIZE));
  outp += OPHDR_LEN;

  /* We send the client identifier in the remote-id suboption. */
  ophdr_store(&outpacket[outp], SUBOPTION_REMOTE_ID);
  ophdr_store(&outpacket[outp + OPCODE_LEN], client_id_l);
  memcpy(&outpacket[outp + OPHDR_LEN], &inpacket[client_id_p], client_id_l);
  outp += OPHDR_LEN + client_id_l;

  /* And the CRA address in the circuit-id suboption. */
  ophdr_store(&outpacket[outp], SUBOPTION_CIRCUIT_ID);
  ophdr_store(&outpacket[outp + OPCODE_LEN], IPV6_ADDR_SIZE);
  memcpy(&outpacket[outp + OPHDR_LEN],
	 (char *)&from.sin6_addr, IPV6_ADDR_SIZE);
  outp += OPHDR_LEN + IPV6_ADDR_SIZE;

  /* Destination is uncomplicated. */
  memset(&dest, 0, sizeof dest);
  dest.sin_port = htons(DHCPv4_SERVER_PORT);
  dest.sin_addr = server_addr;
#ifdef HAVE_SA_LEN
  dest.sin_len = sizeof server_addr;
#endif
  dest.sin_family = AF_INET;

  /* Put in ENDOPTION tag */
  ophdr_store(&outpacket[outp], OPTION_END);
  outp += OPCODE_LEN;
  
  /* Relay the packet. */
  sendto(sock4fd, outpacket, outp,
	 MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof dest);
  return 0;
}

/* Process a packet arriving from a DHCPv4overIPv6 client. */

static int
v4_packet(void)
{
  u_int8_t inpacket[MAX_PACKET_SIZE];
  u_int8_t outpacket[MAX_PACKET_SIZE];
  size_t outp, *inpp;
  int circuit_id_p = 0;
  int client_id_p = 0;
  int client_id_l = 0;
  int portmask;

  OS_VARS;

  int result;
  size_t inmax;
  int copying = 1;
  struct sockaddr_in from;
  socklen_t fromlen = sizeof from;
  struct sockaddr_in6 dest;

  result = recvfrom(sock4fd, inpacket, sizeof inpacket, 0,
		    (struct sockaddr *)&from, &fromlen);
  if (result < 0)
    {
      /* Whenever certain Linux kernels get bogon ICMP port unreachable
       * or ICMP host unreachable packets that implicate the DHCP port,
       * the next recvfrom will return that error, even though there's
       * no way to connect it to anything.   If that happens, just return
       * and we'll loop again.
       */

      if (errno == EHOSTUNREACH || errno == ECONNREFUSED)
	return 0;

      /* If we got some other error, chances are we are hosed, so exit. */
      else
	{
	  syslog(LOG_CRIT, "Unhandled (fatal) error receiving packet: %m");
	  exit(1);
	}
    }

  /* If we get an 8k message, we're going to assume it's truncated--
   * we should never get a message even close to that size.
   */
  if (result == MAX_PACKET_SIZE)
    {
      syslog(LOG_INFO, "Dropping mobygram");
      return 0;
    }

  if (result < OPTIONS_START)
    {
      syslog(LOG_INFO, "Dropping packet with no options.");
      return 0;
    }
  inmax = result;

  /* Copy the entire BOOTP header. */
  memcpy(&outpacket[0], &inpacket[0], OPTIONS_START);

  /* Set giaddr to local relay IPv4 address. */
  memcpy(&outpacket[GIADDR_OFFSET], &relay_addr, 4);

  outp = OPTIONS_START;
  inpp = &outp;

  /* Iterate across the options. */
  OS_START;

  if (opcode == OPTION_CLIENT_IDENTIFIER)
    {
      /* We don't need the faked-up client identifier anymore. */
      inp += OPHDR_LEN + oplen;
    }
  else if (opcode == OPTION_RAI)
    {
      /* This is kludgey, but the RAI is always supposed to be the last
       * option, so we're just going to dive into it rather than recursing.
       */
      copying = 0;
      inp += OPHDR_LEN;
    }
  else if (copying)
    {
      if ((sizeof outpacket) - outp < OPHDR_LEN + oplen)
	{
	noroom:
	  syslog(LOG_INFO, "dropping packet: no room in output buffer.");
	  return 0;
	}

      /* Straight copy. */
      memcpy(&outpacket[outp], &inpacket[inp], oplen + OPHDR_LEN);
      inp += OPHDR_LEN + oplen;
      outp += OPHDR_LEN + oplen;
    }
  else /* !copying */
    {
      if (opcode == SUBOPTION_CIRCUIT_ID)
	{
	  /* This is the IPv6 address we're going to reply to. */
	  circuit_id_p = inp + OPHDR_LEN;
	  if (oplen != IPV6_ADDR_SIZE)
	    {
	      syslog(LOG_INFO,
		     "dropping packet with wrong circuit id length: %d",
		     oplen);
	      return 0;
	    }
	}
      else if (opcode == SUBOPTION_REMOTE_ID)
	{
	  /* This is the client ID that was sent previously. */
	  client_id_p = inp + OPHDR_LEN;
	  client_id_l = oplen;
	}
      inp += OPHDR_LEN + oplen;
    }

  /* Skip over the end option. */
  if (inp < inmax && inpacket[inp] == OPTION_END)
    inp++;
  if (inp + 1 == inmax && inpacket[inp] == OPTION_PAD)
    inp++;

  OS_FINISH;
  
  /* Now put back the old client identifier, if there was one. */
  if (client_id_l)
    {
      if ((sizeof outpacket) - outp < OPHDR_LEN + client_id_l)
	goto noroom;
      ophdr_store(&outpacket[outp], OPTION_CLIENT_IDENTIFIER);
      ophdr_store(&outpacket[outp + OPCODE_LEN], client_id_l);
      memcpy(&outpacket[outp + OPHDR_LEN],
	     &inpacket[client_id_p], client_id_l);
      outp += OPHDR_LEN + client_id_l;
    }

  /* Without the circuit ID option, this packet is garbage. */
  if (!circuit_id_p)
    {
      syslog(LOG_INFO, "dropping packet with missing circuit ID option.");
      return 0;
    }

  /* Get the port set identifier from the CRA Address.   This is bits 108
   * through 115.
   */
  portmask = inpacket[circuit_id_p + 13] & 15;

  /* We don't allocate the bottom 4096 ports to any client, and consequently
   * the top /60 doesn't get a port set allocation; if portmask is 16, we
   * have to drop the reply.
   */
  portmask++;
  if (portmask == 16)
    {
      syslog(LOG_INFO, "dropping portset allocation for top /60");
      return 0;
    }
  /* Okay, we have a port range.   We insert two port range options
   * each of which contains a u_int16_t.
   */
  if ((sizeof outpacket) - outp < 2 * (OPHDR_LEN + 2))
    goto noroom;

  /* Store the options. */
  ophdr_store(&outpacket[outp], OPTION_PORT_RANGE_MIN);
  ophdr_store(&outpacket[outp + OPCODE_LEN], 2);
  word(&outpacket[outp + OPHDR_LEN], portmask << 12);
  outp += OPHDR_LEN + 2;
  ophdr_store(&outpacket[outp], OPTION_PORT_RANGE_MAX);
  ophdr_store(&outpacket[outp + OPCODE_LEN], 2);
  word(&outpacket[outp + OPHDR_LEN], (portmask << 12) + 4095);
  outp += OPHDR_LEN + 2;

  /* Destination is Client Relay Agent on port 67, not port 68. */
  memset(&dest, 0, sizeof dest);
  dest.sin6_port = htons(DHCPv4_SERVER_PORT);
  memcpy((char *)&dest.sin6_addr, &inpacket[circuit_id_p], IPV6_ADDR_SIZE);
#ifdef HAVE_SA_LEN
  dest.sin6_len = sizeof server_addr;
#endif
  dest.sin6_family = AF_INET6;

  /* Put in ENDOPTION tag */
  ophdr_store(&outpacket[outp], OPTION_END);
  outp += OPCODE_LEN;

  /* Relay the packet. */
  sendto(sock6fd, outpacket, outp,
	 MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof dest);
  return 0;
}

int
main(int argc, char **argv)
{
  struct pollfd fds[2];
  openlog(argv[0], LOG_PID | LOG_PERROR, LOG_DAEMON);

  if (argc != 4)
    {
    usage:
      fprintf(stderr,
	      "Usage: %s [server-addr] [shim4-addr] [shim6-addr]\n", argv[0]);
      exit(1);
    }
  if (!inet_pton(AF_INET, argv[1], &server_addr))
    {
      fprintf(stderr, "%s: not a valid IPv4 address\n", argv[1]);
      goto usage;
    }
  if (!inet_pton(AF_INET, argv[2], &relay_addr))
    {
      fprintf(stderr, "%s: not a valid IPv4 address\n", argv[2]);
      goto usage;
    }
  if (!inet_pton(AF_INET6, argv[3], &listen_addr))
    {
      fprintf(stderr, "%s: not a valid IPv6 address\n", argv[3]);
      goto usage;
    }
  
  dhcpv6_socket_setup(DHCPv4_SERVER_PORT);
  dhcpv4_socket_setup(DHCPv4_SERVER_PORT);


  fds[0].fd = sock6fd;
  fds[0].events = POLLIN;
  fds[1].fd = sock4fd;
  fds[1].events = POLLIN;
  do {
    int status = poll(fds, 2, -1);
    if (status < 0)
      {
	syslog(LOG_CRIT, "poll: %m");
	exit(1);
      }
    if (fds[0].revents & POLLIN)
      v6_packet();
    if (fds[1].revents & POLLIN)
      v4_packet();
  } while (1);
}
	     
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
