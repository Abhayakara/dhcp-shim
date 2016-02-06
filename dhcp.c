/* dhcp.c
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

#include "shim.h"

void
word(u_int8_t *dest, u_int16_t wod)
{
  dest[0] = wod >> 8;
  dest[1] = wod & 255;
}

/* Generic interface registration routine... */
void
dhcpv6_socket_setup(u_int16_t port)
{
  struct sockaddr_in6 name;
  int flag = 1;
  char addrbuf[128];
  extern int sock6fd;

  /* Set up the address we're going to bind to. */
  memset(&name, 0, sizeof name);
#if defined(HAVE_SA_LEN)
  name.sin6_len = sizeof name;
#endif
  name.sin6_family = AF_INET6;
  name.sin6_port = htons(port);

  if ((sock6fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
    {
      syslog(LOG_CRIT, "Cannot create DHCPv6 socket: %m");
      exit(1);
    }

  /* The RFC requires v6only to be disabled by default, but
   * it's generally enabled by default.   So just to be sure,
   * we need to explicitly enable it.
   */
  flag = 1;

  if (setsockopt(sock6fd, IPPROTO_IPV6, IPV6_V6ONLY,
		 &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to reset IPV6_V6ONLY sockopt: %m");
      exit(1);
    }

  flag = 1;

#if 0
  if (setsockopt(sock6fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		 &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to reset IPV6_RECVPKTINFO sockopt: %m");
      exit(1);
    }
#endif

  flag = 1;
  if (setsockopt(sock6fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set SO_REUSEADDR sockopt: %m");
      exit(1);
    }

  if (bind(sock6fd, (struct sockaddr *)&name, sizeof name) < 0)
    {
      syslog(LOG_CRIT, "Cannot bind to DHCPv6 port: %m");
      exit(1);
    }

  inet_ntop(AF_INET6, &name.sin6_addr, addrbuf, sizeof addrbuf);
  syslog(LOG_INFO, "bound to %s/%d", addrbuf, port);
}

/* IPv4 socket registration. */
void
dhcpv4_socket_setup(u_int16_t port)
{
  struct sockaddr_in name;
  int flag = 1;
  char addrbuf[128];
  extern int sock4fd;

  /* Set up the address we're going to bind to. */
  memset(&name, 0, sizeof name);
#if defined(HAVE_SA_LEN)
  name.sin_len = sizeof name;
#endif
  name.sin_family = AF_INET;
  name.sin_port = htons(port);

  if ((sock4fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
      syslog(LOG_CRIT, "Cannot create DHCPv4 socket: %m");
      exit(1);
    }

  flag = 1;
  if (setsockopt(sock4fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag) < 0)
    {
      syslog(LOG_CRIT, "Unable to set SO_REUSEADDR sockopt: %m");
      exit(1);
    }

  if (bind(sock4fd, (struct sockaddr *)&name, sizeof name) < 0)
    {
      syslog(LOG_CRIT, "Cannot bind to DHCPv6 port: %m");
      exit(1);
    }

  inet_ntop(AF_INET, &name.sin_addr, addrbuf, sizeof addrbuf);
  syslog(LOG_INFO, "bound to %s/%d", addrbuf, port);
}

/* Search the top level of the DHCP message looking for an Interface-Id
 * option, and return the offset in the message of that option, or zero
 * if none is found.   Can also return -1 if packet is malformed.
 */
int
find_option(u_int8_t *inpacket, size_t *inpp, size_t inmax,
	    int sought, int *lp, int deep)
{

  OS_VARS;

  OS_START;
  if (!deep && opcode == sought)
    {
      *lp = oplen;
      return inp + OPHDR_LEN;
    }
#ifdef DHCPv6
  if (deep && opcode == OPTION_RELAY_MSG)
    {
      int rv;
      /* Descend to the inner message. */
      if (inpacket[inp+OPHDR_LEN] == RELAY_REPLY)
	{
	  size_t subinp = inp + OPHDR_LEN + RELAY_HEADER_SIZE;
	  rv = find_option(inpacket, &subinp, inp + oplen + OPHDR_LEN,
			   sought, lp, 1);
	  if (rv)
	    return rv;
	}
      else
	{
	  size_t subinp = inp + OPHDR_LEN + CLIENT_HEADER_SIZE;
	  rv = find_option(inpacket, &subinp, inp + oplen + OPHDR_LEN,
			   sought, lp, 0);
	  if (rv)
	    return rv;
	}
    }
#endif
  inp += oplen + OPHDR_LEN;
  OS_FINISH;

  return 0;
}
 
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
