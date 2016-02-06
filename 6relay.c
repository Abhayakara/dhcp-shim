/* 6relay.c
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

#define __APPLE_USE_RFC_3542 1 /* fnrk */

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

int sock6fd;	/* DHCP socket. */
int sock4fd;	/* Not used. */
int multicast_interface = 0;
time_t log_start_time = 0;
FILE *logfile = NULL;
struct in6_addr server_addr;
struct in6_addr listen_addr;

static char ll_prefix[] = {0xfe, 0x80, 0, 0,  0, 0, 0, 0};


static void one_packet(void);

void
dhcpv6_multicast_relay_join()
{
  struct ipv6_mreq mreq;
  char addrbuf[128];

  /* Join the All_DHCP_Relay_Agents_and_Servers multicast group.
   * This is link-scoped, so it shouldn't fail.
   */
  memset(&mreq, 0, sizeof mreq);
  inet_pton(AF_INET6, "FF02::1:2", &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = multicast_interface;

  if (setsockopt(sock6fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		 (char *)&mreq, sizeof mreq) < 0)
    {
      syslog(LOG_CRIT, "Unable to join All_DHCP_Relay_Agents_and_"
		"Servers multicast group on %d: %m", multicast_interface);
      exit(1);
    }
  else
    {
      inet_ntop(AF_INET6, (char *)&mreq.ipv6mr_multiaddr,
		addrbuf, sizeof addrbuf);
      syslog(LOG_INFO,
	     "Joined %s on interface %d", addrbuf, multicast_interface);
    }
}

/* Called to copy the options in a range from the input buffer to the
 * output buffer.   inpacket: the input buffer; inpp: current position in
 * the input buffer; inmax: the position after the last byte in the input
 * buffer.  outpacket: the output buffer; outpp: current position in the
 * output buffer; outmax: the position after the last available byte in
 * the output buffer.
 *
 * copy_top is nonzero if we are copying the top-level options in
 * the input buffer hunk we've been given to copy.   This will be zero
 * in the case that we're decapsulating a RELAY-REPLY packet, since
 * we want to discard that encapsulation and any options that came with
 * it, but store the encapsulated header and the options in the encapsulated
 * packet.
 *
 * copy_pd is the function called to copy any IA_PD options encountered
 * while copying.
 *
 * thunk is a void pointer that is passed to copy_pd each time it is called.
 */

int
copy_options(u_int8_t *inpacket, size_t *inpp, size_t inmax,
	     u_int8_t *outpacket, size_t *outpp, size_t outmax,
	     int copy_top,
	     int (*copy_pd)(u_int8_t *inpacket, size_t ia_data,
			    size_t *inpp, size_t inmax,
			    u_int8_t *outpacket, size_t *outpp, size_t outmax,
			    u_int32_t *validp, int *triplicate_maskp),
	     u_int32_t *validp, int *triplicate_maskp)
{
  OS_VARS;
  int rv;
  size_t outp = *outpp;
  int submax;

  size_t rmlp;
  int rmhl;
  
  /* OS_START sets up for the loop and begins the loop. */
  OS_START;

  /* We handle relay messages specially. */
  if (opcode == OPTION_RELAY_MSG)
    {
      /* We've already consumed the option header here. */
      inp += OPHDR_LEN;

      /* Only if we are copying top-level options, we copy the option
       * header of this option.
       */
      if (copy_top)
	{
	  /* Room? */
	  if (outmax - outp < OPHDR_LEN)
	    return -1;
	  ophdr_store(&outpacket[outp], OPTION_RELAY_MSG);
	  rmlp = outp + OPCODE_LEN;
	  outp += OPHDR_LEN;
	}
       
     /* Figure out how big the header inside the relay message option is. */
      if (inpacket[inp] == RELAY_REPLY)
	rmhl = RELAY_HEADER_SIZE;
      else
	rmhl = CLIENT_HEADER_SIZE;

      /* Copy it. */
      memcpy(&outpacket[outp], &inpacket[inp], rmhl);
      inp += rmhl;
      outp += rmhl;
	  
      /* The subcopy only gets the contents of the option, not the
       * whole packet.
       */
      submax = inp + oplen - rmhl;
      
      /* Recursively descend into the relay message, copying options.
       * If the copy fails, pass the return code up the chain.
       */
      rv = copy_options(inpacket, &inp, submax, outpacket, &outp, outmax,
			1, copy_pd, validp, triplicate_maskp);
      if (rv < 0)
	return rv;
      
      /* Store the length. */
      if (copy_top)
	ophdr_store(&outpacket[rmlp], rv + rmhl);
      
      /* If we are discarding top-level options, we can stop copying,
       * because there shouldn't be more than one Relay Message option
       * in a relay message.
       */
      else
	goto success;
    }
  else
    {
      /* We've already consumed the option header here. */
      inp += OPHDR_LEN;

      if (copy_top)
	{
	  /* No space? */
	  if (outmax - outp < oplen + OPHDR_LEN)
	    return -1;
	  /* Stash the option header. */
	  ophdr_store(&outpacket[outp], opcode);
	  ophdr_store(&outpacket[outp + OPCODE_LEN], oplen);
	  /* Copy the payload. */
	  memcpy(&outpacket[outp + OPHDR_LEN], &inpacket[inp], oplen);
	  outp += oplen + OPHDR_LEN;
	}
      inp += oplen;
    }

  OS_FINISH;

 success:
  /* Return value is the number of bytes copied. */
  rv = outp - *outpp;

  /* Update the caller's version of the input buffer and output buffer
   * pointers.
   */
  *inpp = inp;
  *outpp = outp;
  return rv;

}

static void
one_packet(void)
{
  u_int8_t inpacket[MAX_PACKET_SIZE];
  u_int8_t outpacket[MAX_PACKET_SIZE];
  size_t inp;
  size_t outp;
  size_t rmlp;
  u_int16_t rml;

  int result;
  struct sockaddr_in6 from;
  socklen_t fromlen = sizeof from;
  struct sockaddr_in6 dest;
  char buf[100];

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
	return;

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
      return;
    }

  /* This is a packet from the client to the server. */
  if (inpacket[0] == SOLICIT ||
      inpacket[0] == REQUEST ||
      inpacket[0] == CONFIRM ||
      inpacket[0] == RENEW ||
      inpacket[0] == REBIND ||
      inpacket[0] == RELEASE ||
      inpacket[0] == DECLINE ||
      inpacket[0] == RELAY_FORWARD)
    {
      /* Set up and copy encapsulation header into packet. */
      outpacket[0] = RELAY_FORWARD;	/* type */

      /* If this is a RELAY_FORWARD packet, we put the address from which we
       * received the packet in the peer address field, and the copy the link
       * address field from the RELAY_FORWARD.
       */
      if (inpacket[0] == RELAY_FORWARD)
	{
	  /* Malformed packet. */
	  if (result < RELAY_HEADER_SIZE)
	    return;

	  /* Hop count exceeded?   This should never ever happen, so we can
	   * log it.   Most likely reason for it to happen is that the shim
	   * has been misconfigured.
	   */
	  if (inpacket[1] == 255)
	    {
	      inet_ntop(AF_INET6, &from.sin6_addr, buf, sizeof buf);
	      syslog(LOG_INFO, "hop count exceeded from %s", buf);
	      return;
	    }

	  outpacket[1] = inpacket[1] + 1;	/* hop count */

	  /* If the source address is a link-local address, copy in our own
	   * global address; otherwise set the address to zero.
	   */
	  if (!memcmp(&inpacket[2], ll_prefix, 8))
	    memcpy(&outpacket[2], (u_int8_t *)&listen_addr, IPV6_ADDR_SIZE);
	  else
	    memset(&outpacket[2], 0, IPV6_ADDR_SIZE);
	  memcpy(&outpacket[2 + IPV6_ADDR_SIZE],
		 &from.sin6_addr, IPV6_ADDR_SIZE);
	  inp = RELAY_HEADER_SIZE;
	  outp = RELAY_HEADER_SIZE;
	}
      else
	{
	  outpacket[1] = 0;			/* hop count */

	  memcpy(&outpacket[2], (u_int8_t *)&listen_addr, IPV6_ADDR_SIZE);
	  memcpy(&outpacket[2 + IPV6_ADDR_SIZE],
		 &from.sin6_addr, sizeof from.sin6_addr);
	  inp = CLIENT_HEADER_SIZE;
	  outp = RELAY_HEADER_SIZE;
	}
      /* The Relay Message option header goes here, but we don't know how
       * long the relay message option is yet, so we save an index to the
       * relay message length, and remember the length of the input header,
       * so that we can store the right value later.
       */
      ophdr_store(&outpacket[outp], OPTION_RELAY_MSG);
      rmlp = outp + 2;
      rml = inp;
      outp += 4;

      /* Copy in the encapsulated header. */
      memcpy(&outpacket[outp], inpacket, inp);
      outp += inp;

      /* Do recursive descent copy, dropping extra IA_PDs. */
      result = copy_options(inpacket, &inp, result,
			    outpacket, &outp, sizeof outpacket,
			    1, 0, 0, 0);

      /* If the packet was malformed, drop it. */
      if (result < 0)
	return;

      /* Store the Relay Message length, which we now know. */
      ophdr_store(&outpacket[rmlp], rml + result);

      /* Store an interface-id option. */
      ophdr_store(&outpacket[outp], OPTION_INTERFACE_ID);
      ophdr_store(&outpacket[outp + 2], 2);
      outpacket[outp + 4] = from.sin6_scope_id;
      outpacket[outp + 5] = 0;
      outp += 6;

      /* Send packet to server. */
      memset(&dest, 0, sizeof dest);
      memcpy(&dest.sin6_addr, &server_addr, IPV6_ADDR_SIZE);
      dest.sin6_port = htons(DHCPV6_SERVER_PORT);
      dest.sin6_family = AF_INET6;
    }

  /* This is a packet from the server to the client.   All packets
   * from server to client should be encapsulated, because we encapsulated
   * the packet we forwarded.
   */
  else if (inpacket[0] == RELAY_REPLY)
    {
      int ifidp;
      int ifid;
      int ifidl;

      /* Get the destination address from the relay reply. */
      memset(&dest, 0, sizeof dest);
      memcpy(&dest.sin6_addr,
	     &inpacket[2 + IPV6_ADDR_SIZE], sizeof dest.sin6_addr);
      
      /* Skip over the relay reply header. */
      inp = RELAY_HEADER_SIZE;
      outp = 0;

      /* Find the interface ID option, which the server should have
       * returned.
       */
      ifidp = find_option(inpacket, &inp, result,
			  OPTION_INTERFACE_ID, &ifidl, 0);
      if (!ifidp)
	{
	  syslog(LOG_CRIT, "DHCP server did not return interface-id!\n");
	  return;
	}
      if (ifidl != 2)
	{
	  syslog(LOG_CRIT,
		 "DHCP server returned wrong length interface id: %d\n",
		 ifidl);
	  return;
	}
      ifid = inpacket[ifidp];

      /* Recursively descend into the packet.   Skip all the top-level
       * options, because these are relay options the server sent to us,
       * and we don't process relay options.   Upon recursing into the
       * relay message option, we will start copying.   We pass in the
       * triplicate_pd function for copying any IA_PD we encounter, because
       * it will copy it three times, once intact, once modified for VoIP,
       * and once modified for IPTV.   It will also store the valid lifetime
       * through the pointer we pass to expiry.
       */
      if (copy_options(inpacket, &inp, result,
		       outpacket, &outp, sizeof outpacket,
		       0, 0, 0, 0) < 0)
	{
	  return;
	}

      /* If the packet is a RELAY-REPLY, set the destination port to the
       * server port; otherwise to the client port.
       */
      if (outpacket[0] == RELAY_REPLY)
	dest.sin6_port = htons(DHCPV6_SERVER_PORT);
      else
	dest.sin6_port = htons(DHCPV6_CLIENT_PORT);

      /* Use the scope on which we received the packet (which we got back
       * in the interface id option.
       */
      dest.sin6_scope_id = ifid;
      dest.sin6_family = AF_INET6;
    }
  else
    {
      inet_ntop(AF_INET6, &from.sin6_addr, buf, sizeof buf);
      syslog(LOG_INFO, "Discarding packet of type %d from %s",
	     inpacket[0], buf);
      return;
    }

  /* Relay the packet. */
  sendto(sock6fd, outpacket, outp,
	 MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof dest);
}

int
main(int argc, char **argv)
{
  openlog(argv[0], LOG_PID | LOG_PERROR, LOG_DAEMON);

  if (argc != 3)
    {
    usage:
      fprintf(stderr, "Usage: %s [server-addr] [shim-addr]\n", argv[0]);
      exit(1);
    }
  if (!inet_pton(AF_INET6, argv[1], &server_addr))
    {
      fprintf(stderr, "%s: not a valid IPv6 address\n", argv[1]);
      goto usage;
    }
  if (!inet_pton(AF_INET6, argv[2], &listen_addr))
    {
      fprintf(stderr, "%s: not a valid IPv6 address\n", argv[2]);
      goto usage;
    }
  
  dhcpv6_socket_setup(DHCPV6_CLIENT_PORT);

  dhcpv6_multicast_relay_join();
  
  do {
    one_packet();
  } while (1);
}
	     
/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
