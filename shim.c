/* shim.c
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

#define __APPLE_USE_RFC_3542 1 /* bogus */
#define _GNU_SOURCE 1 /* also bogus. */

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
//#include <netpacket/packet.h>
#include <pcap/pcap.h>

#include "shim.h"

int sock6fd;	/* DHCP socket. */
int sock4fd;	/* Not used. */
int local_port_dhcpv6 = DHCPV6_SERVER_PORT;
int multicast_interface = 0;
time_t log_start_time = 0;
FILE *logfile = NULL;

int sss_bit_start = 35;
bool best_effort_na = false;
bool do_fake_pdx = false;

struct in6_addr server_addr;
struct in6_addr listen_addr;
struct in6_addr privacy_addr;

static void one_packet(ssize_t (*sendto_func)(int fd,
					      const void *buf, size_t buflen,
					      int flags,
					      const struct sockaddr *dest,
					      socklen_t destlen));

int setbit(void *array, unsigned int array_len_in_bytes,
           unsigned int bitnum);
int clearbit(void *array, unsigned int array_len_in_bytes,
             unsigned int bitnum);
int assign_bit(void *array, unsigned int array_len_in_bytes,
               unsigned int bitnum, unsigned int value);
int set_sss_bits(unsigned char *addr,
		 unsigned int offset, unsigned int value);

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

static char iptv_iaid[] = {'I', 'P', 'T', 'V'};
static char voip_iaid[] = {'V', 'O', 'I', 'P'};
static char ll_prefix[] = {0xfe, 0x80, 0, 0,  0, 0, 0, 0};

static bool
looking_for_ia(dhcp_opcode_t opcode)
{
  if (opcode == OPTION_IA_NA || opcode == OPTION_IA_PD)
    return true;
  return false;
}

static bool
looking_for_addr(dhcp_opcode_t opcode)
{
  if (opcode == OPTION_IAPREFIX || opcode == OPTION_IAADDR)
    return true;
  return false;
}

static int
iaprefix_copy(dhcp_opcode_t opcode,
	      u_int8_t *inpacket, size_t *inpp, size_t inmax,
	      u_int8_t *outpacket, size_t *outpp, size_t outmax,
	      u_int32_t *validp, copy_option_closure_t *cos)
{
  size_t inp = *inpp;
  size_t outp = *outpp;
  size_t oplen = inmax - inp;

  memcpy(&outpacket[outp], &inpacket[inp - 4], oplen + OPHDR_LEN);
  *outpp = outp + oplen + OPHDR_LEN;
  *inpp = inmax;

  // In order to support dual /57s (rather than blocking the top /64),
  // limit the prefix length to a maximum of 63.  Remember that we did
  // this, so that if we aren't doing PDX, we can lengthen the prefix
  // by 1 on the way back.

  // Also, if we are asked for a prefix longer than 56 and we aren't
  // going to do PD_EXCLUDE, shorten the requested prefix length by
  // one.  This allows us to return a /60 when a /60 is requested, in
  // the case where there are plenty of prefixes available but the
  // server happens to allocate a prefix that contains the topmost
  // /64.
  if (outpacket[outp + OPHDR_LEN + 8] > 63 ||
      (outpacket[outp + OPHDR_LEN + 8] > 56 && !(cos->triplicate_mask &
						 MASK_PD_EXCLUDE)))
    {
      if (outpacket[outp + OPHDR_LEN + 8] > 63)
	{
	  cos->pd_preflen = 64;
	  outpacket[outp + OPHDR_LEN + 8] = 63;
	}
      else
	{
	  cos->pd_preflen = outpacket[outp + OPHDR_LEN + 8];
	  outpacket[outp + OPHDR_LEN + 8]--;
	}
      cos->triplicate_mask |= MASK_PREFIX_WIDENED;
    }
  else
    cos->pd_preflen = outpacket[outp + OPHDR_LEN + 8];

  // If we are doing the best effort prefix using the IA_NA hack, then
  // the prefix we get here isn't going to be the best effort prefix.
  // But we want the server to allocate the prefix from the best effort
  // network, because that's the template.  So force the SSS bits to 001
  // on the way to the server, regardless of what came from the client.
  set_sss_bits(&outpacket[outp + OPHDR_LEN + 9], sss_bit_start, 1);

  return *outpp - outp;
}

/* This is called by copy_options during the copying of the suboptions
 * of an IA_PD option that we are converting to an IA_NA option.  It
 * is called when an IAPREFIX suboption is encountered.  It converts
 * the IAPREFIX suboption to an IAADDR suboption, and fakes an IPv6
 * address by taking the bottom 13 bits of the /60 prefix and putting
 * them in the bottom 13 bits of the address, and masking the bits as
 * they were in the prefix to zero.  The other prefix bits are assumed
 * to be correct.
 */

static int
iaprefix_to_iaaddr(dhcp_opcode_t opcode,
		   u_int8_t *inpacket, size_t *inpp, size_t inmax,
		   u_int8_t *outpacket, size_t *outpp, size_t outmax,
		   u_int32_t *validp, copy_option_closure_t *cos)
{
  size_t inp = *inpp;
  size_t outp = *outpp;
  u_int32_t addrbits;

  // oplen will be the length of the suboptions
  int oplen = inmax - inp;

  // Make sure we actually got the fixed part of the option!
  if (oplen < IAPREFIX_FIXED_LEN)
    return -1;

  /* We've already consumed the option header here. */
//  inp += OPHDR_LEN;

  /* No space? */
  if (outmax - outp < oplen + OPHDR_LEN - 1)
    return -1;

  /* Stash the option header. */
  ophdr_store(&outpacket[outp], OPTION_IAADDR);
  ophdr_store(&outpacket[outp + OPCODE_LEN], oplen - 1);
  outp += OPHDR_LEN;

  // Remember the requested prefix length
  cos->na_preflen = inpacket[inp + 8];
  if (cos->na_preflen < 60)
    cos->na_preflen = 60;

  // Copy the prefix, but clear the bottom 17 bits of the /60.
  memcpy(&outpacket[outp], &inpacket[inp + 9], 5);
  memset(&outpacket[outp + 6], 0, 8);
  outpacket[outp + 5] = inpacket[inp + 9 + 5] & 224;

  // The lower 17 bits of the /60 prefix are the lower 17 bits of the address:
  addrbits = (((inpacket[inp + 9 + 5] & 31) << 12) |
	      (inpacket[inp + 9 + 6] << 4) |
	      ((inpacket[inp + 9 + 7] & 240) >> 4));

  // Store the address bits in the host address.
  outpacket[outp + 8 + 5] = addrbits >> 16;
  outpacket[outp + 8 + 6] = (addrbits >> 8 & 255);
  outpacket[outp + 8 + 7] = addrbits & 255;

  // Copy the suboptions (if any) to the output.
  outp += 16;

  /* Copy the preferred and valid lifetimes. */
  memcpy(&outpacket[outp], &inpacket[inp], 8);
  outp += 8;

  if (oplen > IAPREFIX_FIXED_LEN)
    memcpy(&outpacket[outp], &inpacket[inp], oplen - IAPREFIX_FIXED_LEN);
  outp += oplen - IAPREFIX_FIXED_LEN;
  inp += oplen;
  *outpp = outp;
  *inpp = inp;
  return oplen + OPHDR_LEN - 1;
}

/* Called by copy_options when an IA_PD option is encountered in a message
 * going to the DHCP server.   We arrange to keep a single IA_PD that will
 * actually be sent to the DHCP server.   If we are turning the best effort
 * request into an IA_NA request, we copy the first of the other two prefixes
 * that we see; otherwise we copy the best effort prefix.   If we copy one
 * of the two non-best-effort prefixes, we change the iaid to 'xxxx' because
 * we can't count on it being set the same on every query.
 */
static int
elide_pds(dhcp_opcode_t opcode,
	  u_int8_t *inpacket, size_t *inpp, size_t inmax,
	  u_int8_t *outpacket, size_t *outpp, size_t outmax,
	  u_int32_t *validp, copy_option_closure_t *cos)
{
  size_t outp = *outpp;
  int oplen;
  int this_one;
  size_t ia_data = *inpp;
  oplen = inmax - ia_data;

  // Options start twelve bytes into the IA_NA or IA_PD payload
  *inpp += 12;

  /* If we see an IA_NA here, we drop it, because we don't actually
   * support IA_NAs from the CPE: we are using them for something else.
   */
  if (opcode == OPTION_IA_NA)
    {
      *inpp = inmax;
      return 0;
    }

  /* If this is an IPTP or VoIP IA_ID, and we are not doing privacy, or
   * we've already copied one IA_ID, skip it.
   */
  if (!memcmp(&inpacket[ia_data], iptv_iaid, 4))
    {
      this_one = MASK_IPTV;
    elide:
      if ((cos->triplicate_mask & MASK_PRIVACY) &&
	  ((cos->triplicate_mask & MASK_COLORS) == 0 ||
	   (cos->triplicate_mask & MASK_COLORS) == MASK_BEST_EFFORT))
	goto keep;
      cos->triplicate_mask |= this_one;
      *inpp = inmax;
      return 0;
    }
  else if (!memcmp(&inpacket[ia_data], voip_iaid, 4))
    {
      this_one = MASK_VOIP;
      goto elide;
    }
  this_one = MASK_BEST_EFFORT;
 keep:
  cos->triplicate_mask |= this_one;

  /* Make sure there's space in the output packet. */
  if (outmax - outp < OPHDR_LEN + oplen)
    return -1;

  // Make sure this is a valid IA_PD.
  if (OPHDR_LEN + oplen < IAPD_HDR_LEN)
    return -1;

  /* Copy the IA_PD we are keeping, or if it's the best effort prefix and
   * we are turning it into an IA_NA, do that.
   */
  if (this_one == MASK_BEST_EFFORT && (cos->triplicate_mask & MASK_PRIVACY))
    {
      int poplen, suboplen;
      time_t now;

      /* Write out a header. */
      ophdr_store(&outpacket[outp], OPTION_IA_NA);
      poplen = outp + OPCODE_LEN;

      // Remember the IAID that we got here
      memcpy(cos->best_effort_iaid, &inpacket[ia_data], 4);

      // Figure out the current time for the privacy IAID.
      time(&now);
      now /= (3600 * 24);
      now = now & 3;
      // Now is now a number between 0 and 3, which will change once every day.

      // Copy the fixed portion of the IA option.
      memcpy(&outpacket[outp + OPHDR_LEN], &inpacket[ia_data], 12);

      // Set the bottom two bits to the time discriminator.
      outpacket[outp + OPHDR_LEN + 3] =
	(outpacket[outp + OPHDR_LEN + 3] & ~3) | now;
      outp += 12 + OPHDR_LEN;

      *outpp = outp;

      /* If the IA_PD encloses any options, copy them. */
      if (OPHDR_LEN + oplen > IAPD_HDR_LEN)
	{
	  suboplen = copy_options(inpacket, inpp, inmax,
				  outpacket, outpp, outmax,
				  1, looking_for_addr,
				  iaprefix_to_iaaddr, validp, cos);
	  // If there was an error, stop now.
	  if (suboplen < 0)
	    return suboplen;
	}
      else
	suboplen = 0;

      // Now that we've copied the options, we know and can store the length.
      ophdr_store(&outpacket[poplen], suboplen + 12);
      return OPHDR_LEN + 12 + suboplen;
    }
  else
    {
      // If we're doing it the old way, get the best
      // effort iaid here.
      if (this_one == MASK_BEST_EFFORT)
	memcpy(cos->best_effort_iaid, &inpacket[ia_data], 4);
      ophdr_store(&outpacket[outp], OPTION_IA_PD);
      ophdr_store(&outpacket[outp + OPCODE_LEN], oplen);
      memcpy(&outpacket[outp + OPHDR_LEN], &inpacket[ia_data], 12);
      outp += 12 + OPHDR_LEN;
      *outpp = outp;

      if (OPHDR_LEN + oplen > IAPD_HDR_LEN)
	{
	  int rv = copy_options(inpacket, inpp, inmax,
				outpacket, outpp, outmax, 1,
				looking_for_addr, iaprefix_copy, validp, cos);
	  if (rv < 0)
	    return rv;

	  // The encapsulated options should have exactly filled the
	  // remaining space.
	  if (rv != oplen + OPHDR_LEN - IAPD_HDR_LEN)
	    return -1;
	}
      return OPHDR_LEN + oplen;
    }
}

static int
copy_ia(u_int8_t *inpacket, size_t *inpp, size_t inmax,
	u_int8_t *outpacket, size_t *outpp, size_t outmax,
	copy_option_closure_t *cos,
	int (*copy_sought)(dhcp_opcode_t opcode,
			   u_int8_t *inpacket, size_t *inpp, size_t inmax,
			   u_int8_t *outpacket, size_t *outpp,
			   size_t outmax,
			   u_int32_t *validp, copy_option_closure_t *cos))
{
  size_t outp = *outpp;
  size_t inp = *inpp;
  size_t poplen;
  int oplen, suboplen;
  oplen = inmax - inp;

  /* Make sure there's space in the output packet. */
  if (outmax - outp < OPHDR_LEN + oplen)
    return -1;

  /* Write out a header. */
  ophdr_store(&outpacket[outp], OPTION_IA_PD);
  poplen = outp + OPCODE_LEN;
  ophdr_store(&outpacket[poplen], 0xFACE); /* XXX debugging aid */
  
  /* Copy in the correct IAID .*/
  if (cos->ia_mask == MASK_BEST_EFFORT)
    memcpy(&outpacket[outp + OPHDR_LEN], cos->best_effort_iaid, 4);
  else if (cos->ia_mask == MASK_IPTV)
    memcpy(&outpacket[outp + OPHDR_LEN], iptv_iaid, 4);
  else if (cos->ia_mask == MASK_VOIP)
    memcpy(&outpacket[outp + OPHDR_LEN], voip_iaid, 4);
  else
    return -1;

  memcpy(&outpacket[outp + OPHDR_LEN + 4], &inpacket[inp + 4], 8);
  outp += 12 + OPHDR_LEN;
  inp += 12;
  *outpp = outp;
  *inpp = inp;

  // Copy out the suboptions, transmogrifying the iaaddrs to iaprefixes.
  // (should really only be one iaaddr)
  suboplen = copy_options(inpacket, inpp, inmax,
			  outpacket, outpp, outmax,
			  1, looking_for_addr, copy_sought, 0, cos);
  
  // If there was an error, stop now.
  if (suboplen < 0)
    return suboplen;

  // Store the new length.
  ophdr_store(&outpacket[poplen], suboplen + 12);

  return suboplen + 12;
}

/* This is used by triplicate_pd as the sought option copier given to
 * copy_options when copying the suboptions of an IA_PD option.  It is
 * called when an IAPREFIX suboption is encountered.  It copies the
 * IAPREFIX suboption, but tweaks the IAID and the prefix bits according
 * to cos->ia_mask, which indicates whether a best effort, IPTV or VOIP
 * prefix is required.  The template prefix (the option we received from
 * the DHCP server) is always a best effort prefix, even if we are
 * doing privacy and hence not returning the actual prefix the DHCP
 * server allocated.
 */
static int
iaprefix_tweak(dhcp_opcode_t opcode,
	       u_int8_t *inpacket, size_t *inpp, size_t inmax,
	       u_int8_t *outpacket, size_t *outpp, size_t outmax,
	       u_int32_t *validp, copy_option_closure_t *cos)
{
  size_t inp = *inpp;
  size_t outp = *outpp;
  int oplen = inmax - inp;
  int ubits = 0;
  int prefbits = 0;
  int preflen = 0;

  // Make sure the fixed part of the option is present.
  if (oplen < IAPREFIX_FIXED_LEN)
    return -1;

  /* No space? */
  if (outmax - outp < oplen + OPHDR_LEN)
    return -1;

  /* Stash the option header. */
  ophdr_store(&outpacket[outp], opcode);
  ophdr_store(&outpacket[outp + OPCODE_LEN], oplen);

  /* Copy the payload. */
  memcpy(&outpacket[outp + OPHDR_LEN], &inpacket[inp], oplen);

  // Special case: if we widened the prefix on the way out,
  // and we got back the whole wide prefix, chop it.
  if ((cos->triplicate_mask & MASK_PREFIX_WIDENED) &&
      cos->pd_preflen > outpacket[outp + OPHDR_LEN + 8])
    {
      // outpacket[outp + OPHDR_LEN + 8] = 64;
      outpacket[outp + OPHDR_LEN + 8] = cos->pd_preflen;
    }
  else
    {
      // Compute the u bits for the top /64 in this prefix
      preflen = outpacket[outp + OPHDR_LEN + 8];
      ubits = outpacket[outp + OPHDR_LEN + 9 + 7];

      // This should never happen, but if it does (i.e., the DHCP server
      // is misconfigured), fail.
      if (preflen > 63)
	return -1;

      // This should never happen either, but if it does, we can
      // still do the math.
      if (preflen < 56)
	preflen = 56;

      // The quantity or'd in is all the u bits in the prefix set to 1.
      prefbits = ((1 << (64 - preflen)) - 1);

      // If this prefix includes the all ones /64, and we aren't going to
      // send a PD_EXCLUDE, lengthen the prefix by one.
      if ((prefbits | ubits) == 255 &&
	  (!(cos->triplicate_mask & MASK_PD_EXCLUDE) || preflen == 63))
	{
	  outpacket[outp + OPHDR_LEN + 8]++;
	}
    }

  /* Copy out the valid lifetime. */
  if (validp && cos->ia_mask == MASK_BEST_EFFORT &&
      !(cos->triplicate_mask & MASK_PRIVACY))
    {
      u_int32_t valid = (outpacket[outp + OPHDR_LEN + 4] << 24 |
			 outpacket[outp + OPHDR_LEN + 5] << 16 |
			 outpacket[outp + OPHDR_LEN + 6] << 8 |
			 outpacket[outp + OPHDR_LEN + 7]);
      *validp = valid;
    }

  /* If it's an IA_PREFIX, we need to hack in the service type bits:
   * bits 26, 27 and 28.   Fourth byte of prefix is bits 24-32.
   * (Note: service type bits may be in a different location, as
   * indicated by the --sss-start command-line option.
   */
  if (opcode == OPTION_IAPREFIX)
    {
      if (cos->ia_mask != MASK_BEST_EFFORT)
	{
	  unsigned char *address = &outpacket[outp + OPHDR_LEN + 9];
	  
	  /* clear the 'PIE' bits. */
	  clearbit(address, IPV6_ADDR_SIZE, sss_bit_start - 5);
	  clearbit(address, IPV6_ADDR_SIZE, sss_bit_start - 4);
	  clearbit(address, IPV6_ADDR_SIZE, sss_bit_start - 3);

	  /* IPTV SSS bit string == 0x4 */
	  if (cos->ia_mask == MASK_IPTV)
	    set_sss_bits(address, sss_bit_start, 0x4);
	  
	  /* VoIP SSS bit string == 0x6 */
	  else
	    set_sss_bits(address, sss_bit_start, 0x6);
	}
      else
	{
	  memcpy(cos->b4_addr, &inpacket[inp + 9], IPV6_ADDR_SIZE / 2);
	  memset(&cos->b4_addr[8], 0, IPV6_ADDR_SIZE / 2);
	  cos->b4_addr[13] = (cos->b4_addr[7] & 0xf0) >> 4; // [G]
	  cos->b4_addr[7] = 0xFF;	// top /64
	  cos->b4_addr[15] = 0xB4;
	}
    }
  outp += OPHDR_LEN + oplen;
  inp += oplen;

  // If the prefix contains the top /64, all the ubits will be 1, and
  // in this case we have to lengthen the prefix to exclude the top
  // prefix, or (preferably) send the PD_EXCLUDE option.
  if ((prefbits | ubits) == 255 && preflen != 63)
    {
      // If a PD_EXCLUDE option was requested, exclude the top
      // prefix.
      if (cos->triplicate_mask & MASK_PD_EXCLUDE)
	{
	  ophdr_store(&outpacket[outp], OPTION_PD_EXCLUDE);
	  ophdr_store(&outpacket[outp + OPCODE_LEN], 2);
	  outpacket[outp + OPHDR_LEN] = 64 - preflen;
	  outpacket[outp + OPHDR_LEN + 1] = prefbits << (preflen - 56);
	}
    }

  *outpp = outp;
  *inpp = inp;
  return 12 + oplen + OPHDR_LEN;
}

/* This is called by copy_options during the copying of the suboptions
 * of an IA_NA option.  It is called when an IAADDR suboption is
 * encountered.  It converts the IAADDR suboption to an IAPREFIX
 * suboption, sets the IAID to best effort, and generates the prefix
 * bits by shifting the lower bits of the address up into the prefix
 * and setting the best effort prefix bits.  The other prefix bits are
 * assumed to be correct.
 */

static int
iaaddr_to_iaprefix(dhcp_opcode_t opcode,
		   u_int8_t *inpacket, size_t *inpp, size_t inmax,
		   u_int8_t *outpacket, size_t *outpp, size_t outmax,
		   u_int32_t *validp, copy_option_closure_t *cos)
{
  size_t inp = *inpp;
  size_t outp = *outpp;
  u_int32_t addrbits;

  // oplen will be the length of the suboptions plus the fixed header
  int oplen = inmax - inp;

  // Make sure we actually got the fixed part of the option!
  if (oplen < IAADDR_FIXED_LEN)
    return -1;

  /* We've already consumed the option header here. */
//  inp += OPHDR_LEN;

  /* No space? */
  if (outmax - outp < oplen + OPHDR_LEN + 1)
    return -1;

  /* Stash the option header. */
  ophdr_store(&outpacket[outp], OPTION_IAPREFIX);
  ophdr_store(&outpacket[outp + OPCODE_LEN], oplen + 1);
  outp += OPHDR_LEN;

  /* Copy the preferred and valid lifetimes. */
  memcpy(&outpacket[outp], &inpacket[inp + 16], 8);
  outp += 8;

  /* Set the prefix length to 60. XXX */
  outpacket[outp] = 60;
  outp++;

  /* Copy the prefix, less the bottom 16 bits. */
  memcpy(&outpacket[outp], &inpacket[inp], 6);
  // Set the host part of the prefix to zero.
  memset(&outpacket[outp + 8], 0, 8);
  // The lower 17 bits of the address are the varying 17 bits of the prefix:
  addrbits = (((inpacket[inp + 13] & 1) << 16) |
	      (inpacket[inp + 14] << 8) |
	      inpacket[inp + 15]);
  // The prefix is always a /60 for synthesized varying address prefixes.
  // This means that the bottom four bits are zero, and the varying
  // 17 bits go above that; four stolen out of the user portion of the
  // Terastream prefix, and the other 13 in the usual place.
  outpacket[outp + 7] = ((addrbits & 15) << 4);  // bottom four bits
  outpacket[outp + 6] = ((addrbits >> 4) & 255); // middle eight bits
  outpacket[outp + 5] = ((outpacket[outp + 5] & 224) |
			 ((addrbits >> 12) & 31)); // top five bits
  /* Copy out the valid lifetime. */
  if (validp)
    {
      u_int32_t valid = (inpacket[inp + 16] << 24 | inpacket[inp + 17] << 16 |
			 inpacket[inp + 18] << 8 | inpacket[inp + 19]);
      *validp = valid;
    }

  // Copy the suboptions (if any) to the output.
  outp += 16;
  if (oplen > IAADDR_FIXED_LEN)
    memcpy(&outpacket[outp], &inpacket[inp], oplen - IAADDR_FIXED_LEN);
  outp += oplen - IAADDR_FIXED_LEN;
  inp += oplen;
  *outpp = outp;
  *inpp = inp;
  return oplen + 1;
}

/* Called by copy_options when an IA_PD or IA_NA option is encountered
 * in a message coming from the DHCP server.  When the option is an
 * IA_PD, the assumption is that it contains the assigned best effort
 * prefix; the option is copied into the output packet verbatim, and
 * then copied twice more with the prefix modified to contain first
 * the VoIP control bits, and then the IPTV control bits.
 *
 * If the MASK_PRIVACY bit is set, however, we do not copy the best effort
 * prefix from the IA_PD; in this case, we are expecting an IA_NA for the
 * best effort prefix.   So in this case, when we see the IA_NA, we
 * check to see if it 
 *
 * XXX In addition, the user class option is modified?
 */
static int
triplicate_pd(dhcp_opcode_t opcode,
	      u_int8_t *inpacket, size_t *inpp, size_t inmax,
	      u_int8_t *outpacket, size_t *outpp, size_t outmax,
	      u_int32_t *validp, copy_option_closure_t *cos)
{
  int suboplen;
  size_t outp = *outpp;
  int rv;
  size_t inp, inpbase;

  // Options start twelve bytes into the IA_NA or IA_PD payload
  if (inmax - *inpp < 12)
    return -1;
  inpbase = *inpp;

  /* If this is an IA_NA, and we are doing privacy, and we are doing the
   * best effort prefix (which we probably always are), transmogrify
   * the IA_NA into an IA_PD and do the appropriate bit shifting to make
   * the IAADDR into an IAPREFIX.
   */
  if (opcode == OPTION_IA_NA &&
      (cos->triplicate_mask & MASK_PRIVACY) &&
      (cos->triplicate_mask & MASK_BEST_EFFORT))
    {
      cos->ia_mask = MASK_BEST_EFFORT;
      suboplen = copy_ia(inpacket, inpp, inmax, outpacket, outpp, outmax,
			 cos, iaaddr_to_iaprefix);
      if (suboplen < 0)
	return suboplen;
      rv = suboplen;
    }
  /* Otherwise, we are doing the usual IA_PD, which may need to be
   * copied out more than once.
   */
  else if (opcode == OPTION_IA_PD)
    {
      // We copy the IA_PD up to three times
      rv = 0;

      if (!(cos->triplicate_mask & MASK_PRIVACY) &&
	  (cos->triplicate_mask & MASK_BEST_EFFORT))
	{
	  // Copy in the best effort prefix.
	  inp = inpbase;
	  cos->ia_mask = MASK_BEST_EFFORT;
	  suboplen = copy_ia(inpacket, &inp, inmax,
			     outpacket, outpp, outmax, cos, iaprefix_tweak);
	  if (suboplen < 0)
	    return suboplen;
	  rv += suboplen;
	  *inpp = inp;
	}

      if ((cos->triplicate_mask & MASK_IPTV))
	{
	  // copy in the IPTV prefix
	  inp = inpbase;
	  cos->ia_mask = MASK_IPTV;
	  suboplen = copy_ia(inpacket, &inp, inmax,
			     outpacket, outpp, outmax, cos, iaprefix_tweak);
	  if (suboplen < 0)
	    return suboplen;
	  rv += suboplen;
	}
      if ((cos->triplicate_mask & MASK_VOIP))
	{
	  // copy in the VOIP prefix
	  inp = inpbase;
	  cos->ia_mask = MASK_VOIP;
	  suboplen = copy_ia(inpacket, &inp, inmax,
			     outpacket, outpp, outmax, cos, iaprefix_tweak);
	  if (suboplen < 0)
	    return suboplen;
	  rv += suboplen;
	}

      // This accounts for the case where for some reason
      // triplicate_mask is null.  This can only happen as the result
      // of serious brokenness which may be impossible, but it's easy
      // to check, and easy to fail on, so we do so.
      if (rv == 0)
	return -1;

    }

  // Send the B4 address option if requested.
  if ((cos->triplicate_mask & MASK_B4) &&
      opcode == OPTION_IA_PD &&
      outmax - *outpp >= IPV6_ADDR_SIZE + OPHDR_LEN)
    {
      ophdr_store(&outpacket[*outpp], OPTION_IA_B4);
      ophdr_store(&outpacket[*outpp + OPCODE_LEN], IPV6_ADDR_SIZE);
      memcpy(&outpacket[*outpp + OPHDR_LEN], cos->b4_addr, IPV6_ADDR_SIZE);
      *outpp += OPHDR_LEN + IPV6_ADDR_SIZE;
    }

  /* Update the caller's version of the input buffer and output buffer
   * pointers.
   */
  *inpp = inmax;
  rv = *outpp - outp;
  return rv;
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
 * looking_for is the predicate that decides whether the option we
 * are looking at is one we are looking for; this either matches IA_PDs
 * and IA_NAs or matches IAPREFIX/IAADDR.
 *
 * copy_sought is the function called to copy any option matched by
 * looking_for.
 *
 * thunk is a void pointer that is passed to copy_pd each time it is called.
 */

int
copy_options(u_int8_t *inpacket, size_t *inpp, size_t inmax,
	     u_int8_t *outpacket, size_t *outpp, size_t outmax,
	     int copy_top, bool (*looking_for)(dhcp_opcode_t opcode),
	     int (*copy_sought)(dhcp_opcode_t opcode,
				u_int8_t *inpacket, size_t *inpp,
				size_t inmax,
				u_int8_t *outpacket, size_t *outpp,
				size_t outmax,
				u_int32_t *validp, copy_option_closure_t *cos),
	     u_int32_t *validp, copy_option_closure_t *cos)
{
  OS_VARS;
  int rv;
  size_t outp = *outpp;
  int submax;

  size_t rmlp;
  int rmhl;
  

  inp = *inpp;                                  
                                               
  while (inmax - inp >= OPHDR_LEN)                                      
    {                                                                   
      /* Decode the option code and option length. */                   
      memcpy((char *)&opcode, &inpacket[inp], sizeof opcode);           
      memcpy((char *)&oplen, &inpacket[inp + OPCODE_LEN], sizeof oplen); 
      opcode = ntohd(opcode);                                           
      oplen = ntohd(oplen);                                             
                                                                        
      /* Make sure there's room in the buffer; if not, packet is corrupt, so 
       * drop it.   The math is done in the order shown because it avoids 
       * an unsigned overflow (which actually shouldn't be possible). 
       */                                                             
      if (inmax - inp - OPHDR_LEN < (u_int32_t)oplen)                 
        return -1;

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
			    1, looking_for, copy_sought, validp, cos);
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
      else if (looking_for(opcode))
	{
	  /* We should never see a sought option in a relay packet. */
	  if (!copy_top)
	    return -1;

	  /* Already consumed the option header. */
	  inp += OPHDR_LEN; 

	  /* Call the prefix delegation copier function to copy (or not)
	   * this option.
	   */
	  submax = inp + oplen;

	  /* Copy the sought option (or don't). */
	  rv = copy_sought(opcode, inpacket, &inp, submax,
			   outpacket, &outp, outmax, validp, cos);
	  if (rv == -1)
	    return rv;
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

    }                                                                   
                                                                        
  /* If we get to the end of the options and we haven't consumed all the 
   * bytes, the packet is bad, so drop it. 
   */                                              
  if (inmax != inp)                             
    return -1;

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
handle_packet(u_int8_t *inpacket, ssize_t inmax, struct sockaddr_in6 *from,
	      ssize_t (*sendto_func)(int fd, const void *buf, size_t buflen,
				     int flags,
				     const struct sockaddr *dest,
				     socklen_t destlen))
{
  struct sockaddr_in6 dest;
  char buf[100];
  u_int8_t outpacket[MAX_PACKET_SIZE];
  size_t inp;
  size_t outp;
  size_t rmlp;
  u_int16_t rml;
  ssize_t result;

  bool do_privacy = false;
  int ifidp;
  int ifid;
  int ifidl;

  copy_option_closure_t cos;

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
      int orop, orol;
      int want_b4 = 0;
      int want_pdx;
      int policyMask = 0;

      /* Set up and copy encapsulation header into packet. */
      outpacket[0] = RELAY_FORWARD;	/* type */

      /* If this is a RELAY_FORWARD packet, we put the address from which we
       * received the packet in the peer address field, and the copy the link
       * address field from the RELAY_FORWARD.
       */
      if (inpacket[0] == RELAY_FORWARD)
	{
	  /* Malformed packet. */
	  if (inmax < RELAY_HEADER_SIZE)
	    return;

	  /* Hop count exceeded?   This should never ever happen, so we can
	   * log it.   Most likely reason for it to happen is that the shim
	   * has been misconfigured.
	   */
	  if (inpacket[1] == 255)
	    {
	      inet_ntop(AF_INET6, &from->sin6_addr, buf, sizeof buf);
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
		 &from->sin6_addr, IPV6_ADDR_SIZE);
	  inp = RELAY_HEADER_SIZE;
	  outp = RELAY_HEADER_SIZE;
	}
      else
	{
	  outpacket[1] = 0;			/* hop count */

	  memcpy(&outpacket[2], (u_int8_t *)&listen_addr, IPV6_ADDR_SIZE);
	  memcpy(&outpacket[2 + IPV6_ADDR_SIZE],
		 &from->sin6_addr, sizeof from->sin6_addr);
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

      /* Check for an ORO. */
      orop = find_option(inpacket, &inp, inmax, OPTION_ORO, &orol, 1);
      if (orop > 0)
	{
	  int i;
	  for (i = 0; i < orol; i += 2)
	    {
	      u_int16_t opcode;
	      memcpy((u_int8_t *)&opcode, &inpacket[orop + i], 2);
	      opcode = ntohs(opcode);
	      if (opcode == OPTION_IA_B4)
		want_b4 = 1;
	      if (opcode == OPTION_PD_EXCLUDE && do_fake_pdx)
		want_pdx = 1;
	    }
	}

      /* Look for an interface ID option, which may contain prefix color
       * configuration info.
       */
      ifidp = find_option(inpacket, &inp, inmax,
			  OPTION_INTERFACE_ID, &ifidl, 0);
      if (ifidp > 0 && ifidl > 12 && !memcmp(&inpacket[ifidp], VENDOR_IID_TAG, 4))
	{
	  int i;
	vendorTagParse:
	  if (inpacket[ifidp + 4] == 'P')
	    do_privacy = true;
	  for (i = 8; i + 3 < ifidl; i += 4)
	    {
	      if (!memcmp(&inpacket[ifidp + i], "_ANY", 4))
		policyMask |= MASK_BEST_EFFORT;
	      else if (!memcmp(&inpacket[ifidp + i], "IPTV", 4))
		policyMask |= MASK_IPTV;
	      else if (!memcmp(&inpacket[ifidp + i], "VOIP", 4))
		policyMask |= MASK_VOIP;
	    }
	}
      else
	{
	  ifidp = find_option(inpacket, &inp, inmax,
			      OPTION_REMOTE_ID, &ifidl, 0);
	  if (ifidp > 0 && ifidl > 8 &&
	      !memcmp(&inpacket[ifidp + 4], VENDOR_IID_TAG, 4))
	    goto vendorTagParse;
	  else
	    // If we didn't get a policy mask, allow all.
	    policyMask |= MASK_COLORS;
	}

      /* Initialize the triplicate mask. */
      if (want_b4)
	cos.triplicate_mask = MASK_B4;
      else
	cos.triplicate_mask = 0;

      if (do_privacy)
	cos.triplicate_mask |= MASK_PRIVACY;

      if (want_pdx)
	cos.triplicate_mask |= MASK_PD_EXCLUDE;

      /* Do recursive descent copy, dropping extra IA_PDs. */
      result = copy_options(inpacket, &inp, inmax,
			    outpacket, &outp, sizeof outpacket,
			    1, looking_for_ia,
			    elide_pds, (u_int32_t *)0, &cos);

      /* If the packet was malformed, drop it. */
      if (result < 0)
	return;

      // Clear the bits that are blocked by policy.
      if (!(policyMask & MASK_BEST_EFFORT))
	cos.triplicate_mask &= ~MASK_BEST_EFFORT;
      if (!(policyMask & MASK_IPTV))
	cos.triplicate_mask &= ~MASK_IPTV;
      if (!(policyMask & MASK_VOIP))
	cos.triplicate_mask &= ~MASK_VOIP;

      /* Store the Relay Message length, which we now know. */
      ophdr_store(&outpacket[rmlp], rml + result);

      /* Store an interface-id option. */
      ophdr_store(&outpacket[outp], OPTION_INTERFACE_ID);
      ophdr_store(&outpacket[outp + 2], 8);
      outp += OPHDR_LEN;
      outpacket[outp] = from->sin6_scope_id;
      outpacket[outp + 1] = cos.triplicate_mask;
      memcpy(&outpacket[outp + 2], cos.best_effort_iaid, 4);
      outpacket[outp + 6] = cos.na_preflen;
      outpacket[outp + 7] = cos.pd_preflen;
      outp += 8;

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
      u_int32_t expiry = 0;

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
      ifidp = find_option(inpacket, &inp, inmax,
			  OPTION_INTERFACE_ID, &ifidl, 0);
      if (ifidp < OPHDR_LEN)
	{
	  syslog(LOG_CRIT, "DHCP server did not return interface-id!\n");
	  return;
	}
      if (ifidl != 8)
	{
	  syslog(LOG_CRIT,
		 "DHCP server returned wrong length interface id: %d\n",
		 ifidl);
	  return;
	}
      ifid = inpacket[ifidp];
      cos.triplicate_mask = inpacket[ifidp + 1];
      memcpy(cos.best_effort_iaid, &inpacket[ifidp + 2], 4);
      cos.na_preflen = inpacket[ifidp + 6];
      cos.pd_preflen = inpacket[ifidp + 7];

      /* Recursively descend into the packet.   Skip all the top-level
       * options, because these are relay options the server sent to us,
       * and we don't process relay options.   Upon recursing into the
       * relay message option, we will start copying.   We pass in the
       * triplicate_pd function for copying any IA_PD we encounter, because
       * it will copy it three times, once intact, once modified for VoIP,
       * and once modified for IPTV.   It will also store the valid lifetime
       * through the pointer we pass to expiry.
       */
      if (copy_options(inpacket, &inp, inmax,
		       outpacket, &outp, sizeof outpacket, 0, looking_for_ia,
		       triplicate_pd, &expiry, &cos) < 0)
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

      /* Check the valid lifetime we got from triplicate_pd.   If it's
       * zero, don't write a log entry--this means no prefix was assigned.
       */
      if (expiry)
	{
	  time_t now;
	  char filename[64];

	  /* Roll logs at 24 hours. */
	  time(&now);
	  if (now - log_start_time > 24 * 3600)
	    {
	      if (logfile)
		fclose(logfile);
	      snprintf(filename, sizeof filename, "log-%ld", now);
	      logfile = fopen(filename, "w");
	      log_start_time = now;
	    }

	  /* Write a log entry.
	   * If the log is mature, start a new one.
	   */
	  if (logfile)
	    {
	      /* Each entry is just the time, the length, and the data,
	       * and won't be successfully readable on a differently-endian
	       * machine or a machine with different word size.
	       */
	      fwrite(&now, sizeof now, 1, logfile);
	      fwrite(&outp, sizeof outp, 1, logfile);
	      fwrite(outpacket, outp, 1, logfile);
	      fflush(logfile);
	    }
	}
    }
  else
    {
      inet_ntop(AF_INET6, &from->sin6_addr, buf, sizeof buf);
      syslog(LOG_INFO, "Discarding packet of type %d from %s",
	     inpacket[0], buf);
      return;
    }

  /* Relay the packet. */
  sendto_func(sock6fd, outpacket, outp,
	      MSG_DONTWAIT, (struct sockaddr *)&dest, sizeof dest);
}

static void
one_packet(ssize_t (*sendto_func)(int fd, const void *buf, size_t buflen,
				  int flags,
				  const struct sockaddr *dest,
				  socklen_t destlen))
{
  u_int8_t inpacket[MAX_PACKET_SIZE];
  int result;
  struct sockaddr_in6 from;

  char cmsg_buf[1024];
  //  struct cmsghdr *cmh;
  struct iovec iov;
  struct msghdr mh;

  /* Set up msgbuf. */
  memset(&iov, 0, sizeof iov);
  memset(&mh, 0, sizeof mh);
	
  /* This is equivalent to the from argument in recvfrom. */
  mh.msg_name = (caddr_t)&from;
  mh.msg_namelen = sizeof from;
	
  /* This is equivalent to the buf argument in recvfrom. */
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  iov.iov_base = (caddr_t)&inpacket[0];
  iov.iov_len = sizeof inpacket;

  /* This is where additional headers get stuffed. */
  mh.msg_control = cmsg_buf;
  mh.msg_controllen = sizeof cmsg_buf;

  result = recvmsg(sock6fd, &mh, 0);
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

#if 0
  // Parse the control messages...
  if (best_effort_na)
    {
      for (cmh = CMSG_FIRSTHDR(&mh); cmh; cmh = CMSG_NXTHDR(&mh, cmh))
	{
	  if (cmh->cmsg_level == IPPROTO_IPV6 &&
	      cmh->cmsg_type == IPV6_PKTINFO)
	    {
	      struct in6_pktinfo *pktinfo;
	      
	      /* The sockaddr should be right after the cmsg_hdr. */
	      pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmh);

	      /* Check to see if the destination address of this packet is
	       * the special destination address.
	       */
	      if (!memcmp(&privacy_addr,
			  &pktinfo->ipi6_addr, sizeof privacy_addr))
		do_privacy = true;
	    }
	}
    }
#endif
  handle_packet(inpacket, result, &from, sendto_func);
}

static ssize_t
pcap_sendto(int fd, const void *buf, size_t buflen, int flags,
	    const struct sockaddr *dest, socklen_t destlen)
{
  return buflen;
}

static void
pcap_packet (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  size_t inlen = h->caplen;
  int inp;

  // We are just assuming a normal IPv6 header framed in an ethernet header
  // containing a UDP header; if any of these assumptions are wrong we'll
  // get garbage.
  inp = 14 /* l2 */ + 40 /* ipv6 */ + 8 /* udp */;
  struct sockaddr_in6 from;

  // Only process packets that are destined for our address, or we will
  // produce garbage on server packets, etc.
  if (!memcmp(&bytes[14 /* l2 */ + 8 /* version/length/etc */ + 16 /* src */],
	      &listen_addr, IPV6_ADDR_SIZE) ||
      !memcmp(&bytes[14 + 8 + 16], &server_addr, IPV6_ADDR_SIZE))
    {
      memset(&from, 0, sizeof from);
      memcpy(&from.sin6_addr, &bytes[14 + 8], IPV6_ADDR_SIZE);
      memcpy(&from.sin6_port, &bytes[14 + 40], 2);
      handle_packet((u_int8_t *)&bytes[inp], inlen - inp, &from, pcap_sendto);
    }  
}

int
main(int argc, char **argv)
{
  int i;
  const char *replay_file = 0;
  
  openlog(argv[0], LOG_PID | LOG_PERROR, LOG_DAEMON);

  for (i = 1; i < argc; i++)
    {
      if (!strcmp(argv[i], "--replay-pcap"))
	{
	  if (i + 1 == argc)
	    break;
	  replay_file = argv[i + 1];
	  ++i;
	}
      else if (strcmp(argv[i], "--sss-start") == 0)
	{
	  // We need two arguments here.
	  if (i + 1 == argc)
	    break;
	  sss_bit_start = atoi(argv[i + 1]);   /* need a safer conversion.
					      use strtoul() */
	  ++i;
	}
      else if (strcmp(argv[i], "--fake-pdx") == 0)
	{
	  do_fake_pdx = true;
	}
      else if (strcmp(argv[i], "--best-effort-na") == 0)
	{
	  if (i + 1 == argc)
	    break;
	  best_effort_na = true;
	  
	  const char *privacy_addr_arg = argv[i + 1];
	  if (!inet_pton(AF_INET6, privacy_addr_arg, &privacy_addr))
	    {
	      fprintf(stderr,
		      "%s: not a valid IPv6 address\n", privacy_addr_arg);
	      goto usage;
	    }
	  i++;
	}
      else
	break;
    }
  if (argc - i != 2)
    {
    usage:
      fprintf(stderr,
	      "Usage: %s [--replay-pcap pcap-file]\n"
	      "          [--best-effort-na privacy-addr]\n"
	      "          [--sss-start BITINDEX] [--do-fake-pdx]]\n"
	      "          [server-addr] [shim-addr]\n",
	      argv[0]);
      exit(1);
    }
  
  const char *server_addr_arg = argv[i];
  if (!inet_pton(AF_INET6, server_addr_arg, &server_addr))
    {
      fprintf(stderr, "%s: not a valid IPv6 address\n", server_addr_arg);
      goto usage;
    }

  const char *listen_addr_arg = argv[i + 1];
  if (!inet_pton(AF_INET6, listen_addr_arg, &listen_addr))
    {
      fprintf(stderr, "%s: not a valid IPv6 address\n", listen_addr_arg);
      goto usage;
    }
  
  if (replay_file)
    {
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *p = pcap_open_offline(replay_file, errbuf);
      if (!p)
	{
	  fprintf(stderr, "%s: %s\n", replay_file, errbuf);
	  exit(1);
	}
      pcap_loop(p, 0, pcap_packet, (unsigned char *)replay_file);
      pcap_close(p);
    }
  else
    {
      dhcpv6_socket_setup(local_port_dhcpv6);
      
      dhcpv6_multicast_relay_join();
      
      do {
	one_packet(sendto);
      } while (1);
    }
  return 0;
}


int set_sss_bits(unsigned char *addr, unsigned int offset, unsigned int value)
{
    clearbit(addr, IPV6_ADDR_SIZE, offset + 2);
    clearbit(addr, IPV6_ADDR_SIZE, offset + 1);
    clearbit(addr, IPV6_ADDR_SIZE, offset);

    if ((value & 0x4) != 0) {
        setbit(addr, IPV6_ADDR_SIZE, offset);
    }
    
    if ((value & 0x2) != 0) {
        setbit(addr, IPV6_ADDR_SIZE, offset + 1);
    }

    if ((value & 0x1) != 0) {
        setbit(addr, IPV6_ADDR_SIZE, offset + 2);
    }

    return 0;
}

    
int setbit(void *array, unsigned int array_len_in_bytes,
           unsigned int bitnum) 
{
    return assign_bit(array, array_len_in_bytes, bitnum, 1);
}

int clearbit(void *array, unsigned int array_len_in_bytes,
             unsigned int bitnum)
{
    return assign_bit(array, array_len_in_bytes, bitnum, 0);
}

/* for big-endian bit strings */

int assign_bit(void *array, unsigned int array_len_in_bytes,
           unsigned int bitnum, unsigned int value) 
{
    if (bitnum >= (array_len_in_bytes * 8) || (value != 0 && value != 1))
        return -1;

    unsigned int idx = bitnum / 8;
    unsigned int bitpos = bitnum % 8;
    unsigned char *carray = (unsigned char *) array;
    unsigned char byte = carray[idx];

    if (value == 0)
        byte &= ~(0x80 >> bitpos);
    else
        byte |= 0x80 >> bitpos;

    carray[idx] = byte;

    return 0;
}
 

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
