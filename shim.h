/* shim.h
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

#ifdef DHCPv4
typedef u_int8_t dhcp_opcode_t ;
typedef u_int8_t dhcp_oplen_t;
#define OPCODE_LEN 1
#define OPLEN_LEN 1
#define ntohd(x)	(x)
#define ophdr_store(dest, val)	((*(dest)) = (val))
#else
typedef u_int16_t dhcp_opcode_t ;
typedef u_int16_t dhcp_oplen_t;
#define OPCODE_LEN 2
#define OPLEN_LEN 2
#define ntohd(x)	ntohs(x)
#define ophdr_store(dest, val)	word(dest, val)
#define DHCPv6	1
#endif

typedef enum { false = 0, true = 1} bool;

#define OPHDR_LEN (OPCODE_LEN + OPLEN_LEN)

/* Option scanner macros.
 *
 * OS_VARS defines variables used by the option scanner.
 * OS_START does all the work to set up the option scan, and includes the
 * beginning of the while loop.
 * OS_FINISH ends the while loop and contains all the finishing code to
 * return a result.
 * The code written between OS_START and OS_FINISH is run in a loop until
 * all the options in the input range have been scanned and (where appropriate)
 * copied.
 */

/* Variables used by option scanner */
#define OS_VARS					\
  dhcp_opcode_t opcode;				\
  dhcp_oplen_t oplen;				\
  size_t inp;

#define OS_START				\
  inp = *inpp;					\
  						\
  while (inmax - inp >= OPHDR_LEN)					\
    {									\
      /* Decode the option code and option length. */			\
      memcpy((char *)&opcode, &inpacket[inp], sizeof opcode);		\
      memcpy((char *)&oplen, &inpacket[inp + OPCODE_LEN], sizeof oplen); \
      opcode = ntohd(opcode);						\
      oplen = ntohd(oplen);						\
      									\
      /* Make sure there's room in the buffer; if not, packet is corrupt, so \
       * drop it.   The math is done in the order shown because it avoids \
       * an unsigned overflow (which actually shouldn't be possible). \
       */							      \
      if (inmax - inp - OPHDR_LEN < (u_int32_t)oplen)		      \
	return -1;

#define OS_FINISH				\
    }									\
      									\
  /* If we get to the end of the options and we haven't consumed all the \
   * bytes, the packet is bad, so drop it. \
   */						   \
  if (inmax != inp)				\
    return -1;

#define MAX_PACKET_SIZE		8192
#define IPV6_ADDR_SIZE		16
#define RELAY_HEADER_SIZE	34
#define CLIENT_HEADER_SIZE	4
#define IAPD_HDR_LEN		16
#define IAPREFIX_FIXED_LEN	25
#define IAADDR_FIXED_LEN	24

#define SOLICIT			1
#define ADVERTISE		2
#define REQUEST			3
#define CONFIRM			4
#define RENEW			5
#define REBIND			6
#define REPLY			7
#define RELEASE			8
#define DECLINE			9
#define RECONFIGURE		10
#define INFORMATION_REQUEST	11
#define RELAY_FORWARD		12
#define RELAY_REPLY		13

#define	OPTION_IA_PD		25
#define OPTION_IA_NA		3
#define OPTION_RELAY_MSG	9
#define	OPTION_USER_CLASS	15
#define OPTION_IAPREFIX		26
#define OPTION_IAADDR		5
#define OPTION_INTERFACE_ID	18
#define OPTION_REMOTE_ID	37
#define OPTION_SUBSCRIBER_ID	38
#define OPTION_IA_B4		199
#define OPTION_ORO		6
#define OPTION_PD_EXCLUDE	67

#define DHCPV6_SERVER_PORT	547
#define DHCPV6_CLIENT_PORT	546

#define MASK_BEST_EFFORT	1
#define MASK_IPTV		2
#define MASK_VOIP		4
#define MASK_COLORS	(MASK_BEST_EFFORT | MASK_IPTV | MASK_VOIP)
#define MASK_B4			8
#define MASK_PRIVACY		16
#define MASK_PD_EXCLUDE		32
#define MASK_PREFIX_WIDENED	64

typedef struct {
  int triplicate_mask;
  int ia_mask;
  u_int8_t best_effort_iaid[4];
  u_int8_t b4_addr[IPV6_ADDR_SIZE];
  u_int8_t na_preflen;
  u_int8_t pd_preflen;
} copy_option_closure_t;

// In order to send prefix color selection info in the interface
// ID option, you need to define a vendor tag that will identify
// the IID as containing that info.
// #define VENDOR_IID_TAG "YPLC"

void word(u_int8_t *dest, u_int16_t word);
void dhcpv6_socket_setup(u_int16_t port);
void dhcpv4_socket_setup(u_int16_t port);
int find_option(u_int8_t *inpacket, size_t *inpp, size_t inmax,
		int sought, int *lp, int deep);
int copy_options(u_int8_t *inpacket, size_t *inpp, size_t inmax,
		 u_int8_t *outpacket, size_t *outpp, size_t outmax,
		 int copy_top, bool (*looking_for)(dhcp_opcode_t opcode),
		 int (*copy_sought)(dhcp_opcode_t opcode,
				    u_int8_t *inpacket,
				    size_t *inpp, size_t inmax,
				    u_int8_t *outpacket, size_t *outpp,
				    size_t outmax, u_int32_t *validp,
				    copy_option_closure_t *cos),
		 u_int32_t *validp, copy_option_closure_t *cos);

/* Local Variables:  */
/* mode:C */
/* c-file-style:"gnu" */
/* end: */
