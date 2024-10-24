/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct forward_item
{
  uint32_t next_hop;
  char *interface;
};


static int sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        struct sr_arpentry **entry,
        char *if_name);

static void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);


static struct forward_item longest_prefix_match(struct sr_instance* sr, uint32_t ip);
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);  
  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  // replicate the packet
  uint8_t *packet_copy = (uint8_t *)malloc(len);
  memcpy(packet_copy, packet, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet_copy;
  uint16_t ethtype = ntohs(eth_hdr->ether_type);
  if (ethtype == ethertype_ip) {
    struct sr_arpentry * entry = NULL;
    char if_name[sr_IFACE_NAMELEN];
    memset(if_name, 0, sr_IFACE_NAMELEN);
    int res = sr_handle_ip_packet(sr, packet_copy+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface, &entry, if_name);
    if ( res == 1 && entry) {
      // send the packet
      struct sr_if * out_if = get_interface_from_ip(sr, entry->ip);
      // for (int i = 0; i < ETHER_ADDR_LEN; i++) {
      //   eth_hdr->ether_dhost[i] = entry->mac[i];
      //   eth_hdr->ether_shost[i] = out_if->addr[i];
      // }
      memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet_copy, len, out_if->name);
      free(entry);
    }
    else if ( res == 1 && !entry){ // entry not found
      // queue the packet
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet_copy+sizeof(sr_ethernet_hdr_t));
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_dst, packet_copy, len, if_name);
      handle_arpreq(sr, req);
    }
  } else if (ethtype == ethertype_arp) {
    sr_handle_arp_packet(sr, packet_copy+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface);
  } 

  free(packet_copy);
  /* fill in code here */

} /* end sr_handlepacket */

static int sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        struct sr_arpentry **entry,
        char *if_name)
{ 
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)packet;  
  // check the length of the packet and send icmp packet if necessary
  uint16_t tmp = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (len < sizeof(sr_ip_hdr_t) || cksum(packet, sizeof(sr_ip_hdr_t)) != tmp) { 
    sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
    return 0;
  }
  ip_hdr->ip_sum = tmp;

  ip_hdr->ip_ttl--;
  if (ip_hdr->ip_ttl == 0) {
    sr_send_icmp_packet(sr, packet, len, interface, 11, 0);
    return 0;
  }
  // recomputing the checksum
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  // check if it is icmp request and if it is sent to one of the interfaces
  if (ip_hdr->ip_p == ip_protocol_icmp) {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t));
    if (icmp_hdr->icmp_type == 8) {
      struct sr_if *if_walker = sr->if_list;
      while (if_walker) {
        if (if_walker->ip == ip_hdr->ip_dst) {
          sr_send_icmp_packet(sr, packet, len, interface, 0, 0);
          return 0;
        }
        if_walker = if_walker->next;
      }
    }
  } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {
    // if it is not icmp packet, but tcp or udp and it is sent to one of the interfaces, send icmp port unreachable
    struct sr_if *if_walker = sr->if_list;
    while (if_walker) {
      if (if_walker->ip == ip_hdr->ip_dst) {
        sr_send_icmp_packet(sr, packet, len, interface, 3, 3);
        return 0;
      }
      if_walker = if_walker->next;
    }
  } else {
    return 0;
  }

  struct forward_item fi = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (fi.next_hop == 0) {
    sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
    return 0;
  }

  strcpy(if_name, fi.interface);
  // check the arp cache

  *entry = sr_arpcache_lookup(&(sr->cache), fi.next_hop);
  return 1;
}

static void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{ 
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)packet;
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet - sizeof(sr_ethernet_hdr_t));
  
  if (arp_hdr->ar_op == htons(arp_op_request)) {
    if (arp_hdr->ar_tip == sr_get_interface(sr, interface)->ip) {
      eth_hdr->ether_type = htons(ethertype_arp);
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_dhost[i] = arp_hdr->ar_sha[i];
        eth_hdr->ether_shost[i] = sr_get_interface(sr, interface)->addr[i];
      }
      arp_hdr->ar_op = htons(arp_op_reply);
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];
        arp_hdr->ar_sha[i] = sr_get_interface(sr, interface)->addr[i];
      }
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = sr_get_interface(sr, interface)->ip;
      sr_send_packet(sr, packet-sizeof(sr_ethernet_hdr_t), len+sizeof(sr_ethernet_hdr_t), interface);
    }
  } else if (arp_hdr->ar_op == htons(arp_op_reply)) {
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (req) {
      struct sr_packet *pkt_walker = req->packets;
      while (pkt_walker) {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt_walker->buf);
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
          eth_hdr->ether_dhost[i] = arp_hdr->ar_sha[i];
          eth_hdr->ether_shost[i] = sr_get_interface(sr, pkt_walker->iface)->addr[i];
        }
        sr_send_packet(sr, pkt_walker->buf, pkt_walker->len, pkt_walker->iface);
        pkt_walker = pkt_walker->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
  }
  return;
}

void sr_send_icmp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t type,
        uint8_t code)
{ 
  //malloc a new packet with ethernet header, ip header and icmp header
  sr_ethernet_hdr_t *ori_eth_hdr = (sr_ethernet_hdr_t *)(packet- sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *ori_ip_hdr = (sr_ip_hdr_t *)(packet);
  sr_ethernet_hdr_t *eth_hdr;
  if (type == 0) { // echo reply
    printf("icmp echo reply\n");
    int total = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    eth_hdr = (sr_ethernet_hdr_t *)malloc(total);
    memset(eth_hdr, 0, total);
    // modify ethernet header
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, ori_eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, ori_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    // modify ip header
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((void*)eth_hdr + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_v = ori_ip_hdr->ip_v;
    ip_hdr->ip_hl = ori_ip_hdr->ip_hl;
    ip_hdr->ip_tos = ori_ip_hdr->ip_tos;
    ip_hdr->ip_len = ori_ip_hdr->ip_len;
    ip_hdr->ip_id = ori_ip_hdr->ip_id;
    ip_hdr->ip_off = ori_ip_hdr->ip_off;
    ip_hdr->ip_p = ori_ip_hdr->ip_p;
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_src = ori_ip_hdr->ip_dst;
    ip_hdr->ip_dst = ori_ip_hdr->ip_src;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    // modify icmp header
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
  } else { 
    eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    // modify ethernet header
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, ori_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    // fill ip header and icmp header
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((void*)eth_hdr + sizeof(sr_ethernet_hdr_t));
    memcpy(ip_hdr, packet, sizeof(sr_ip_hdr_t));
    // modify ip header
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    ip_hdr->ip_off = IP_DF;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
    ip_hdr->ip_dst = ori_ip_hdr->ip_src;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    // modify icmp header
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((void*)ip_hdr + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
    memcpy(icmp_hdr->data, packet, sizeof(sr_ip_hdr_t) + 8);
  }
  sr_send_packet(sr, (uint8_t *)eth_hdr, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), interface);
  free(eth_hdr);
  return;
}


static struct forward_item longest_prefix_match(struct sr_instance* sr, uint32_t ip)
{
  uint32_t next_hop_ip = 0;
  struct sr_rt *rt_walker = sr->routing_table;
  while (rt_walker) {
    if ((rt_walker->mask.s_addr & ip) == rt_walker->dest.s_addr) {
      next_hop_ip = rt_walker->gw.s_addr;
      break;
    }
    rt_walker = rt_walker->next;
  }
  return (struct forward_item){next_hop_ip, rt_walker->interface};
}
/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
