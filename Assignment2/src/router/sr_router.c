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

static int sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        struct sr_arpentry **entry);

static void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);


static uint32_t longest_prefix_match(struct sr_instance* sr, uint32_t ip);
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

  // replicate the packet
  uint8_t *packet_copy = (uint8_t *)malloc(len);
  memcpy(packet_copy, packet, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet_copy;
  uint16_t ethtype = ntohs(eth_hdr->ether_type);
  if (ethtype == ethertype_ip) {
    struct sr_arpentry * entry = NULL;
    int res = sr_handle_ip_packet(sr, packet_copy+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface, &entry);
    if ( res == 1 && entry) {
      // send the packet
      struct sr_if * out_if = get_interface_from_ip(sr, entry->ip);
      for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_dhost[i] = entry->mac[i];
        eth_hdr->ether_shost[i] = out_if->addr[i];
      }
      sr_send_packet(sr, packet_copy, len, out_if->name);
    }
    else if ( res == 1 && !entry){ // entry not found
      // queue the packet
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet_copy+sizeof(sr_ethernet_hdr_t));
      struct sr_if * out_if = get_interface_from_ip(sr, ip_hdr->ip_dst);
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), out_if->ip, packet_copy, len, out_if->name);
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
        struct sr_arpentry **entry)
{ 
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)packet;
  // check the length of the packet and send icmp packet if necessary
  if (len < sizeof(sr_ip_hdr_t) || cksum(packet, sizeof(sr_ip_hdr_t)) != ip_hdr->ip_sum) { 
    sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
    return 0;
  }

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
  } else {
    // if it is not icmp packet, but tcp or udp and it is sent to one of the interfaces, send icmp port unreachable
    struct sr_if *if_walker = sr->if_list;
    while (if_walker) {
      if (if_walker->ip == ip_hdr->ip_dst) {
        sr_send_icmp_packet(sr, packet, len, interface, 3, 3);
        return 0;
      }
      if_walker = if_walker->next;
    }
  }

  uint32_t next_hop_ip = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (next_hop_ip == 0) {
    sr_send_icmp_packet(sr, packet, len, interface, 3, 0);
    return 0;
  }

  // check the arp cache

  *entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
  return 1;
}

static void sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
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
    eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t) + len);
    // modify ethernet header
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, ori_eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, ori_eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    // fill original ip header and icmp header
    memcpy(eth_hdr + sizeof(sr_ethernet_hdr_t), packet, len);
    // modify ip header
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_hdr + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_ttl = INIT_TTL;
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;
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
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_hdr + sizeof(sr_ethernet_hdr_t));
    memcpy(ip_hdr, packet, sizeof(sr_ip_hdr_t));
    // modify ip header
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    ip_hdr->ip_off = IP_DF;
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
    ip_hdr->ip_dst = ori_ip_hdr->ip_src;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    // modify icmp header
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
  }
  sr_send_packet(sr, (uint8_t *)eth_hdr, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), interface);
  free(eth_hdr);
  return;
}

void sr_send_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint16_t opcode)
{
  return;
}

static uint32_t longest_prefix_match(struct sr_instance* sr, uint32_t ip)
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
  return next_hop_ip;
}
/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
