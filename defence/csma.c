/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         The 802.15.4 standard CSMA protocol (nonbeacon-enabled)
 * \author
 *         Adam Dunkels <adam@sics.se>
 *         Simon Duquennoy <simon.duquennoy@inria.fr>
 */

#include "net/mac/csma/csma.h"
#include "net/mac/csma/csma-output.h"
#include "net/mac/framer/frame802154.h"
#include "net/mac/mac-sequence.h"
#include "net/packetbuf.h"
#include "net/netstack.h"
#include "sys/rtimer.h"
#include <stdbool.h>
#include <stdio.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CSMA"
#define LOG_LEVEL LOG_LEVEL_MAC

// ---- Start of the new code. ----

#define NUMBER_OF_ALLOWED_NODES 10
#define ALPHA_SHIFT 3
#define MAX_VALID_IAT (RTIMER_SECOND / 10)
#define CHEAT_THRESHOLD_TICKS 1500
#define MAX_SUSPICIOUS_SCORE 10


// Stores info about a node.
typedef struct
{
  linkaddr_t addr;
  uint32_t ewma;
  int8_t suspicion_score;
  rtimer_clock_t last_time;
  bool is_blacklisted;
} Node;

static Node nodes[NUMBER_OF_ALLOWED_NODES];
static int nodes_length = 0;
static int nr_dropped_packets = 0;

static void print_addr(const linkaddr_t *sender_addr)
{
  printf("Address: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
         sender_addr->u8[0], sender_addr->u8[1], sender_addr->u8[2], sender_addr->u8[3],
         sender_addr->u8[4], sender_addr->u8[5], sender_addr->u8[6], sender_addr->u8[7]);
}


// If the node has been stored in the array, return it.
// otherwise, create a new node in the array.
static Node *get_node(const linkaddr_t *node_addr)
{

  if (linkaddr_cmp(node_addr, &linkaddr_null))
    return NULL;

  // Check if the node is in the stored array.
  for (int i = 0; i < nodes_length; i++)
  {
    if (linkaddr_cmp(node_addr, &nodes[i].addr))
    {
      return &nodes[i];
    }
  }

  if (nodes_length >= NUMBER_OF_ALLOWED_NODES)
  {
    // Out of bounds for this experiment. Show an error.
    printf("[Backoff Detection] Too many nodes in this set-up.\n");
    return NULL;
  }

  printf("[Backoff Detection] Encountered a new node. \n");
  print_addr(node_addr);

  // Add the node to the index
  linkaddr_copy(&nodes[nodes_length].addr, node_addr);

  nodes[nodes_length].ewma = 0;
  nodes[nodes_length].suspicion_score = 0;
  nodes[nodes_length].last_time = RTIMER_NOW() - (RTIMER_SECOND * 30); // set far in the past to avoid instant detection.
  nodes[nodes_length].is_blacklisted = false;

  nodes_length++;

  return &nodes[nodes_length - 1];
}


// process_node calculates the ewma, compares it to the threshold and checks if the node is malicious.
// returns true if the node should be banned.
static bool process_node(Node *node)
{

  rtimer_clock_t now = RTIMER_NOW();

  // iat -> inter arrival time
  rtimer_clock_t iat = now - node->last_time;
  node->last_time = now;

  if (iat > MAX_VALID_IAT) return false;

  if (node->ewma == 0) {
    node->ewma = iat;
  } else {
    uint32_t s_prev = node->ewma;
    node->ewma = (iat + (s_prev << ALPHA_SHIFT) - s_prev) >> ALPHA_SHIFT;
  }

  if (node->ewma < CHEAT_THRESHOLD_TICKS) {
    
    node->suspicion_score++;

    if (node->suspicion_score >= MAX_SUSPICIOUS_SCORE) {
      return true;
    }
  } else if (node->suspicion_score > 0) {
    node->suspicion_score--;
  }

  return false;
}

// ---- End of the new code. ----

static void
init_sec(void)
{
#if LLSEC802154_USES_AUX_HEADER
  if (packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL) ==
      PACKETBUF_ATTR_SECURITY_LEVEL_DEFAULT)
  {
    packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL,
                       CSMA_LLSEC_SECURITY_LEVEL);
  }
#endif
}
/*---------------------------------------------------------------------------*/
static void
send_packet(mac_callback_t sent, void *ptr)
{

  init_sec();

  csma_output_packet(sent, ptr);
}
/*---------------------------------------------------------------------------*/
static void
input_packet(void)
{
#if CSMA_SEND_SOFT_ACK
  uint8_t ackdata[CSMA_ACK_LEN];
#endif

  // LOG_INFO("Package received [perform test here]\n");

  if (packetbuf_datalen() == CSMA_ACK_LEN)
  {
    /* Ignore ack packets */
    LOG_DBG("ignored ack\n");
  }
  else if (CSMA_FRAMER.parse() < 0)
  {
    LOG_ERR("failed to parse %u\n", packetbuf_datalen());
  }
  else if (!linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
                         &linkaddr_node_addr) &&
           !packetbuf_holds_broadcast())
  {
    LOG_WARN("not for us\n");
  }
  else if (linkaddr_cmp(packetbuf_addr(PACKETBUF_ADDR_SENDER), &linkaddr_node_addr))
  {
    LOG_WARN("frame from ourselves\n");
  }
  else
  {

    // 
    //    New code for ANS starts here
    //
    Node *node = get_node(packetbuf_addr(PACKETBUF_ADDR_SENDER));

    if (node != NULL)
    {

      if (node->is_blacklisted == true)
      {
        nr_dropped_packets++;

        if (nr_dropped_packets % 10 == 0) {
          printf("[Backoff Detection] Dropped %d total packets from flagged nodes\n", nr_dropped_packets);
        }

        return;
      }

      // check if it is a violation
      if (process_node(node))
      {
        printf("[Backoff Detection] Violating node detected. Blacklisting node. ");
        print_addr(&node->addr);

        node->is_blacklisted = true;
      }
    }

    // 
    //    New code for ANS ends here
    //

    int duplicate = 0;

    /* Check for duplicate packet. */
    duplicate = mac_sequence_is_duplicate();
    if (duplicate)
    {
      /* Drop the packet. */
      LOG_WARN("drop duplicate link layer packet from ");
      LOG_WARN_LLADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
      LOG_WARN_(", seqno %u\n", packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));
    }
    else
    {
      mac_sequence_register_seqno();
    }

#if CSMA_SEND_SOFT_ACK
    if (packetbuf_attr(PACKETBUF_ATTR_MAC_ACK))
    {
      ackdata[0] = FRAME802154_ACKFRAME;
      ackdata[1] = 0;
      ackdata[2] = ((uint8_t *)packetbuf_hdrptr())[2];
      NETSTACK_RADIO.send(ackdata, CSMA_ACK_LEN);
    }
#endif /* CSMA_SEND_SOFT_ACK */
    if (!duplicate)
    {
      LOG_INFO("received packet from ");
      LOG_INFO_LLADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
      LOG_INFO_(", seqno %u, len %u\n", packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO), packetbuf_datalen());
      NETSTACK_NETWORK.input();
    }
  }
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  return NETSTACK_RADIO.on();
}
/*---------------------------------------------------------------------------*/
static int
off(void)
{
  return NETSTACK_RADIO.off();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  radio_value_t radio_max_payload_len;

  /* Check that the radio can correctly report its max supported payload */
  if (NETSTACK_RADIO.get_value(RADIO_CONST_MAX_PAYLOAD_LEN, &radio_max_payload_len) != RADIO_RESULT_OK)
  {
    LOG_ERR("! radio does not support getting RADIO_CONST_MAX_PAYLOAD_LEN. Abort init.\n");
    return;
  }

#if CSMA_SEND_SOFT_ACK
  radio_value_t radio_rx_mode;

  /* Disable radio driver's autoack */
  if (NETSTACK_RADIO.get_value(RADIO_PARAM_RX_MODE, &radio_rx_mode) != RADIO_RESULT_OK)
  {
    LOG_WARN("radio does not support getting RADIO_PARAM_RX_MODE\n");
  }
  else
  {
    /* Unset autoack */
    radio_rx_mode &= ~RADIO_RX_MODE_AUTOACK;
    if (NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, radio_rx_mode) != RADIO_RESULT_OK)
    {
      LOG_WARN("radio does not support setting RADIO_PARAM_RX_MODE\n");
    }
  }
#endif

  mac_sequence_init();

#if LLSEC802154_USES_AUX_HEADER
#ifdef CSMA_LLSEC_DEFAULT_KEY0
  uint8_t key[16] = CSMA_LLSEC_DEFAULT_KEY0;
  csma_security_set_key(0, key);
#endif
#endif /* LLSEC802154_USES_AUX_HEADER */
  csma_output_init();
  on();
}
/*---------------------------------------------------------------------------*/
static int
max_payload(void)
{
  int framer_hdrlen;
  radio_value_t max_radio_payload_len;
  radio_result_t res;

  init_sec();

  framer_hdrlen = NETSTACK_FRAMER.length();

  res = NETSTACK_RADIO.get_value(RADIO_CONST_MAX_PAYLOAD_LEN,
                                 &max_radio_payload_len);

  if (res == RADIO_RESULT_NOT_SUPPORTED)
  {
    LOG_ERR("Failed to retrieve max radio driver payload length\n");
    return 0;
  }

  if (framer_hdrlen < 0)
  {
    /* Framing failed, we assume the maximum header length */
    framer_hdrlen = CSMA_MAC_MAX_HEADER;
  }

  return MIN(max_radio_payload_len, PACKETBUF_SIZE) - framer_hdrlen - LLSEC802154_PACKETBUF_MIC_LEN();
}
/*---------------------------------------------------------------------------*/
const struct mac_driver csma_driver = {
    "CSMA",
    init,
    send_packet,
    input_packet,
    on,
    off,
    max_payload,
};
/*---------------------------------------------------------------------------*/
