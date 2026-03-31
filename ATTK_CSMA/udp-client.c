#define N1
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include <string.h>
#include "net/mac/csma/csma-output.h"

#define LOG_MODULE "NORMAL"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* --- SLOW DOWN THE RATE --- */
/* Start with 5 seconds to ensure the BR can handle the logs */
#define SEND_INTERVAL (5 * CLOCK_SECOND) 

static struct simple_udp_connection udp_conn;

/* Use a single pointer to point to the correct string */
static char *msg = "N1"; 

PROCESS(normal_process, "Normal UDP Node");
AUTOSTART_PROCESSES(&normal_process);

PROCESS_THREAD(normal_process, ev, data)
{
  static struct etimer timer;
  static uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  /* Set msg based on build flags */
  #ifdef ATTK
    msg = "A1";
  #elif defined(N2)
    msg = "N2";
  #else
    msg = "N1";
  #endif

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, NULL);

  LOG_INFO("Waiting for RPL root...\n");

  etimer_set(&timer, CLOCK_SECOND * 2);
  while(!NETSTACK_ROUTING.node_is_reachable() || 
        !NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
    LOG_INFO("Searching for root...\n");
  }

  LOG_INFO("Root found! Starting transmissions...\n");

  etimer_set(&timer, SEND_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    if(NETSTACK_ROUTING.node_is_reachable()) {
      LOG_INFO("Sending %s to root\n", msg);
      simple_udp_sendto(&udp_conn, msg, strlen(msg), &dest_ipaddr);
      print_csma_stats();
    } else {
      LOG_ERR("Root lost, waiting...\n");
    }

    etimer_reset(&timer);
  }

  PROCESS_END();
}