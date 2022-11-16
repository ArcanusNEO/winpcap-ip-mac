#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <time.h>

#include <winsock2.h>

#include <windows.h>
#include <winnt.h>

#include "pcap.h"

typedef struct {
  uint8_t byte[6];
} __attribute__((packed)) mac_t;

typedef struct {
  mac_t    dst_mac;
  mac_t    src_mac;
  uint16_t ether_type;
} __attribute__((packed)) etherheader_t;

typedef struct {
  etherheader_t etherheader;
  uint16_t      htype;
  uint16_t      ptype;
  uint8_t       maclen;
  uint8_t       iplen;
  uint16_t      op;
  mac_t         src_mac;
  uint32_t      src_ip;
  mac_t         dst_mac;
  uint32_t      dst_ip;
} __attribute__((packed)) arpframe_t;

mac_t capmac(pcap_t* adhandle, uint32_t src_ip) {
  mac_t ret = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  struct pcap_pkthdr* header;

  int      res;
  uint8_t* pkt_data;

  while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
    if (res == 0) continue;  // Timeout elapsed
    arpframe_t* ippacket = pkt_data;
    if (ntohs(ippacket->etherheader.ether_type) == 0x806
        && ntohs(ippacket->op) == 0x0002 && ippacket->src_ip == src_ip) {
      memcpy(&ret, &ippacket->etherheader.src_mac, sizeof(mac_t));
      break;
    }
  }
  return ret;
}

#define printmac(mac)                                                   \
  printf("%02x:%02x:%02x:%02x:%02x:%02x", (mac).byte[0], (mac).byte[1], \
         (mac).byte[2], (mac).byte[3], (mac).byte[4], (mac).byte[5])

#define MX_IP_SZ     16
#define MX_IP_SZ_FMT "15"

signed main(int argc, char* argv[]) {
  static char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t*  alldevs;
  // Retrieve the device list
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return -1;
  }

  pcap_if_t* d;
  int        i = 0;
  // Print the list
  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description) printf(" (%s) ", d->description);
    else printf(" (N/A) ");
    for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next)
      if (((struct sockaddr_in*) a->addr)->sin_family == AF_INET && a->addr)
        printf("%c%s", " ("[a == d->addresses],
               inet_ntoa(((struct sockaddr_in*) a->addr)->sin_addr));
    puts(")");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    return -1;
  }

  printf("Enter the interface number (1-%d): ", i);
  int inum;
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    // Free the device list
    pcap_freealldevs(alldevs);
    return -1;
  }

  // Jump to the selected adapter
  for (d = alldevs, i = 0; i < inum - 1; d = d->next, ++i) { }

  pcap_t* adhandle;
  // Open the adapter
  if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
    fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by WinPcap\n",
            d->name);
    // Free the device list
    pcap_freealldevs(alldevs);
    return -1;
  }

  char self_ip[MX_IP_SZ];
  for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next)
    if (((struct sockaddr_in*) a->addr)->sin_family == AF_INET && a->addr) {
      strcpy(self_ip, inet_ntoa(((struct sockaddr_in*) a->addr)->sin_addr));
      break;
    }

  printf("\nListening on %s (%s)...\n", d->description, self_ip);

  // At this point, we don't need any more the device list. Free it
  pcap_freealldevs(alldevs);

  printf("Enter IP: ");
  char query_ip[MX_IP_SZ];
  scanf("%" MX_IP_SZ_FMT "s", query_ip);

  arpframe_t arpframe = {
    .etherheader = {.dst_mac    = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                    .src_mac    = 0,
                    .ether_type = htons(0x806)}, // 帧类型为ARP
    .htype       = htons(0x0001), // 硬件类型为以太网
    .ptype       = htons(0x0800), // 协议类型为IP
    .maclen      = 6, // 硬件地址长度为6
    .iplen       = 4, // 协议地址长为4
    .op          = htons(0x0001), // 操作为ARP请求
    .src_mac     = 0,
    .src_ip      = 0,
    .dst_mac     = 0,
    .dst_ip      = inet_addr(self_ip)
  };

  printf("\nQuerying...\n");

  pcap_sendpacket(adhandle, &arpframe, sizeof(arpframe_t));
  mac_t self_mac = capmac(adhandle, arpframe.dst_ip);

  printf("\nSelf MAC Address: ");
  printmac(self_mac);
  puts("");

  mac_t mac = self_mac;

  if (strcmp(self_ip, query_ip)) {
    arpframe.etherheader.src_mac = self_mac;
    arpframe.src_mac             = self_mac;
    arpframe.src_ip              = inet_addr(self_ip);
    arpframe.dst_ip              = inet_addr(query_ip);
    pcap_sendpacket(adhandle, &arpframe, sizeof(arpframe_t));
    mac = capmac(adhandle, arpframe.dst_ip);
  }
  printf("\nQueried MAC Address: ");
  printmac(mac);
  puts("");

  pcap_close(adhandle);
}
