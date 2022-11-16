#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <time.h>
#include <windows.h>
#include <winnt.h>

#include "pcap.h"

typedef struct {
  uint8_t byte[6];
} __attribute__((packed)) mac_t;

typedef struct {
  mac_t    daddr;
  mac_t    saddr;
  uint16_t type;
} __attribute__((packed)) etherheader_t;

typedef struct {
  etherheader_t eth;
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

signed main(int argc, char* argv[]) {
  static char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t*  alldevs;
  /* Retrieve the device list */
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return -1;
  }

  pcap_if_t* d;
  int        i = 0;
  /* Print the list */
  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description) printf(" (%s)\n", d->description);
    else printf(" (No description available)\n");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    return -1;
  }

  printf("Enter the interface number (1-%d):", i);
  int inum;
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  /* Jump to the selected adapter */
  for (d = alldevs, i = 0; i < inum - 1; d = d->next, ++i)
    ;

  pcap_t* adhandle;
  /* Open the adapter */
  if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
    fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by WinPcap\n",
            d->name);
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);

  /* At this point, we don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);

  int                 res;
  struct pcap_pkthdr* header;
  const uint8_t*      pkt_data;
  /* Retrieve the packets */
  while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
    if (res == 0) continue; /* Timeout elapsed */

    /* convert the timestamp to readable format */
    time_t     local_tv_sec = header->ts.tv_sec;
    struct tm* ltime        = localtime(&local_tv_sec);
    char       timestr[16];
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("[Timestamp] %s,%.6d\n", timestr, header->ts.tv_usec);
    printf("[Capture length] %u\n", header->caplen);
    printf("[Total length] %u\n", header->len);
    const etherheader_t* eh = pkt_data;
    printf("[Source MAC] %x:%x:%x:%x:%x:%x\n", eh->saddr.byte[0],
           eh->saddr.byte[1], eh->saddr.byte[2], eh->saddr.byte[3],
           eh->saddr.byte[4], eh->saddr.byte[5]);
    printf("[Destination MAC] %x:%x:%x:%x:%x:%x\n", eh->daddr.byte[0],
           eh->daddr.byte[1], eh->daddr.byte[2], eh->daddr.byte[3],
           eh->daddr.byte[4], eh->daddr.byte[5]);
    printf("[EtherType] 0x%04hx\n", ntohs(eh->type));
    puts("--------");
  }

  if (res == -1) {
    printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
    return -1;
  }

  pcap_close(adhandle);
}
