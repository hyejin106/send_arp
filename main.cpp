#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>

#define PRINT_MAC "%s - %02x:%02x:%02x:%02x:%02x:%02x\n"

static const uint8_t IP_ADDR_LEN = 0x04;
static const uint8_t ARP_REQUEST_TMAC[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t BROADCAST_DMAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp eth0 192.168.10.2 192.168.10.1\n");
}

void printMAC(const char* msg, unsigned char* target) {
    printf(PRINT_MAC, msg, target[0], target[1], target[2], target[3], target[4], target[5]);
}

void getMacAddr(char * dev, unsigned char * host_mac, struct in_addr host_ip){

    // this func from
    // https://www.binarytides.com/c-program-to-get-mac-address-from-interface-name-on-linux/

    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    host_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    ioctl(fd, SIOCGIFADDR, &ifr);
    host_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    
    close(fd);

    printMAC("HOST MAC", (unsigned char *)ifr.ifr_hwaddr.sa_data);
    printf("host ip: %s\n", inet_ntoa(host_ip));

}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    struct in_addr sender_ip;
    inet_pton(AF_INET, argv[2], &sender_ip.s_addr);

    struct in_addr target_ip;
    inet_pton(AF_INET, argv[3], &target_ip.s_addr);

    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char packet[42];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    unsigned char host_mac[6];
    struct in_addr host_ip;
    getMacAddr(dev, host_mac, host_ip);

    struct ether_header eth_header;
    memcpy(eth_header.ether_dhost, BROADCAST_DMAC, ETH_ALEN);
    memcpy(eth_header.ether_shost, host_mac, ETH_ALEN);
    eth_header.ether_type = htons(ETHERTYPE_ARP);

    memcpy(packet, &eth_header, sizeof(ether_header));
    int packet_len = sizeof(ether_header);

    struct arphdr arp_header;
    arp_header.ar_hrd = htons(ARPHRD_ETHER);
    arp_header.ar_pro = htons(ETHERTYPE_IP);
    arp_header.ar_hln = ETHER_ADDR_LEN;
    arp_header.ar_pln = IP_ADDR_LEN;
    arp_header.ar_op = htons(ARPOP_REQUEST);

    memcpy(packet + packet_len, &arp_header, sizeof(arp_header));
    packet_len += sizeof(arp_header);

    memcpy(packet + packet_len, host_mac, ETH_ALEN);
    packet_len += ETH_ALEN;
    memcpy(packet + packet_len, &host_ip, IP_ADDR_LEN);
    packet_len += IP_ADDR_LEN;
    memcpy(packet + packet_len, &ARP_REQUEST_TMAC, ETH_ALEN);
    packet_len += ETH_ALEN;
    memcpy(packet + packet_len, &sender_ip, IP_ADDR_LEN);
    packet_len += IP_ADDR_LEN;

    pcap_sendpacket(handle, packet, sizeof(packet));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pckt;

        int res = pcap_next_ex(handle, &header, &pckt);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("\n===============================\n");
        printf("%u bytes captured\n", header->caplen);

        struct ether_header* eth_header = (ether_header *)pckt;
        if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
            pckt += sizeof(struct ether_header);
            struct arphdr* arp_hdr = (arphdr *)pckt;

            if(ntohs(arp_hdr->ar_op) == ARPOP_REPLY){
                pckt += sizeof(struct arphdr);
                unsigned char target_mac[6];
                memcpy(target_mac, pckt, 6);
                printMAC("target_mac", target_mac);
                break;
            }
        }

    }

    pcap_close(handle);
    return 0;
}