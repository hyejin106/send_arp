#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define PRINT_MAC "%s - %02x:%02x:%02x:%02x:%02x:%02x\n"

static const uint8_t IP_ADDR_LEN = 0x04;
static  uint8_t ARP_REQUEST_TMAC[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t BROADCAST_DMAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

void usage() {
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp eth0 192.168.10.2 192.168.10.1\n");
}

void printMAC(const char* msg, unsigned char * target) {
    printf(PRINT_MAC, msg, target[0], target[1], target[2], target[3], target[4], target[5]);
}

void getMacAddr(char * dev, unsigned char * host_mac){

    // this func from
    // https://www.binarytides.com/c-program-to-get-mac-address-from-interface-name-on-linux/

    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    unsigned char * host_addr = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    memcpy(host_mac, host_addr, 6);
    printMAC("HOST MAC", host_mac);

    close(fd);
}

void getIPAddr(char * dev, struct in_addr * host_ip){

    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    ioctl(fd, SIOCGIFADDR, &ifr);
    *host_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    printf("HOST IP - %s\n", inet_ntoa(*host_ip));
    close(fd);
}

void sendArpPacket(pcap_t* handle, char * dev, int op, unsigned char * smac, struct in_addr sip, unsigned char * tmac, struct in_addr tip){
    unsigned char packet[42];

    struct ether_header eth_header;
    memcpy(eth_header.ether_dhost, BROADCAST_DMAC, ETH_ALEN);
    memcpy(eth_header.ether_shost, smac, ETH_ALEN);
    eth_header.ether_type = htons(ETHERTYPE_ARP);

    memcpy(packet, &eth_header, sizeof(ether_header));
    int packet_len = sizeof(ether_header);

    struct ether_arp ethernet_arp;
    ethernet_arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    ethernet_arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    ethernet_arp.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    ethernet_arp.ea_hdr.ar_pln = IP_ADDR_LEN;
    ethernet_arp.ea_hdr.ar_op = htons(op);
    memcpy(ethernet_arp.arp_sha, smac, ETH_ALEN);
    memcpy(ethernet_arp.arp_spa, &sip, IP_ADDR_LEN);
    memcpy(ethernet_arp.arp_tha, tmac, ETH_ALEN);
    memcpy(ethernet_arp.arp_tpa, &tip, IP_ADDR_LEN);

    memcpy(packet + packet_len, &ethernet_arp, sizeof(struct ether_arp));
    pcap_sendpacket(handle, packet, sizeof(packet));
}

int getSenderMac(pcap_t* handle, struct in_addr target_ip, unsigned char *sender_mac){
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
                memcpy(sender_mac, pckt, 6);
                printMAC("SENDER MAC", sender_mac);
                return 0;
            }
        }
    }
    return -1;
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
    getMacAddr(dev, host_mac);
    getIPAddr(dev, &host_ip);

    sendArpPacket(handle, dev, ARPOP_REQUEST, host_mac, host_ip, ARP_REQUEST_TMAC, sender_ip);

    unsigned char sender_mac[6];
    getSenderMac(handle, target_ip, sender_mac);

    sendArpPacket(handle, dev, ARPOP_REPLY, host_mac, target_ip, sender_mac, sender_ip);

    pcap_close(handle);
    return 0;
}