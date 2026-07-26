/*
 * raw_capture.c -- Raw Socket Packet Capture and Protocol Investigation
 * ISEA Phase III Networking Internship -- Assignment 3
 *
 * Captures live IP traffic using an AF_PACKET raw socket, decodes the
 * Ethernet + IP header of every frame, and -- for the protocol assigned
 * to this student by roll-number rule -- prints the required field
 * summary for at least 20 matching packets.
 *
 * Roll number last digit -> assigned protocol:
 *     0-3 -> ICMP      4-6 -> UDP      7-9 -> TCP
 *
 * Build:
 *     gcc raw_capture.c -o raw_capture
 * Run (requires root -- raw sockets need CAP_NET_RAW):
 *     sudo ./raw_capture --roll 2201234 --iface eth0 --count 20 --extra ttl_id
 *
 * Output format (one block per matched packet):
 *     ROLL_NO=...
 *     ASSIGNED_PROTOCOL=...
 *     PACKET_NO=...
 *     SRC_IP=...
 *     DST_IP=...
 *     PROTOCOL=...
 *     PROTOCOL_NO=...
 *     TTL=...
 *     PACKET_SIZE=...
 *     ADDITIONAL_FIELD=...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#define BUF_SIZE 65536

typedef enum { PROTO_ICMP = 1, PROTO_UDP = 17, PROTO_TCP = 6 } assigned_proto_t;

static assigned_proto_t assign_protocol(const char *roll_no) {
    size_t len = strlen(roll_no);
    char last_char = roll_no[len - 1];
    int digit = last_char - '0';
    if (digit >= 0 && digit <= 3) return PROTO_ICMP;
    if (digit >= 4 && digit <= 6) return PROTO_UDP;
    return PROTO_TCP; /* 7-9 */
}

static const char *proto_name(assigned_proto_t p) {
    switch (p) {
        case PROTO_ICMP: return "ICMP";
        case PROTO_UDP:  return "UDP";
        case PROTO_TCP:  return "TCP";
        default:         return "UNKNOWN";
    }
}

/* Extra IP-header field selector for Task 5 */
typedef enum { EXTRA_NONE, EXTRA_VERSION, EXTRA_IHL, EXTRA_ID, EXTRA_TOS, EXTRA_FRAG } extra_field_t;

static extra_field_t parse_extra(const char *s) {
    if (!s) return EXTRA_NONE;
    if (strcmp(s, "version") == 0) return EXTRA_VERSION;
    if (strcmp(s, "ihl") == 0)     return EXTRA_IHL;
    if (strcmp(s, "id") == 0)      return EXTRA_ID;
    if (strcmp(s, "tos") == 0)     return EXTRA_TOS;
    if (strcmp(s, "frag") == 0)    return EXTRA_FRAG;
    return EXTRA_NONE;
}

static void print_extra_field(extra_field_t field, const struct iphdr *ip) {
    switch (field) {
        case EXTRA_VERSION: printf("IP_VERSION=%u\n", ip->version); break;
        case EXTRA_IHL:     printf("HEADER_LENGTH_WORDS=%u\n", ip->ihl); break;
        case EXTRA_ID:       printf("IDENTIFICATION=%u\n", ntohs(ip->id)); break;
        case EXTRA_TOS:      printf("TYPE_OF_SERVICE=%u\n", ip->tos); break;
        case EXTRA_FRAG:     printf("FRAGMENT_OFFSET=%u\n", ntohs(ip->frag_off) & 0x1FFF); break;
        default: break;
    }
}

int main(int argc, char *argv[]) {
    char roll_no[64] = "0000000";
    char iface[IFNAMSIZ] = "any";
    int target_count = 20;
    extra_field_t extra_field = EXTRA_NONE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--roll") == 0 && i + 1 < argc) {
            strncpy(roll_no, argv[++i], sizeof(roll_no) - 1);
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            strncpy(iface, argv[++i], sizeof(iface) - 1);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            target_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--extra") == 0 && i + 1 < argc) {
            extra_field = parse_extra(argv[++i]);
        }
    }

    assigned_proto_t assigned = assign_protocol(roll_no);
    fprintf(stderr, "[INFO] ROLL_NO=%s -> ASSIGNED_PROTOCOL=%s\n", roll_no, proto_name(assigned));
    fprintf(stderr, "[INFO] Listening on interface '%s' for at least %d %s packets...\n",
            iface, target_count, proto_name(assigned));

    /* AF_PACKET + ETH_P_IP gives us full Ethernet frames for ANY IP
     * traffic on the chosen interface, independent of the L4 protocol --
     * we then filter by ip->protocol in userspace against the assignment. */
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock_fd < 0) {
        perror("socket() -- did you run this with sudo?");
        return EXIT_FAILURE;
    }

    if (strcmp(iface, "any") != 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl(SIOCGIFINDEX)");
            close(sock_fd);
            return EXIT_FAILURE;
        }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_IP);
        if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind()");
            close(sock_fd);
            return EXIT_FAILURE;
        }
    }

    unsigned char *buffer = malloc(BUF_SIZE);
    int matched_count = 0;

    while (matched_count < target_count) {
        ssize_t n = recvfrom(sock_fd, buffer, BUF_SIZE, 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        if ((size_t)n < sizeof(struct ethhdr) + sizeof(struct iphdr)) continue;

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (ip->protocol != (uint8_t)assigned) continue; /* not our assigned protocol */

        matched_count++;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        printf("ROLL_NO=%s\n", roll_no);
        printf("ASSIGNED_PROTOCOL=%s\n", proto_name(assigned));
        printf("PACKET_NO=%d\n", matched_count);
        printf("SRC_IP=%s\n", src_ip);
        printf("DST_IP=%s\n", dst_ip);
        printf("PROTOCOL=%s\n", proto_name(assigned));
        printf("PROTOCOL_NO=%d\n", ip->protocol);
        printf("TTL=%d\n", ip->ttl);
        printf("PACKET_SIZE=%d\n", ntohs(ip->tot_len));

        size_t ip_header_len = ip->ihl * 4;
        unsigned char *l4 = (unsigned char *)ip + ip_header_len;

        if (assigned == PROTO_ICMP) {
            struct icmphdr *icmp = (struct icmphdr *)l4;
            printf("ICMP_TYPE=%d\n", icmp->type);
            printf("ICMP_CODE=%d\n", icmp->code);
        } else if (assigned == PROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)l4;
            printf("SRC_PORT=%d\n", ntohs(udp->source));
            printf("DST_PORT=%d\n", ntohs(udp->dest));
        } else if (assigned == PROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)l4;
            printf("SRC_PORT=%d\n", ntohs(tcp->source));
            printf("DST_PORT=%d\n", ntohs(tcp->dest));
            printf("TCP_FLAGS=%s%s%s%s%s%s\n",
                   tcp->syn ? "SYN " : "", tcp->ack ? "ACK " : "",
                   tcp->fin ? "FIN " : "", tcp->rst ? "RST " : "",
                   tcp->psh ? "PSH " : "", tcp->urg ? "URG " : "");
        }

        if (extra_field != EXTRA_NONE) {
            print_extra_field(extra_field, ip);
        }
        printf("\n");
        fflush(stdout);
    }

    free(buffer);
    close(sock_fd);
    fprintf(stderr, "[INFO] Captured %d matching packets. Exiting.\n", matched_count);
    return EXIT_SUCCESS;
}
