#ifndef HTTPSNOOP_H
#define HTTPSNOOP_H

#include <vmlinux.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define IP_BUF_SIZE 16
#define THREAD_NAME_BUF_SIZE 16
#define METHOD_BUF_SIZE 8
#define RINGBUF_SIZE 1024
#define REQUEST_MAP_SIZE 1024
#define TARGET_BUF_SIZE 512

#define MAX_HTTP_SIZE 1500
#define MIN_HTTP_SIZE 12
#define MAX_HTTP_STATUS 599

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

struct http_exchange {
  pid_t tid;
  pid_t pid;
  u64 latency_ns;
  int status_code;
  char method[METHOD_BUF_SIZE];
  char thread_name[THREAD_NAME_BUF_SIZE];
  char server_ip[IP_BUF_SIZE];
  char client_ip[IP_BUF_SIZE];
  char target[TARGET_BUF_SIZE];
} __attribute__((packed));

struct request_map_key {
  u32 server_ip;
  u32 client_ip;
  u16 server_port;
  u16 client_port;
};

#define DECODE_TCP_PACKET(sk_buff_addr, ip, tcp, data, data_len, use_eth) \
  do {                                                                    \
    struct sk_buff skb = {};                                              \
    bpf_probe_read_kernel(&skb, sizeof(struct sk_buff), sk_buff_addr);    \
    data_len = skb.len;                                                   \
    data = (void*) (long) skb.data;                                       \
    if (use_eth) {                                                        \
      struct ethhdr eth = {};                                             \
      if (data_len < sizeof(struct ethhdr)) {                             \
        return EXIT_FAILURE;                                              \
      }                                                                   \
      data_len -= sizeof(struct ethhdr);                                  \
      bpf_probe_read_kernel(&eth, sizeof(struct ethhdr), data);           \
      data += sizeof(struct ethhdr);                                      \
      if (eth.h_proto != bpf_htons(ETH_P_IP)) {                           \
        return EXIT_FAILURE;                                              \
      }                                                                   \
    }                                                                     \
    if (data_len < sizeof(struct iphdr)) {                                \
      return EXIT_FAILURE;                                                \
    }                                                                     \
    bpf_probe_read_kernel(&ip, sizeof(struct iphdr), data);               \
    u8 ip_ihl = ip.ihl << 2;                                              \
    if (data_len < ip_ihl) {                                              \
      return EXIT_FAILURE;                                                \
    }                                                                     \
    data += ip_ihl;                                                       \
    data_len -= ip_ihl;                                                   \
    if (ip.protocol != IPPROTO_TCP) {                                     \
      return EXIT_FAILURE;                                                \
    }                                                                     \
    if (data_len < sizeof(struct tcphdr)) {                               \
      return EXIT_FAILURE;                                                \
    }                                                                     \
    bpf_probe_read_kernel(&tcp, sizeof(struct tcphdr), data);             \
    u8 tcp_doff = tcp.doff << 2;                                          \
    if (data_len < tcp_doff) {                                            \
      return EXIT_FAILURE;                                                \
    }                                                                     \
    data_len -= tcp_doff;                                                 \
    data += tcp_doff;                                                     \
  } while (0)
#endif
