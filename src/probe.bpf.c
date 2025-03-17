#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <yeet/yeet.h>

#include "httpsnoop.h"

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, REQUEST_MAP_SIZE);
  __type(key, struct request_map_key);
  __type(value, struct http_query);
} request_map SEC(".maps");

RINGBUF_CHANNEL(http_queries, RINGBUF_SIZE * sizeof(struct http_query), http_query);

static struct http_query empty = {};

int str_compare(char* str1, char* str2, int max)
{
  int i;
  for (i = 0; i < max; i++) {
    if (str1[i] != str2[i]) {
      return 0;
    }
    if (str1[i] == '\0')
      return i;
  }
  return 1;
}

static __always_inline u8 is_http(char* data)
{
  if (str_compare(data, "GET /", 5)
      || str_compare(data, "POST /", 6)
      || str_compare(data, "PUT /", 5)
      || str_compare(data, "DELETE /", 8)) {
    return PACKET_TYPE_REQUEST;
  }

  if (str_compare(data, "HTTP/1", 6)) {
    return PACKET_TYPE_RESPONSE;
  }

  return EXIT_FAILURE;
}

static __always_inline void handle_response(struct iphdr ip, struct tcphdr tcp, char* buf, struct http_query* http_data)
{
  int i;
  int first_space = 0;
  bool first = true;
  for (i = 0; i < MIN_HTTP_SIZE; i++) {
    if (buf[i] == ' ') {
      if (!first) {
        break;
      }
      first_space = i + 1;
      first = false;
    }
  }
  buf[i] = '\0';

  if (first_space + 2 < MIN_HTTP_SIZE) {
    int status = 0;
    status += (buf[first_space] - '0') * 100;
    status += (buf[first_space + 1] - '0') * 10;
    status += (buf[first_space + 2] - '0');
    http_data->status = status;
  }
}

static __always_inline void handle_request(void* data, struct iphdr ip, struct tcphdr tcp, char* buf, struct http_query* http_data)
{
  int i;
  for (i = 0; i < MIN_HTTP_SIZE; i++) {
    if (buf[i] == '/') {
      break;
    }
  }
  // set the / in buffer to null so we can use bpf_probe_read_kernel_str to get the method <METHOD> /<ROUTE>
  buf[i - 1] = '\0';
  data += i;

  bpf_probe_read_kernel_str(&http_data->method, sizeof(http_data->method), buf);
  bpf_probe_read_kernel_str(&http_data->request, sizeof(http_data->request), data);

  u16 j;
  for (j = 1; j < sizeof(http_data->request); j++) {
    if (http_data->request[j] == ' ') {
      http_data->request[j] = '\0';
      break;
    }
  }

  u32 dp = ip.daddr;
  u8 d_octets[] = {
    dp & 0xff,
    dp >> 8 & 0xff,
    dp >> 16 & 0xff,
    dp >> 24 & 0xff,
  };
  BPF_SNPRINTF(http_data->dest_ip, 16, "%pI4", d_octets, 2);

  u32 sp = ip.saddr;
  u8 s_octets[] = {
    sp & 0xff,
    sp >> 8 & 0xff,
    sp >> 16 & 0xff,
    sp >> 24 & 0xff,
  };
  BPF_SNPRINTF(http_data->source_ip, 16, "%pI4", s_octets, 2);
}

SEC("tracepoint/net/net_dev_xmit")
int trace_egress(struct trace_event_raw_net_dev_xmit* ctx)
{
  void* buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip = {};
  struct tcphdr tcp = {};
  void* data;
  int data_len;
  DECODE_TCP_PACKET(buff_addr, ip, tcp, data, data_len, true);

  if (data_len > MAX_HTTP_SIZE || data_len < MIN_HTTP_SIZE) {
    return 0;
  }

  char buf[MIN_HTTP_SIZE] = {};
  bpf_probe_read_kernel(buf, MIN_HTTP_SIZE, data);
  u8 packet_type = is_http(buf);

  if (packet_type == PACKET_TYPE_REQUEST) {
    struct request_map_key key = {};
    key.source_ip = ip.saddr;
    key.dest_ip = ip.daddr;
    key.source_port = tcp.source;
    key.dest_port = tcp.dest;

    bpf_map_update_elem(&request_map, &key, &empty, BPF_ANY);
    struct http_query* cached = bpf_map_lookup_elem(&request_map, &key);
    if (!cached) {
      return EXIT_FAILURE;
    }

    handle_request(data, ip, tcp, buf, cached);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    cached->pid = pid_tgid;
    cached->tgid = pid_tgid >> 32;
    cached->latency_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&cached->comm, sizeof(cached->comm));
    bpf_map_update_elem(&request_map, &key, cached, BPF_ANY);
  }

  if (packet_type == PACKET_TYPE_RESPONSE) {
    struct request_map_key key = {};

    key.dest_ip = ip.saddr;
    key.dest_port = tcp.source;
    key.source_ip = ip.daddr;
    key.source_port = tcp.dest;

    struct http_query* cached = bpf_map_lookup_elem(&request_map, &key);
    if (!cached) {
      return EXIT_FAILURE;
    }

    struct http_query* ret = bpf_ringbuf_reserve(&http_queries, sizeof(struct http_query), 0);
    if (!ret) {
      return EXIT_FAILURE;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ret->pid = pid_tgid;
    ret->tgid = pid_tgid >> 32;
    ret->latency_ns = bpf_ktime_get_ns() - cached->latency_ns;
    bpf_get_current_comm(&ret->comm, sizeof(ret->comm));

    bpf_probe_read_kernel_str(&ret->method, sizeof(ret->method), &cached->method);
    bpf_probe_read_kernel_str(&ret->dest_ip, sizeof(ret->dest_ip), &cached->dest_ip);
    bpf_probe_read_kernel_str(&ret->source_ip, sizeof(ret->source_ip), &cached->source_ip);
    bpf_probe_read_kernel_str(&ret->request, sizeof(ret->request), &cached->request);

    handle_response(ip, tcp, buf, ret);

    bpf_ringbuf_submit(ret, 0);
  }
  return EXIT_SUCCESS;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_ingress(struct trace_event_raw_net_dev_template* ctx)
{
  void* buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip = {};
  struct tcphdr tcp = {};
  void* data;
  int data_len;
  DECODE_TCP_PACKET(buff_addr, ip, tcp, data, data_len, false);

  if (data_len > MAX_HTTP_SIZE || data_len < MIN_HTTP_SIZE) {
    return 0;
  }

  char buf[MIN_HTTP_SIZE] = {};
  int rval = bpf_probe_read_kernel(buf, MIN_HTTP_SIZE, data);
  if (rval < 0) {
    return EXIT_FAILURE;
  }

  u8 packet_type = is_http(buf);

  if (packet_type == PACKET_TYPE_REQUEST) {
    struct request_map_key key = {};
    key.source_ip = ip.saddr;
    key.dest_ip = ip.daddr;
    key.source_port = tcp.source;
    key.dest_port = tcp.dest;

    bpf_map_update_elem(&request_map, &key, &empty, BPF_ANY);
    struct http_query* cached = bpf_map_lookup_elem(&request_map, &key);
    if (!cached) {
      return EXIT_FAILURE;
    }

    handle_request(data, ip, tcp, buf, cached);

    cached->latency_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_map, &key, cached, BPF_ANY);
  }

  if (packet_type == PACKET_TYPE_RESPONSE) {
    struct request_map_key key = {};
    // change order on receive
    key.dest_ip = ip.saddr;
    key.dest_port = tcp.source;
    key.source_ip = ip.daddr;
    key.source_port = tcp.dest;

    struct http_query* cached = bpf_map_lookup_elem(&request_map, &key);
    if (!cached) {
      return EXIT_FAILURE;
    }

    struct http_query* ret = bpf_ringbuf_reserve(&http_queries, sizeof(struct http_query), 0);
    if (!ret) {
      return EXIT_FAILURE;
    }

    ret->pid = cached->pid;
    ret->tgid = cached->tgid;
    ret->latency_ns = bpf_ktime_get_ns() - cached->latency_ns;

    bpf_probe_read_kernel_str(&ret->method, sizeof(ret->method), &cached->method);
    bpf_probe_read_kernel_str(&ret->comm, sizeof(ret->comm), &cached->comm);
    bpf_probe_read_kernel_str(&ret->dest_ip, sizeof(ret->dest_ip), &cached->dest_ip);
    bpf_probe_read_kernel_str(&ret->source_ip, sizeof(ret->source_ip), &cached->source_ip);
    bpf_probe_read_kernel_str(&ret->request, sizeof(ret->request), &cached->request);

    handle_response(ip, tcp, buf, ret);

    bpf_ringbuf_submit(ret, 0);
  }

  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");