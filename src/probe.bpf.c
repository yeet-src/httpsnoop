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
  __type(value, struct http_exchange);
} request_map SEC(".maps");

RINGBUF_CHANNEL(http_exchanges, RINGBUF_SIZE * sizeof(struct http_exchange), http_exchange);

static struct http_exchange empty = {};

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
      || str_compare(data, "PATCH /", 7)
      || str_compare(data, "DELETE /", 8)
      || str_compare(data, "HEAD /", 6)
      || str_compare(data, "OPTIONS /", 9)
      || str_compare(data, "CONNECT /", 9)
      || str_compare(data, "TRACE /", 7)) {
    return PACKET_TYPE_REQUEST;
  }

  if (str_compare(data, "HTTP/1", 6)) {
    return PACKET_TYPE_RESPONSE;
  }

  return EXIT_FAILURE;
}

static __always_inline void handle_response(struct iphdr ip, struct tcphdr tcp, char* buf, struct http_exchange* http_data)
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
    http_data->status_code = status;
  }
}

static __always_inline void handle_request(void* data, struct iphdr ip, struct tcphdr tcp, char* buf, struct http_exchange* http_data)
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
  bpf_probe_read_kernel_str(&http_data->target, sizeof(http_data->target), data);

  u16 j;
  for (j = 1; j < sizeof(http_data->target); j++) {
    if (http_data->target[j] == ' ') {
      http_data->target[j] = '\0';
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
  BPF_SNPRINTF(http_data->server_ip, 16, "%pI4", d_octets, 2);

  u32 sp = ip.saddr;
  u8 s_octets[] = {
    sp & 0xff,
    sp >> 8 & 0xff,
    sp >> 16 & 0xff,
    sp >> 24 & 0xff,
  };
  BPF_SNPRINTF(http_data->client_ip, 16, "%pI4", s_octets, 2);
}

SEC("tracepoint/net/net_dev_xmit")
int trace_egress(struct trace_event_raw_net_dev_xmit* ctx)
{
  void* sk_buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip_header = {};
  struct tcphdr tcp_header = {};
  void* data;
  int data_len;
  DECODE_TCP_PACKET(sk_buff_addr, ip_header, tcp_header, data, data_len, true);

  if (data_len > MAX_HTTP_SIZE || data_len < MIN_HTTP_SIZE) {
    return 0;
  }

  char buf[MIN_HTTP_SIZE] = {};
  bpf_probe_read_kernel(buf, MIN_HTTP_SIZE, data);
  u8 packet_type = is_http(buf);

  if (packet_type == PACKET_TYPE_REQUEST) {
    struct request_map_key key = {};
    key.client_ip = ip_header.saddr;
    key.server_ip = ip_header.daddr;
    key.client_port = tcp_header.source;
    key.server_port = tcp_header.dest;

    bpf_map_update_elem(&request_map, &key, &empty, BPF_ANY);
    struct http_exchange* request = bpf_map_lookup_elem(&request_map, &key);
    if (!request) {
      return EXIT_FAILURE;
    }

    handle_request(data, ip_header, tcp_header, buf, request);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    request->tid = pid_tgid;
    request->pid = pid_tgid >> 32;
    request->latency_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&request->thread_name, sizeof(request->thread_name));
    bpf_map_update_elem(&request_map, &key, request, BPF_ANY);
  }

  if (packet_type == PACKET_TYPE_RESPONSE) {
    struct request_map_key key = {};

    key.server_ip = ip_header.saddr;
    key.server_port = tcp_header.source;
    key.client_ip = ip_header.daddr;
    key.client_port = tcp_header.dest;

    struct http_exchange* request = bpf_map_lookup_elem(&request_map, &key);
    if (!request) {
      return EXIT_FAILURE;
    }

    struct http_exchange* exchange = bpf_ringbuf_reserve(&http_exchanges, sizeof(struct http_exchange), 0);
    if (!exchange) {
      return EXIT_FAILURE;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    exchange->tid = pid_tgid;
    exchange->pid = pid_tgid >> 32;
    exchange->latency_ns = bpf_ktime_get_ns() - request->latency_ns;
    bpf_get_current_comm(&exchange->thread_name, sizeof(exchange->thread_name));

    bpf_probe_read_kernel_str(&exchange->method, sizeof(exchange->method), &request->method);
    bpf_probe_read_kernel_str(&exchange->server_ip, sizeof(exchange->server_ip), &request->server_ip);
    bpf_probe_read_kernel_str(&exchange->client_ip, sizeof(exchange->client_ip), &request->client_ip);
    bpf_probe_read_kernel_str(&exchange->target, sizeof(exchange->target), &request->target);

    handle_response(ip_header, tcp_header, buf, exchange);

    bpf_ringbuf_submit(exchange, 0);
  }
  return EXIT_SUCCESS;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_ingress(struct trace_event_raw_net_dev_template* ctx)
{
  void* sk_buff_addr = BPF_CORE_READ(ctx, skbaddr);
  struct iphdr ip_header = {};
  struct tcphdr tcp_header = {};
  void* data;
  int data_len;
  DECODE_TCP_PACKET(sk_buff_addr, ip_header, tcp_header, data, data_len, false);

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
    key.client_ip = ip_header.saddr;
    key.server_ip = ip_header.daddr;
    key.client_port = tcp_header.source;
    key.server_port = tcp_header.dest;

    bpf_map_update_elem(&request_map, &key, &empty, BPF_ANY);
    struct http_exchange* request = bpf_map_lookup_elem(&request_map, &key);
    if (!request) {
      return EXIT_FAILURE;
    }

    handle_request(data, ip_header, tcp_header, buf, request);

    request->latency_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_map, &key, request, BPF_ANY);
  }

  if (packet_type == PACKET_TYPE_RESPONSE) {
    struct request_map_key key = {};
    // change order on receive
    key.server_ip = ip_header.saddr;
    key.server_port = tcp_header.source;
    key.client_ip = ip_header.daddr;
    key.client_port = tcp_header.dest;

    struct http_exchange* request = bpf_map_lookup_elem(&request_map, &key);
    if (!request) {
      return EXIT_FAILURE;
    }

    struct http_exchange* exchange = bpf_ringbuf_reserve(&http_exchanges, sizeof(struct http_exchange), 0);
    if (!exchange) {
      return EXIT_FAILURE;
    }

    exchange->tid = request->tid;
    exchange->pid = request->pid;
    exchange->latency_ns = bpf_ktime_get_ns() - request->latency_ns;

    bpf_probe_read_kernel_str(&exchange->method, sizeof(exchange->method), &request->method);
    bpf_probe_read_kernel_str(&exchange->thread_name, sizeof(exchange->thread_name), &request->thread_name);
    bpf_probe_read_kernel_str(&exchange->server_ip, sizeof(exchange->server_ip), &request->server_ip);
    bpf_probe_read_kernel_str(&exchange->client_ip, sizeof(exchange->client_ip), &request->client_ip);
    bpf_probe_read_kernel_str(&exchange->target, sizeof(exchange->target), &request->target);

    handle_response(ip_header, tcp_header, buf, exchange);

    bpf_ringbuf_submit(exchange, 0);
  }

  return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");
