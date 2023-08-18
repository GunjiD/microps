#include <asm-generic/errno-base.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "net.h"
#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct pseudo_hdr {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

struct udp_hdr {
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t sum;
};

// コントロールブロックの構造体
struct udp_pcb {
  int state;
  struct ip_endpoint local; // 自分のアドレス&ポート番号
  struct queue_head queue;  /* receive queue */
  struct sched_ctx ctx;     // スケジューラが使うコンテキスト
};

// 受信キューのエントリの構造体
struct udp_queue_entry {
  struct ip_endpoint foreign; // 送信元のアドレス&ポート番号
  uint16_t len;
  uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void
udp_dump(const uint8_t *data, size_t len)
{
  struct udp_hdr *hdr;

  flockfile(stderr);
  hdr = (struct udp_hdr *)data;
  fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
  fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
  fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
  fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
  
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
    
  funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB Functions must be called after mutex locked
 */

static struct udp_pcb *
udp_pcb_alloc(void)
{
  struct udp_pcb *pcb;

  // 使用されていないPCBを探して返す
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
    if (pcb->state == UDP_PCB_STATE_FREE) {
      pcb->state = UDP_PCB_STATE_OPEN;
      sched_ctx_init(&pcb->ctx);
      return pcb;
    }
  }
  
  return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
  struct queue_entry *entry;

  // PCBの状態をクローズ中にする
  pcb->state = UDP_PCB_STATE_CLOSING;

  // クローズされたことを休止中のタスクに知らせるために起床させる
  if (sched_ctx_destroy(&pcb->ctx) == -1) {
    sched_wakeup(&pcb->ctx);
    return;
  }

  // 値をクリア
  pcb->state = UDP_PCB_STATE_FREE;
  pcb->local.addr = IP_ADDR_ANY;
  pcb->local.port = 0;

  while (1) { /* Discard the entries in the queue. */
    entry = queue_pop(&pcb->queue);
    if (!entry) {
      break;
    }
    memory_free(entry);
  }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
  struct udp_pcb *pcb;

  for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
    // OPEN状態のPCBのみが対象
    if (pcb->state == UDP_PCB_STATE_OPEN) {
      // IPアドレスとポート番号が一致するPCBを探して返す
      // IPアドレスがワイルドカードの場合、全てのアドレスに対して一致の判定を下す
      if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) {
	return pcb;
      }  
    }
  }
  
  return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
  struct udp_pcb *pcb;

  if (id < 0 || id >= (int)countof(pcbs)) {
    /* out of range */
    return NULL;
  }

  pcb = &pcbs[id];
  if (pcb->state != UDP_PCB_STATE_OPEN) {
    return NULL;
  }

  return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
  return indexof(pcbs, pcb);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct pseudo_hdr pseudo;
  uint16_t psum = 0;
  struct udp_hdr *hdr;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  struct udp_pcb *pcb;
  struct udp_queue_entry *entry;

  // ヘッダサイズに満たないデータはエラーとする
  if (len < sizeof(*hdr)) {
    errorf("too short");
    return;
  }

  hdr = (struct udp_hdr *)data;

  // IPから渡されたデータ長とUDPヘッダに含まれるデータグラム長が一致しない場合はエラー
  if (len != ntoh16(hdr->len)) {
    errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
    return;
  }

  // チェックサム計算のために疑似ヘッダを準備
  pseudo.src = src;
  pseudo.dst = dst;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_UDP;
  pseudo.len = hton16(len);

  // チェックサムの計算結果はビット反転されているので戻す
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
  
  if (cksum16((uint16_t *)hdr, len, psum) != 0) {
    errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
    return;
  }

  debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
	 ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
	 ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
	 len, len - sizeof(*hdr));
  udp_dump(data, len);

  mutex_lock(&mutex);
  
  pcb = udp_pcb_select(dst, hdr->dst);
  if (!pcb) {
    /* port is not in use */
    mutex_unlock(&mutex);
    return;
  }
  
  entry = memory_alloc(sizeof(*entry) + (len - sizeof(*hdr)));
  if (!entry) {
    mutex_unlock(&mutex);
    errorf("memory_alloc() failure");
    return;
  }

  // エントリの各項目に値を設定しデータをコピー
  entry->foreign.addr = src;
  entry->foreign.port = hdr->src;
  entry->len = len - sizeof(*hdr);
  memcpy(entry->data, hdr + 1, entry->len);

  // 受信キューにエントリをプッシュ
  if (!queue_push(&pcb->queue, entry)) {
    mutex_unlock(&mutex);
    errorf("queue_push() failure");
    return;
  }

  debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->queue.num);
  sched_wakeup(&pcb->ctx);
  mutex_unlock(&mutex);
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
  uint8_t buf[IP_PAYLOAD_SIZE_MAX];
  struct udp_hdr *hdr;
  struct pseudo_hdr pseudo;
  uint16_t total, psum = 0;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  // IPのペイロードに載せきれないほど大きなデータが渡されたらエラーを返す
  if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
    errorf("too long");
    return -1;
  }
  hdr = (struct udp_hdr *)buf;
  
  hdr->src = src->port;
  hdr->dst = dst->port;
  total = sizeof(*hdr) + len;
  hdr->len = hton16(total);
  hdr->sum = 0;
  memcpy(hdr + 1, data, len);

  // チェックサム計算のために疑似ヘッダを準備
  pseudo.src = src->addr;
  pseudo.dst = dst->addr;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_UDP;
  pseudo.len = hton16(total);

  // 疑似ヘッダのチェックサムを計算
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);

  // チェックサム計算
  hdr->sum = cksum16((uint16_t *)hdr, total, psum);

  debugf("%s => %s, len=%zu (payload=%zu)",
	 ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
  udp_dump((uint8_t *)hdr, total);

  if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
    errorf("ip_output() failure");
    return -1;
  }
  
  return len;
}

static void
event_handler(void *arg)
{
  struct udp_pcb *pcb;

  (void)arg;
  mutex_lock(&mutex);
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
    // 有効なPCBのコンテキスト全てに割り込みを発生させる
    if (pcb->state == UDP_PCB_STATE_OPEN) {
      sched_interrupt(&pcb->ctx);      
    }
  }
  mutex_unlock(&mutex);
}

int
udp_init(void)
{
  if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1) {
    errorf("ip_protocol_register() failure");
    return -1;
  }

  // イベントの購読
  if (net_event_subscribe(event_handler, NULL) == -1) {
    errorf("net_event_subscribe() failure");
    return -1;
  }

  return 0;
}

/*
 * UDP User Commands
 */

int
udp_open(void)
{
  struct udp_pcb *pcb;
  int id;

  mutex_lock(&mutex);
  pcb = udp_pcb_alloc();
  if (!pcb) {
    errorf("udp_pcb_alloc() failure");
    mutex_unlock(&mutex);
    return -1;
  }

  id = udp_pcb_id(pcb);
  mutex_unlock(&mutex);
  return id;
}

int
udp_close(int id)
{
  struct udp_pcb *pcb;

  mutex_lock(&mutex);
  pcb = udp_pcb_get(id);
  if (!pcb) {
    errorf("udp_pcb_get() failure");
    mutex_unlock(&mutex);
    return -1;
  }

  udp_pcb_release(pcb);
  mutex_unlock(&mutex);
  
  return 0;
}

int
udp_bind(int id, struct ip_endpoint *local)
{
  struct udp_pcb *pcb, *exist;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  mutex_lock(&mutex);

  // IDからPCBのポインタを取得
  pcb = udp_pcb_get(id);
  if (!pcb) {
    errorf("udp_pcb_get() failure");
    mutex_unlock(&mutex);
    return -1;
  }

  // PCBを検索し見つかったらエラーを返す
  exist = udp_pcb_select(local->addr, local->port);
  if (exist) {
    mutex_unlock(&mutex);
    return -1;
  }

  // pcb->localにlocalの値をコピー
  pcb->local = *local;

  debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
  mutex_unlock(&mutex);
  return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
  struct udp_pcb *pcb;
  struct ip_endpoint local;
  struct ip_iface *iface;
  char addr[IP_ADDR_STR_LEN];
  uint32_t p;

  mutex_lock(&mutex);

  // IDからPCBのポインタを取得
  pcb = udp_pcb_get(id);
  if (!pcb) {
    errorf("pcb not found, id =%d", id);
    mutex_unlock(&mutex);
    return -1;
  }


  local.addr = pcb->local.addr;

  // 自分の使うアドレスがワイルドカードだったら宛先アドレスに応じて送信元アドレスを自動的に選択する
  if (local.addr == IP_ADDR_ANY) {
    iface = ip_route_get_iface(foreign->addr);
    if (!iface) {
      errorf("iface not found that can reach foreign address, addr=%s",
	     ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
      mutex_unlock(&mutex);
      return -1;
    }

    local.addr = iface->unicast;
    debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
  }

  // 自分の使うポート番号が設定されていなかったら送信元ポートを自動的に選択する
  if (!pcb->local.port) {
    for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
      if (!udp_pcb_select(local.addr, hton16(p))) {
	pcb->local.port = hton16(p);
	debugf("dinamic assign local port, port=%d", p);
	break;
      }
    }
    // 使用可能なポートがなかったらエラーを返す
    if (!pcb->local.port) {
      debugf("failed to dinamic assign local port, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
      mutex_unlock(&mutex);
      return -1;
    }
  }

  local.port = pcb->local.port;
  mutex_unlock(&mutex);
  
  return udp_output(&local, foreign, data, len);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
  struct udp_pcb *pcb;
  struct udp_queue_entry *entry;
  ssize_t len;
  int err;

  mutex_lock(&mutex);
  
  pcb = udp_pcb_get(id);
  if (!pcb) {
    errorf("pcb not found, id=%d", id);
    mutex_unlock(&mutex);
    return -1;
  }

  // 受信キューからエントリを取り出す
  while (1) {
    entry = queue_pop(&pcb->queue);
    if (entry) {
      break;
    }

    /* Wait to be woken up by sched_wakeup() or sched_interrupt() */
    err = sched_sleep(&pcb->ctx, &mutex, NULL);
    // エラーだった場合はsched_interrup()による起床なのでerrnoにEINTRを設定してエラーを返す
    if (err) {
      debugf("interrupted");
      mutex_unlock(&mutex);
      errno = EINTR;
      return -1;
    }

    if (pcb->state == UDP_PCB_STATE_CLOSING) {
      debugf("closed");
      udp_pcb_release(pcb);
      mutex_unlock(&mutex);
      return -1;
    }
  }

  mutex_unlock(&mutex);
  if (foreign) {
    *foreign = entry->foreign;
  }
  
  // バッファが小さければ切り詰めて格納する
  len = MIN(size, entry->len); /* truncate */
  memcpy(buf, entry->data, len);
  memory_free(entry);
  
  return len;
}
