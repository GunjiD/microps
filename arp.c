#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

#define ARP_HRD_ETHER 0x0001

#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32

// ARPキャッシュの状態を表す定数
#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

struct arp_hdr {
  uint16_t hrd;
  uint16_t pro;
  uint8_t hln;
  uint8_t pln;
  uint16_t op;
};

// ARPキャッシュの構造体
struct arp_cache {
  unsigned char state;        // キャッシュの状態
  ip_addr_t pa;               // プロトコルアドレス
  uint8_t ha[ETHER_ADDR_LEN]; // ハードウェアアドレス
  struct timeval timestamp;   // 最終更新時刻
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; // ARPキャッシュの配列

struct arp_ether_ip {
  struct arp_hdr hdr;
  uint8_t sha[ETHER_ADDR_LEN];
  uint8_t spa[IP_ADDR_LEN];
  uint8_t tha[ETHER_ADDR_LEN];
  uint8_t tpa[IP_ADDR_LEN];
};

static char *
arp_opcode_ntoa(uint16_t opcode)
{
  switch (ntoh16(opcode)) {
  case ARP_OP_REQUEST:
    return "Request";
  case ARP_OP_REPLY:
    return "Reply";
  }
  return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
  struct arp_ether_ip *message;
  ip_addr_t spa, tpa;
  char addr[128];

  message = (struct arp_ether_ip *)data;
  flockfile(stderr);
  fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
  fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
  fprintf(stderr, "        hln: %u\n", message->hdr.hln);
  fprintf(stderr, "        pln: %u\n", message->hdr.pln);
  fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
  fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
  memcpy(&spa, message->spa, sizeof(spa));
  fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
  fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
  memcpy(&tpa, message->tpa, sizeof(tpa));
  fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));  
  
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  
  funlockfile(stderr);
}

/*
 * ARP Cache
 *
 * NOTE: ARP Cache Functions must be called after mutex locked
*/

static void
arp_cache_delete(struct arp_cache *cache)
{
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

  cache->state = ARP_CACHE_STATE_FREE;
  cache->pa = 0;
  memset(cache->ha, 0, ETHER_ADDR_LEN);
  timerclear(&cache->timestamp);
}

static struct arp_cache *
arp_cache_alloc(void)
{
  struct arp_cache *entry, *oldest = NULL;

  for (entry = caches; entry < tailof(caches); entry++) {
    // 使用されていないエントリを返す
    if (entry->state == ARP_CACHE_STATE_FREE) {
      return entry;
    }
    // 空きがなかったときのために一番古いエントリも一緒に探す
    if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
      oldest = entry;
    }
  }

  // 現在登録されている内容を削除する
  // 空きがなかったら一番古いエントリを返す
  arp_cache_delete(oldest);
  return oldest;
}

static struct arp_cache *
arp_cache_select(ip_addr_t pa)
{
  struct arp_cache *entry;
  
  for (entry = caches; entry < tailof(caches); entry++) {
    // FREE状態ではないエントリから探す
    if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) {
      return entry;
    }
  }

  return NULL;
}

static struct arp_cache *
arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  // エントリを検索しなければNULLを返す
  cache = arp_cache_select(pa);
  if (!cache) {
    return NULL;
  }

  cache->state = ARP_CACHE_STATE_RESOLVED;
  memcpy(cache->ha, ha, ETHER_ADDR_LEN);
  gettimeofday(&cache->timestamp, NULL);
  
  debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),  ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

static struct arp_cache *
arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  cache = arp_cache_alloc();
  if (!cache) {
    return NULL;
  }

  // エントリの情報を設定する
  cache->state = ARP_CACHE_STATE_RESOLVED;
  cache->pa = pa;
  memcpy(cache->ha, ha, ETHER_ADDR_LEN);
  gettimeofday(&cache->timestamp, NULL);

  debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),  ether_addr_ntop(ha, addr2, sizeof(addr2)));
  return cache;
}

static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
  struct arp_ether_ip request;

  // ARPヘッダ領域の設定
  request.hdr.hrd = hton16(ARP_HRD_ETHER);
  request.hdr.pro = hton16(ARP_PRO_IP);
  request.hdr.hln = ETHER_ADDR_LEN;
  request.hdr.pln = IP_ADDR_LEN;
  request.hdr.op = hton16(ARP_OP_REQUEST);
  // 可変領域の設定
  memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
  memset(request.tha,  0, ETHER_ADDR_LEN);
  memcpy(request.tpa, &tpa, IP_ADDR_LEN);

  debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
  arp_dump((uint8_t *)&request, sizeof(request));
  
  return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);

}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
  struct arp_ether_ip reply;

  // ARPヘッダ領域の設定
  reply.hdr.hrd = hton16(ARP_HRD_ETHER);
  reply.hdr.pro = hton16(ARP_PRO_IP);
  reply.hdr.hln = ETHER_ADDR_LEN;
  reply.hdr.pln = IP_ADDR_LEN;
  reply.hdr.op = hton16(ARP_OP_REPLY);
  // 可変領域の設定
  memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
  memcpy(reply.tha, tha, ETHER_ADDR_LEN);
  memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

  debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
  arp_dump((uint8_t *)&reply, sizeof(reply));
  
  return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
  struct arp_ether_ip *msg;
  ip_addr_t spa, tpa;
  struct net_iface *iface;
  int marge = 0;

  // 期待するARPメッセージのサイズより小さかったらエラーを返す
  if (len < sizeof(*msg)) {
    errorf("too short");
    return;
  }

  msg = (struct arp_ether_ip *)data;

  // ハードウェアアドレスのチェック
  if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
    errorf("does not match hardware address: 0x%04x or hardware length: %u", ntoh16(msg->hdr.hrd), msg->hdr.hln);
    return;
  }
  
  // プロトコルアドレスのチェック
  if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
    errorf("does not match protocol: 0x%04x or address length: %u", ntoh16(msg->hdr.pro), msg->hdr.pln);
    return;
  }

  debugf("dev=%s, len=%zu", dev->name, len);
  arp_dump(data, len);

  // spa/tpaをmemcpy()でip_addr_tの変数へ取り出す
  memcpy(&spa, msg->spa, sizeof(spa));
  memcpy(&tpa, msg->tpa, sizeof(tpa));
  
  mutex_lock(&mutex);
  // ARPメッセージを受信したら、まず送信元アドレスのキャッシュ情報を更新する
  if (arp_cache_update(spa, msg->sha)) {
    /* updated */
    marge = 1;
  }
  mutex_unlock(&mutex);
  
  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);

  // ARP要求のターゲットプロトコルアドレスと一致するか確認
  if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
    // 先の処理で送信元アドレスのキャッシュ情報が更新されていなければ送信元アドレスのキャッシュ情報を新規登録する
    if (!marge) {
      mutex_lock(&mutex);
      arp_cache_insert(spa, msg->sha);
      mutex_unlock(&mutex);
    }
    if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
      arp_reply(iface, msg->sha, spa, msg->sha);
    }
  }
}

int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
  struct arp_cache *cache;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[ETHER_ADDR_STR_LEN];

  // 物理デバイスと論理インターフェースがそれぞれEthernetとIPであることを確認
  if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
    debugf("unsupported hardware address type");
    return ARP_RESOLVE_ERROR;
  }

  if (iface->family != NET_IFACE_FAMILY_IP) {
    debugf("unsupported protocol address type");
    return ARP_RESOLVE_ERROR;
  }

  mutex_lock(&mutex);
  // プロトコルアドレスをキーにARPキャッシュを検索
  cache = arp_cache_select(pa);
  if(!cache) {
    // ARPキャッシュに問い合わせ中のエントリを作成
    debugf("cache not found pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
    cache = arp_cache_alloc();
    if (!cache) {
      mutex_unlock(&mutex);
      errorf("arp_cache_unlock() failure");
      return ARP_RESOLVE_ERROR;
    }
    
    cache->state = ARP_CACHE_STATE_INCOMPLETE;
    cache->pa = pa;
    gettimeofday(&cache->timestamp, NULL);
    mutex_unlock(&mutex);
    
    arp_request(iface, pa);
    return ARP_RESOLVE_INCOMPLETE;
  }

  // 見つかったエントリがINCOMPLETEの場合はパケロスしている可能性があるため再送する
  if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
    mutex_unlock(&mutex);
    arp_request(iface, pa);
    return ARP_RESOLVE_INCOMPLETE;
  }

  // 見つかったハードウェアアドレスをコピー
  memcpy(ha, cache->ha, ETHER_ADDR_LEN);
  mutex_unlock(&mutex);
  debugf("resolved pa=%s, ha=%s",
	 ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
  
  return ARP_RESOLVE_FOUND;
}

int
arp_init(void)
{
  if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1){
    errorf("net_protocol_register() failure");
    return -1;
  }

  return 0;
}
