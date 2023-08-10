#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct net_protocol {
  struct net_protocol *next; 
  uint16_t type;
  struct queue_head queue; /* input queue */
  void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry {
  struct net_device *dev;
  size_t len;
  uint8_t data[];
};

/* NOTE: if you want to add/delete the entries after net_run(),  you need to protect these lists with a mutex */
static struct net_device *devices; // デバイスリスト(リストの先頭を指すポインタ)
static struct net_protocol *protocols; // 登録されているプロトコルのリスト

// デバイス構造体のサイズのメモリを確保
// ・memory_alloc() で確保したメモリ領域は0で初期化されている
// ・メモリが確保できなかったらエラーとしてNULLを返す
struct net_device *
net_device_alloc(void)
{
  struct net_device *dev;

  dev = memory_alloc(sizeof(*dev));
  if (!dev) {
    errorf("memory_alloc() failure");
    return NULL;
  }
  return dev;
}

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
  static unsigned int index = 0;

  dev->index = index++; // デバイスのインデックス番号を設定
  snprintf(dev->name, sizeof(dev->name), "net%d", dev->index); // デバイス名を生成(net0, net1, net2...)
  dev->next = devices;
  devices = dev;
  infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
  return 0;
}

static int
net_device_open(struct net_device *dev)
{
  // デバイスの状態を確認
  if (NET_DEVICE_IS_UP(dev)) {
    errorf("already opened, dev=%s", dev->name);
    return -1;
  }

  // デバイスドライバのオープン関数を呼び出す
  if (dev->ops->open) {
    if (dev->ops->open(dev) == -1) {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }

  // UPフラグを立てる
  dev->flags |= NET_DEVICE_FLAG_UP;
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

static int
net_device_close(struct net_device *dev)
{
  // デバイスの状態を確認
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }

  // デバイスドライバのクローズ関数を呼び出す
  if (dev->ops->close) {
    if (dev->ops->close(dev) == -1) {
      errorf("failure, dev=%s", dev->name);
      return -1;
    }
  }

  // UPフラグを落とす
  dev->flags &= ~NET_DEVICE_FLAG_UP;
  infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
  return 0;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
  // デバイスの状態を確認しUP状態でなければ送信できないのでエラーを返す
  if (!NET_DEVICE_IS_UP(dev)) {
    errorf("not opened, dev=%s", dev->name);
    return -1;
  }

  // データのサイズを確認
  if (len > dev->mtu) {
    errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
    return -1;
  }

  debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
  debugdump(data, len);

  if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
    errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
    return -1;
  }
  
  return 0;
}

/* NOTE: must not be call after net_run() */
int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *, size_t, struct net_device *))
{
  struct net_protocol *proto;

  // 重複登録の確認
  for (proto = protocols; proto; proto = proto->next) {
    if (type == proto->type) {
      errorf("already registered, type=0x%04x", type);
      return -1;
    }
  }

  // プロトコル構造体のメモリを確保
  proto = memory_alloc(sizeof(*proto));
  if (!proto) {
    errorf("memory_alloc() failure");
    return -1;
  }

  // プロトコル種別と入力関数を設定
  proto->type = type;
  proto->handler = handler;

  // プロトコルリストの先頭に追加
  proto->next = protocols;
  protocols = proto;

  infof("registered, type=0x%04x", type);
  
  return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
  struct net_protocol *proto;
  struct net_protocol_queue_entry *entry;

  for(proto = protocols; proto; proto = proto->next) {
    if (proto->type == type) {
      // 新しいエントリのメモリを確保
      entry = memory_alloc(sizeof(*entry) + len);
      if (!entry) {
	errorf("memory_alloc() failure");
	return -1;
      }

      // 新しいエントリへメタデータの設定と受信データのコピー
      entry->len = len;
      entry->dev = dev;
      memcpy(entry->data, data, len);

      // キューに新しいエントリを挿入
      queue_push(&proto->queue, entry);
      
      debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
	     proto->queue.num, dev->name, type, len);
      debugdump(data, len);
      return 0;
    }
  }
  /* unsupported protocols */
  return 0;
}

int net_run(void)
{
  struct net_device *dev;

  //  割り込み機構の起動
  if (intr_run() == -1) {
    errorf("intr_run() failure");
    return -1;
  }

  debugf("open all devices...");

  // 登録済みの全デバイスをオープン
  for(dev = devices; dev; dev = dev->next) {
    net_device_open(dev);
  }
  debugf("running...");
  return 0;
}

void
net_shutdown(void)
{
  struct net_device *dev;

  debugf("close all devices...");
  for (dev = devices; dev; dev = dev->next) {
    net_device_close(dev);
  }

  intr_shutdown();
  debugf("shutting down");
}

int
net_init(void)
{
  if (intr_init() == -1) {
    errorf("intr_init() failure");
    return -1;
  }

  if (ip_init() == -1) {
    errorf("ip_init() failure");
    return -1;
  }
  
  infof("initialized");
  return 0;
}

