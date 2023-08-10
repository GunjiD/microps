#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEVICE_TYPE_DUMMY     0x0000
#define NET_DEVICE_TYPE_LOOPBACK  0x0001
#define NET_DEVICE_TYPE_ETHERNET  0x0002

#define NET_DEVICE_FLAG_UP        0x0001
#define NET_DEVICE_FLAG_LOOPBACK  0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P       0x0040
#define NET_DEVICE_FLAG_NEED_ARP  0x0100

#define NET_DEVICE_ADDR_LEN 16

#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

struct net_device {
  struct net_device *next;             // 次のデバイスへのポインタ
  unsigned int index;
  char name[IFNAMSIZ];
  uint16_t type;                       // デバイスの種別 (net.h に NET_DEVICE_TYPE_XXXとして定義)
  uint16_t mtu;                        // デバイスのMTU(Maximum Transmission Unit)
  uint16_t flags;                      // 各種フラグ(net.hにNET_DEVICE_FLAG_XXXとして定義) 
  uint16_t hlen;                       /* header length */
  uint16_t alen;                       /* address length */
  uint16_t addr[NET_DEVICE_ADDR_LEN];
  union{
    uint8_t peer[NET_DEVICE_ADDR_LEN];
    uint8_t broadcast[NET_DEVICE_ADDR_LEN];
  };
  struct net_device_ops *ops;          // デバイスドライバに実装されている関数が設定された struct net_device_ops へのポインタ
  void *priv;                          // デバイスドライバが使うプライベートなデータへのポインタ
};

// デバイスドライバに実装されている関数へのポインタを格納
// 送信関数(transmit)は必須、それ以外の関数は任意
struct net_device_ops {
  int (*open)(struct net_device *dev);
  int (*close)(struct net_device *dev);
  int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

extern struct net_device *
net_device_alloc(void);
extern int
net_device_register(struct net_device *dev);
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

extern int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);

extern int
net_run(void);
extern void
net_shutdown(void);
extern int
net_init(void);

#endif
