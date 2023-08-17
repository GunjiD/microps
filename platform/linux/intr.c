#include <bits/time.h>
#include <bits/types/struct_itimerspec.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

// 割り込み要求(IRQ) 
struct irq_entry {
  struct irq_entry *next;                      // 次のIRQ構造体へのポインタ
  unsigned int irq;                            // 割り込み番号(IRQ番号)
  int (*handler)(unsigned int irq, void *dev); // 割り込みハンドラ(割り込みが発生した際に呼び出す関数へのポインタ)
  int flags;                                   // フラグ(INTR_IRQ_SHAREDが指定された場合はIRQ番号を共有可能)
  char name[16];                               // デバッグ出力で識別するための名前
  void *dev;                                   // 割り込みの発生元となるデバイス(struct net_device 以外にも対応できるように void * で保持)
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to protect these lists with a mutex */ 
static struct irq_entry *irqs; // IRQリスト

static sigset_t sigmask; // シグナル集合

static pthread_t tid;
static pthread_barrier_t barrier;

int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
  struct irq_entry *entry;

  debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
  for (entry = irqs; entry; entry = entry->next) {
    // IRQ番号が既に登録されている場合、IRQ番号の共有が許可されているかチェック
    if (entry->irq == irq) {
      if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
	errorf("conflicts with already registerd IRQs");
	return -1;
      }
    }
  }

  // IRQリストへ新しいエンリを追加
  entry = memory_alloc(sizeof(*entry));
  if (!entry) {
    errorf("memory_alloc() failure");
    return -1;
  }
  entry->irq = irq;
  entry->handler = handler;
  entry->flags = flags;
  strncpy(entry->name, name, sizeof(entry->name)-1);
  entry->dev = dev;
  entry->next = irqs;
  irqs = entry;
  sigaddset(&sigmask, irq);
  debugf("registerd: irq=%u, name=%s", irq, name);

  return 0;
}

int
intr_raise_irq(unsigned int irq)
{
  return pthread_kill(tid, (int)irq);
}

static int
intr_timer_setup(struct itimerspec *interval)
{
  timer_t id;

  // タイマーの作成
  if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
    errorf("timer_create: %s", strerror(errno));
    return -1;
  }

  // インターバルの設定
  if (timer_settime(id, 0, interval, NULL) == -1) {
    errorf("timer_settime: %s", strerror(errno));
    return -1;
  }

  return 0;
}

static void *
intr_thread(void *arg)
{
  // インターバルの値
  const struct timespec ts = {0, 1000000}; /* lms */
  struct itimerspec interval = {ts, ts};
  
  int terminate = 0, sig, err;
  struct irq_entry *entry;

  debugf("start...");

  // メインスレッドと同期をとるための処理
  pthread_barrier_wait(&barrier);
  if (intr_timer_setup(&interval) == -1) {
    errorf("intr_timer_setup() failure");
    return NULL;
  }
  
  while (!terminate) {
    err = sigwait(&sigmask, &sig);
    if (err) {
      errorf("sigwait() %s", strerror(err));
      break;
    }
    switch(sig) {
    case SIGHUP:
      // 割nnnnり込みスレッドへ終了を通知するためのシグナル
      terminate = 1;
      break;
    case SIGUSR1:
      net_softirq_handler();
      break;
    case SIGUSR2:
      net_event_handler();
      break;
    case SIGALRM:
      // 周期処理用のタイマーが発火した際の処理
      net_timer_handler();
      break;
    default:
      for (entry = irqs; entry; entry = entry->next) {
	// IRQ番号が一致するエントリの割り込みハンドラを呼び出す
	if (entry->irq == (unsigned int)sig) {
	  debugf("irq=%d, name=%s", entry->irq, entry->name);
	  entry->handler(entry->irq, entry->dev);
	}
      }
      break;
    }
  }

  debugf("terminated");
  return NULL;
}

int
intr_run(void)
{
  int err;

  // シグナルマスクの設定
  err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
  if (err) {
    errorf("pthread_sigmask() %s", strerror(err));
    return -1;
  }
  
  // 割り込み処理スレッドの起動
  err = pthread_create(&tid, NULL, intr_thread, NULL);
  if (err) {
    errorf("pthread_create() %s", strerror(err));
    return -1;
  }

  // スレッドが動き出すまで待つ
  pthread_barrier_wait(&barrier);
  
  return 0;
}

void
intr_shutdown(void)
{
  if (pthread_equal(tid, pthread_self()) != 0) {
    /* Thread not created. */
    return;
  }
  pthread_kill(tid, SIGHUP);
  pthread_join(tid, NULL);
}

int
intr_init(void)
{
  tid = pthread_self();
  pthread_barrier_init(&barrier, NULL, 2);
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGHUP);
  sigaddset(&sigmask, SIGUSR1);
  sigaddset(&sigmask, SIGUSR2);
  sigaddset(&sigmask, SIGALRM);
  
  return  0;
}
