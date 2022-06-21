#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>
#include <string.h>
#include "list.h"

struct sns_msg {
	uint16_t txn_id;
	int msg_id;
	int service;
	int port;

	struct list_head li;
};

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

void print_hex_dump(const char *prefix, const void *buf, size_t len);

#define sns_msg_get_by_txn(list, _txn)                                       \
	({                                                                     \
		struct sns_msg *msg, *out = NULL;                            \
		list_for_each_entry(msg, (list), li)                           \
		{                                                              \
			if (msg->txn_id == _txn) {                                \
				out = msg;                                     \
				break;                                         \
			};                                                     \
		}                                                              \
		out;                                                           \
	})

#endif