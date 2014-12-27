#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

#include "tcp_base.h"
#include "tcp_state.h"

#define BITS 20
#define HASH_TABLE_SIZE (1 << BITS)
#define RTT_BITS 10
#define RTT_HASH_TABLE_SIZE (1 << RTT_BITS)

struct hash_table_entry {
	struct tcp_state *ts;
	struct hash_table_entry *next;
};

struct rtt_hash_table_entry {
	struct time_stamp *ts;
	struct rtt_hash_table_entry *next;
};
struct rtt_hash_table_entry **new_rtt_hash_table();
struct time_stamp *find_rtt_entry(struct rtt_hash_table_entry **hash_table, struct time_stamp ts);
int insert_rtt_entry(struct rtt_hash_table_entry **hash_table, struct time_stamp *ts);
int delete_rtt_entry(struct rtt_hash_table_entry **hash_table, struct time_stamp ts);
void cleanup_rtt_hash_table(struct rtt_hash_table_entry **hash_table);

struct hash_table_entry **new_hash_table();
struct tcp_state *find_ts_entry(struct hash_table_entry **hash_table, struct tcp_key *key);
int insert_ts_entry(struct hash_table_entry **hash_table, struct tcp_state *ts);
int delete_ts_entry(struct hash_table_entry **hash_table, struct tcp_state *ts);
void cleanup_hash_table(struct hash_table_entry **hash_table);

#endif
