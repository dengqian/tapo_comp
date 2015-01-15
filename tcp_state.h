#ifndef __TCP_STATE_H__
#define __TCP_STATE_H__

#include "tcp_base.h"
#include "tcp_options.h"
#include "tcp_range_list.h"

#include "def.h"

#include <stdio.h>

#define IS_SYN(th) th->syn
#define IS_RST(th) th->rst
#define IS_FIN(th) th->fin
#define IS_ACK(th) !(th->syn || th->rst || th->fin)

#define TCP_CA_OPEN 0
#define TCP_CA_RECOVERY 1

extern const char *tcp_ca_state[];
struct seq_dup_time {
	uint32_t ack_seq;
	double time;
};
struct tcp_state {
	struct tcp_key key;
	char name[128];

	int pkt_cnt;
	int state;

	struct tcp_option option;
	// time related
	double last_in_time;
	double last_out_time;
	double start_time;
	double last_time;
	double transfer_time;

	struct seq_dup_time third_dup_ack_time;
	int dup_ack_cnt;

	int retrans_flag;
	int tail;
	int last_len;
	int last_dir;

	uint32_t seq_base;
	uint32_t max_snd_seg_size;

	uint32_t snd_nxt;
	uint32_t snd_una;
	uint32_t rcv_nxt; // largest ack_snt
	uint32_t rcv_una; // seq of the incomming pkt
	uint32_t last_in_seq;
	uint32_t last_out_ack;

	// list
	struct list_head disorder_list;
	struct list_head retrans_list;
	struct list_head reordering_list;
	struct list_head spurious_retrans_list;

	// time list 
	struct list_head in_time_list;
	struct list_head out_time_list;
	struct list_head estimate_time_list;

	// stall related
	struct list_head stall_list;
	int stall_cnt;

	struct rtt_t rtt;
	struct rtt_hash_table_entry **tsp_table;
};

struct tcp_state *new_tcp_state(struct tcp_key *key, double time);
int tcp_state_machine(struct tcp_state *ts, struct tcphdr *th, int len, double cap_time, int dir);
void finish_tcp_state(struct tcp_state *ts);
void dump_ts_info(FILE *fp, struct tcp_state *ts);

#endif
