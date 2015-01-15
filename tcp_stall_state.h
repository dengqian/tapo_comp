#ifndef __TCP_STALL_STATE_H__
#define __TCP_STALL_STATE_H__

#include "tcp_base.h"
#include "list.h"
#include <stdio.h>

struct tcp_state;

struct tcp_stall_state {
	int max_snd_seg_size;
	//int ca_state;
	// length of the last in packet 
	int cur_len;
	int last_dir;
	int tail;

	double cur_time;
	double duration;
	double srtt;
	double rto;
	double ack_delay_time;
	double third_dup_ack_time;
	
	uint32_t seq_base;
	uint32_t snd_una;
	uint32_t snd_nxt;
	//duration from ack_snt to seq_rcv exceed timeout
	uint32_t rcv_nxt;
	uint32_t rcv_una;

	int sacked;
	int spurious;
	int retrans;
	int cur_pkt_retrans;
	int cur_pkt_spurious;
	int cur_pkt_dir;

	struct list_head list;
};

static inline int inside (uint32_t seq1, uint32_t seq2, uint32_t seq3) 
{
	return seq3 - seq2 >= seq1 - seq2;
}
void init_tcp_stall(struct tcp_state *ts, struct tcp_stall_state *tss, double duration);
void fill_tcp_stall_list(struct tcp_state *ts, struct list_head *stall_list);
void dump_tss_info(FILE *fp, struct tcp_stall_state *tss);

#endif
