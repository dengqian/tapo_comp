#include "tcp_state.h"
#include "tcp_rtt.h"
#include "malloc.h"
#include "tcp_sack.h"
#include "log.h"
#include "def.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define DELTA 2

const char *tcp_ca_state[] = { "TCP_CA_OPEN", "TCP_CA_RECOVERY" };

static inline void dump_list(FILE *fp, const char *fmt, \
		struct tcp_state *ts, struct list_head *list);
// valid state: TCP_CLOSE, TCP_SYN_RECV, TCP_SYN_SENT, TCP_ESTABLISHED, TCP_FIN_WAIT1, TCP_FIN_WAIT2 }
// 				TCP_LISTEN
struct tcp_state *new_tcp_state(struct tcp_key *key, double time)
{
	struct tcp_state *ts = MALLOC(struct tcp_state);

	// all the variables have been set to 0

	memcpy(&ts->key, key, sizeof(struct tcp_key));
	sprintf(ts->name, "%s.%hu", inet_ntoa(key->addr[1]), ntohs(key->port[1]));


	init_list_head(&ts->disorder_list);
	init_list_head(&ts->retrans_list);
	init_list_head(&ts->reordering_list);
	init_list_head(&ts->spurious_retrans_list);
	init_list_head(&ts->in_time_list);
	init_list_head(&ts->estimate_time_list);

	return ts;
}

//delete related node from retrans_list and add it to reordering_list
void update_retrans_and_reorder(struct tcp_state *ts, uint32_t seq)
{
	struct list_head *node;
	uint32_t begin, end;
	if((node = find_node_by_seq(&ts->reordering_list, seq)) != NULL){
		struct range_t *range = list_entry(node, struct range_t, list);
		begin = range->begin;
		end = range->end;
		FREE(range);
		list_delete_entry(node);
		append_to_range_list(&ts->reordering_list, begin, end);
	}
}

//get_third_seq in disorder_list
int get_third_seq(struct list_head *list) 
{
	struct list_head *pos;
	struct range_t *range;
	int cnt = 0;
	list_for_each(pos, list) {
		cnt++;
		if(cnt == 3) {
			range = list_entry(pos, struct range_t, list);
			return range->begin;
		}
	}
	return 0;
}
static void handle_in_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	uint32_t seq = ntohl(th->seq);
			// ack_seq = ntohl(th->ack_seq);
	double estimate_time = time;
	FILE *fp = stdout;
	//fprintf(fp, "last_seq:%d, seq:%d\n", ts->last_seq, seq);

	if (seq > ts->ack_snt) {
		// insert into disorder_list orderly
		insert_to_range_list(&ts->disorder_list, seq, seq+len);
		// calculate the time we estimate it arrives
		if (get_time_by_seq(ts->ack_snt, &ts->estimate_time_list) == 0) {
			estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((ts->ack_snt - ts->last_seq)*1.0 / (seq - ts->last_seq));
			insert_seq_rtt(ts->ack_snt, estimate_time, &ts->estimate_time_list);
		}
	} else if (seq == ts->ack_snt && ts->last_seq > seq) {
		uint32_t b, e;
		int l;
		uint32_t third_seq;
		double third_dup_time = time;
		// time gap > rtt -> retrans
		if ((third_seq = get_third_seq(&ts->disorder_list)) != 0) {
			third_dup_time = get_time_by_seq(third_seq, &ts->in_time_list);
		}
		estimate_time = get_time_by_seq(seq, &ts->estimate_time_list);
		if (estimate_time == 0)
			estimate_time = time;
	
		//dump_list(fp, "disorder_list:", ts, &ts->disorder_list);
		if (time-third_dup_time > ts->syn_rtt || time-estimate_time > DELTA*ts->syn_rtt) {
			l = get_retrans(seq, &ts->disorder_list, &b, &e);
			if (l > 0)
				append_to_range_list(&ts->retrans_list, b, e);
		} else {
			append_to_range_list(&ts->reordering_list, seq, seq+len);
		}
		struct range_t *range = MALLOC(struct range_t);
		range = list_entry(&ts->disorder_list, struct range_t, list);
		// smallest seq in disorder_list is larger than seq+len
		if (range->begin > seq+len && ts->last_seq > seq+len) {
			estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((ts->last_seq - seq - len)*1.0 / (ts->last_seq - seq));
			insert_seq_rtt(seq+len, estimate_time, &ts->estimate_time_list);
			//fprintf(fp, "seq: %d, estimate_time: %lf\n", seq+len-ts->seq_base, estimate_time-ts->start_time);
		} 
		delete_ordered_node(&ts->disorder_list, seq+len);
	} else if(seq < ts->ack_snt){
		append_to_range_list(&ts->spurious_retrans_list, seq, seq+len);
		update_retrans_and_reorder(ts, seq);
	} 
}

static void handle_out_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	//uint32_t seq = ntohl(th->seq);
	uint32_t ack_seq = ntohl(th->ack_seq);
	ts->ack_snt = ack_seq;
	if(IS_SYN(th)) {
		ts->syn_ack_time = time;
	}
	delete_node_before_seq(&ts->disorder_list, ack_seq);
}

int tcp_state_machine(struct tcp_state *ts, struct tcphdr *th, int len, double cap_time, int dir)
{
	uint32_t seq = ntohl(th->seq);
	uint32_t ack_seq = ntohl(th->ack_seq);
	ts->pkt_cnt += 1;
	FILE * fp = stdout;
	//fprintf(fp, "seq:%d\n", seq);
	if (dir == DIR_IN && ts->state == TCP_SYN_SENT) {
		// calculate rtt 
		ts->ack_syn_time = cap_time;
		ts->syn_rtt = ts->ack_syn_time - ts->syn_ack_time;
	}
	if (dir == DIR_IN && IS_SYN(th)) {
		// client may reestablish a connection
		ts->state = TCP_SYN_RECV;
		ts->start_time = cap_time;
		ts->seq_base = seq;
		ts->ack_snt = seq;
		//fprintf(fp, "TCP_SYN_RECV, seq_base:%d\n", seq);
	}
	else if (IS_RST(th)) {
		// both can drop the connection by RST
		ts->state = TCP_CLOSING;
	}
	else {
		switch (ts->state) {
			case TCP_LISTEN:
				if (dir == DIR_IN && IS_SYN(th))
					ts->state = TCP_SYN_RECV;
				break;
			case TCP_SYN_RECV:
				if (dir == DIR_OUT && IS_SYN(th)) {
					ts->state = TCP_SYN_SENT;
				}
				break;
			case TCP_SYN_SENT:
				if (dir == DIR_IN && IS_ACK(th)) {
					ts->state = TCP_ESTABLISHED;
				}
				break;
			case TCP_ESTABLISHED:
				if (IS_RST(th)) {
					ts->state = TCP_CLOSING;
				}
				else if (IS_FIN(th)) {
					if (dir == DIR_IN) 
						ts->state = TCP_FIN_WAIT1;
					else
						ts->state = TCP_FIN_WAIT2;
				}
				break;
			case TCP_FIN_WAIT1:
				if (dir == DIR_OUT && ack_seq == ts->rcv_una)
					ts->state = TCP_CLOSE;
				break;
			case TCP_FIN_WAIT2:
				if (dir == DIR_IN && ack_seq == ts->snd_nxt)
					ts->state = TCP_CLOSE;
				break;
			case TCP_CLOSING:
				// do nothing here, wait for the timeout
				break;
			default:
				LOG(ERROR, "unknown tcp state: %d.\n", ts->state);
				break;
		}
	}

	get_tcp_option(th, &ts->options);

	if (ts->state == TCP_CLOSING || ts->state == TCP_CLOSE)
		return 0;

	if (dir == DIR_IN && IS_SYN(th)) {
		ts->start_time = cap_time;
	}

	if (dir == DIR_OUT) {
		handle_out_pkt(ts, th, cap_time, len);
	}
	else {
		handle_in_pkt(ts, th, cap_time, len);
	}

	if (dir == DIR_IN) {
		ts->last_in_time = cap_time;
		// record in_time to the list
		//if(seq > ts->seq_base)
		insert_seq_rtt(seq, cap_time, &ts->in_time_list);
		ts->last_seq = seq;
	}

	return 0;
}

static inline void dump_list(FILE *fp, const char *fmt, \
		struct tcp_state *ts, struct list_head *list)
{
	struct list_head *p;
	struct range_t *r;
	fprintf(fp, fmt);
	list_for_each(p, list) {
		r = list_entry(p, struct range_t, list);
		fprintf(fp, " (%d,%d)", 
				(r->begin - ts->seq_base), 
			   (r->end - ts->seq_base));
		
	}
	fprintf(fp, "\n");
}


static inline void dump_time_list(FILE *fp, const char *fmt, \
		struct tcp_state *ts, struct list_head *list)
{
	struct list_head *p;
	struct seq_rtt_t *r;
	fprintf(fp, fmt);
	list_for_each(p, list) {
		r = list_entry(p, struct seq_rtt_t, list);
		fprintf(fp, " (%d,%lf)", 
				r->ack_seq - ts->seq_base, 
			   	r->time - ts->start_time);
		
	}
	fprintf(fp, "\n");
}
/*
void dump_tss_list(FILE *fp, struct list_head *list)
{
	struct list_head *pos;
	struct tcp_stall_state *tss;
	list_for_each(pos, list) {
		tss = list_entry(pos, struct tcp_stall_state, list);
		dump_tss_info(fp, tss);
		enum stall_type type = parse_stall(tss);
		fprintf(fp, "%s: \"%s\"\n", stall_text[type], stall_details[type]);
	}
}
*/

void dump_ts_info(FILE *fp, struct tcp_state *ts)
{
	dump_time_list(fp, "in_time:", ts, &ts->in_time_list);
	//dump_time_list(fp, "estimate_time", ts, &ts->estimate_time_list);
	dump_list(fp, "retrans:", ts, &ts->retrans_list);
	dump_list(fp, "reorder:", ts, &ts->reordering_list);
	dump_list(fp, "spurious:", ts, &ts->spurious_retrans_list);
	//dump_list(fp, "lost:", ts, &ts->lost_list);
	fprintf(fp, "%s: \"%d\"\n", "pkt_cnt", ts->pkt_cnt);
	fprintf(fp, "%s: \"%lf\"\n\n", "rtt", ts->syn_rtt);
	//fprintf(fp, "%s: \"%d\"\n", "seq_base", ts->seq_base);
}

static void free_tcp_state(struct tcp_state *ts)
{
	//delete_rtt_list(&ts->rtt_list);

	delete_list(&ts->retrans_list, struct range_t, list);
	//delete_list(&ts->block_list, struct range_t, list);
	delete_list(&ts->reordering_list, struct range_t, list);
	delete_list(&ts->spurious_retrans_list, struct range_t, list);
	//delete_list(&ts->lost_list, struct range_t, list);
	delete_list(&ts->disorder_list, struct range_t, list);
	//delete_list(&ts->stall_list, struct tcp_stall_state, list);
	delete_rtt_list(&ts->in_time_list);

	FREE(ts);
}

void finish_tcp_state(struct tcp_state *ts)
{
	/*struct list_head *pos;
	list_for_each(pos, &ts->in_time_list) {
		struct seq_rtt_t *time_node = list_entry(pos, struct seq_rtt_t, list);
		time_node->ack_seq -= ts->seq_base;
		time_node->time -= ts->start_time;
	}*/
	/*if (ts->max_snd_seg_size != 0) {
		get_lost_list(ts);
		get_reord_list(ts);

		fill_tcp_stall_list(ts, &ts->stall_list);

		FILE *fp = stdout;

		fprintf(fp, "name: %s\n", ts->name);
		fprintf(fp, "#(stalls): %d\n", ts->stall_cnt);
		dump_ts_info(fp, ts);
		// dump tss info
		dump_tss_list(fp, &ts->stall_list);
	}*/
	FILE *	fp = stdout;
	fprintf(fp, "name: %s\n", ts->name);
	dump_ts_info(fp, ts);
	free_tcp_state(ts);
}
