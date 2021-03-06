#include "tcp_state.h"
#include "tcp_rtt.h"
#include "malloc.h"
#include "tcp_sack.h"
#include "tcp_stall_state.h"
#include "rule_parser.h"
#include "hash_table.h"
#include "log.h"
#include "def.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define DELTA 2
#define TRIPLE 3

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
	ts->state = TCP_LISTEN;
	ts->ca_state = TCP_CA_OPEN;

	init_rtt(&ts->rtt);	

	init_list_head(&ts->disorder_list);
	init_list_head(&ts->retrans_list);
	init_list_head(&ts->reordering_list);
	init_list_head(&ts->spurious_retrans_list);
	init_list_head(&ts->in_time_list);
	init_list_head(&ts->out_time_list);
	init_list_head(&ts->estimate_time_list);
	init_list_head(&ts->stall_list);

	// ts->tsp_table = new_rtt_hash_table();

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
// return the first ack'out time which acknowledges seq
double get_first_ack_time(struct list_head *list, uint32_t seq) 
{
	struct list_head *pos;
	struct list_head *pre_pos;
	struct seq_rtt_t *t_node;
	struct seq_rtt_t *pre_node;
	list_for_each_prev (pos, list) {
		t_node = list_entry(pos, struct seq_rtt_t, list);
		pre_pos = pos->prev;
		pre_node = list_entry(pre_pos, struct seq_rtt_t, list);
		if(t_node->ack_seq > seq && pre_node->ack_seq <= seq)
			return t_node->time;
	}
	return 0;
}
//get ack_delay_time according to in and out time list
double get_ack_delay_time(struct tcp_state *ts, uint32_t seq)
{
	struct list_head *in_pos = find_node_by_seq(&ts->in_time_list, seq);
	struct seq_rtt_t *node;
	double ack_time;
	if (in_pos != NULL) {
		node = list_entry(in_pos, struct seq_rtt_t, list);
		ack_time = get_first_ack_time(&ts->out_time_list, seq);
		return ack_time - node->time;
	}
	return 0;
}
//get_third_seq in disorder_list
/*int get_third_seq(struct list_head *list) 
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
}*/

//get the number of bytes reordered, record reorder begin and end
int get_reorder(uint32_t seq, struct list_head *list, uint32_t *b, uint32_t *e)
{
	struct list_head *reord_node = list->next;
	*b = seq;
	*e = seq;
	while (reord_node != list) {
		struct range_t *reord = list_entry(reord_node, struct range_t, list);
		if(before(reord->begin, *b))
			*b = reord->begin;
		if(after(reord->end, *e))
			*e = reord->end;
		reord_node = reord_node->next;
	}
	return *e - *b;
}

int get_retrans(struct tcp_state *ts, uint32_t seq, struct list_head *list, uint32_t *b, uint32_t *e)
{
	// FILE *fp = stdout;
	struct list_head *pos = list;
	struct range_t *range = list_entry(list, struct range_t, list);
	*b = seq;
	*e = range->begin;
	list_for_each (pos, list) {
		range = list_entry(pos, struct range_t, list);
		*e = range->begin < *e ? range->begin : *e;
	}

	return *e - *b;
}

//update rtt useing time_stamp 
void update_rtt_with_time_stamp(uint32_t seq, struct tcp_state *ts, struct time_stamp *tsp)
{
	uint32_t rtt = ts->option.ts.ts_val - tsp->ts_ecr;
	update_rtt(&ts->rtt, rtt);
}

//insert into list ordered by seq
static void handle_in_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	uint32_t seq = ntohl(th->seq),
			 ack_seq = ntohl(th->ack_seq);
	double estimate_time = time;
	int disorder_num = 0;

	ts->snd_una = ack_seq;
	ts->rcv_una = seq;
	ts->rcv_max = MAX(ts->rcv_max, seq + len);

	ts->max_snd_seg_size = MAX(ts->max_snd_seg_size, len);
	disorder_num=get_list_item_num(&ts->disorder_list);
	
	if (ts->ca_state == TCP_CA_OPEN && ts->state == TCP_ESTABLISHED &&  seq+len < ts->rcv_max && disorder_num > 1) {
		ts->ca_state = TCP_CA_RECOVERY;
		ts->recovery_point = ts->rcv_max;
	}
	
	if (seq > ts->rcv_nxt && seq > 1) {
		append_to_range_list(&ts->disorder_list, seq, seq+len);
		// calculate the time we estimate pkt with seq rcv_nxt arrives
		if (get_time_by_seq(ts->rcv_nxt, &ts->estimate_time_list) == 0) {
			estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((ts->rcv_nxt - ts->last_in_seq)*1.0 / (seq - ts->last_in_seq));
			insert_seq_rtt(ts->rcv_nxt, estimate_time, &ts->estimate_time_list);
			uint32_t tmp_seq = ts->rcv_nxt;
			// LOG(DEBUG, "%d, %d, %d\n", ts->rcv_nxt, seq,  ts->max_snd_seg_size);
			while (ts->max_snd_seg_size > 0 && tmp_seq + ts->max_snd_seg_size < seq) {
				estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((tmp_seq - ts->last_in_seq)*1.0 / (seq - ts->last_in_seq));
				insert_seq_rtt(tmp_seq, estimate_time, &ts->estimate_time_list);
				tmp_seq += ts->max_snd_seg_size;
				// LOG(DEBUG, "%d, %d, in cycling...", ts->rcv_nxt, ts->max_snd_seg_size);
			}
		}
		else if (ts->max_snd_seg_size > 0 && seq > ts->last_in_seq + ts->max_snd_seg_size) {
			uint32_t tmp_seq = ts->last_in_seq + ts->max_snd_seg_size;
			while (tmp_seq + ts->max_snd_seg_size < seq) {
				estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((tmp_seq - ts->last_in_seq)*1.0 / (seq - ts->last_in_seq));
				insert_seq_rtt(tmp_seq, estimate_time, &ts->estimate_time_list);
				tmp_seq += ts->max_snd_seg_size;
			}
		}
	} else if (seq == ts->rcv_nxt && (disorder_num) > 0) {
		uint32_t b, e; 
		int l;
		double third_dup_time = time;
		if (disorder_num >= 2 || ts->last_in_seq - seq > ts->max_snd_seg_size) {
		/*	l = get_retrans(ts, seq, &ts->disorder_list, &b, &e);
			if(l > 0)
				append_to_range_list(&ts->retrans_list, b, e);*/
			append_to_range_list(&ts->retrans_list, seq, seq+len);
		} else {
			// if (ts->ca_state == TCP_CA_RECOVERY && ts->)
			if (ts->rcv_nxt == ts->third_dup_ack_time.ack_seq)
 				third_dup_time = ts->third_dup_ack_time.time;
			estimate_time = get_time_by_seq(seq, &ts->estimate_time_list);
			if (estimate_time == 0)
				estimate_time = time;
	
			if (time-third_dup_time > TICK_TO_TIME(ts->rtt.srtt >> 3) || time-estimate_time > MAX(TICK_TO_TIME(ts->rtt.srtt >> 3 * TRIPLE), 0.2)) {
			 	append_to_range_list(&ts->retrans_list, seq, seq+len);
				/*l = get_retrans(ts, seq, &ts->disorder_list, &b, &e);
				if(l > 0)
					append_to_range_list(&ts->retrans_list, b, e);*/
			} else {
				l = get_reorder(seq, &ts->disorder_list, &b, &e);
				if(l>0)
					append_to_range_list(&ts->reordering_list, b, e);
			}
		}
	
		struct list_head *pos = find_node_by_seq(&ts->disorder_list, seq+len);
		if (pos == NULL) {
			estimate_time = ts->last_in_time + (time - ts->last_in_time) * ((ts->last_in_seq - seq - len)*1.0 / (ts->last_in_seq - seq));
			insert_seq_rtt(seq+len, estimate_time, &ts->estimate_time_list);
		} 

	} else if(seq < ts->rcv_nxt || (seq == ts->last_in_seq && ts->pkt_cnt > 4)){
		append_to_range_list(&ts->spurious_retrans_list, seq, seq+len);
		update_retrans_and_reorder(ts, seq);
	} 

	/*struct time_stamp *tsp = find_rtt_entry(ts->tsp_table, ts->option.ts);
	if(tsp != NULL){
		fprintf(fp, "updateing rtt, rtt: %.3lf\n", TICK_TO_TIME(ts->rtt.srtt >> 3));
	//	update_rtt_with_time_stamp(seq, ts, tsp);
	}*/
}

static void handle_out_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	uint32_t seq = ntohl(th->seq),
			 ack_seq = ntohl(th->ack_seq);

	ts->rcv_nxt = ack_seq;
	ts->snd_nxt = seq + len;
	
	if (ts->ca_state != TCP_CA_OPEN && ack_seq >= ts->recovery_point) {
		ts->ca_state = TCP_CA_OPEN;
	}
	
	// tail record
	if (ts->state == TCP_ESTABLISHED) {
		if (len > 0)
			ts->tail = 1;
		else 
			ts->tail = 0;
	}
	if (ts->state == TCP_ESTABLISHED && ack_seq == ts->last_out_ack) {
		ts->dup_ack_cnt = get_list_item_num(&ts->disorder_list);
	} else {
		ts->dup_ack_cnt = 0;	
	}
	if (ts->dup_ack_cnt == 3) {
		ts->third_dup_ack_time.ack_seq = ack_seq;
		ts->third_dup_ack_time.time = time;
		// ts->state = TCP_
	}
	if(ack_seq > ts->last_out_ack) {
		delete_before_seq(ack_seq, &ts->estimate_time_list);
		delete_node_before_seq(&ts->disorder_list, ack_seq);
	}
	//time_stamp record
/*	struct time_stamp *tsp = find_rtt_entry(ts->tsp_table, ts->option.ts);
	if (tsp == NULL) {
		insert_rtt_entry(ts->tsp_table, &ts->option.ts);
	}
*/	
}

int tcp_state_machine(struct tcp_state *ts, struct tcphdr *th, int len, double cap_time, int dir)
{
	uint32_t seq = ntohl(th->seq);
	uint32_t ack_seq = ntohl(th->ack_seq);
	ts->pkt_cnt += 1;
	if (dir == DIR_IN && ts->state == TCP_SYN_SENT) {
		// calculate first rtt during syn
		int rtt = TIME_TO_TICK(cap_time - ts->last_out_time);
		update_rtt(&ts->rtt, rtt);
	}

	if (dir == DIR_IN && IS_SYN(th)) {
		// client may reestablish a connection
		ts->state = TCP_SYN_RECV;
		ts->start_time = cap_time;
		ts->seq_base = seq;
		ts->rcv_nxt = seq;
		ts->rcv_una = seq;
		ts->rcv_max = seq + len;
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
					ts->tail = 1;
					if (dir == DIR_IN){
						ts->state = TCP_FIN_WAIT1;
					} 
					else
						ts->state = TCP_FIN_WAIT2;
				}
				break;
			case TCP_FIN_WAIT1:
				if (dir == DIR_OUT && ack_seq == ts->rcv_una+1)
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

	if (ts->state == TCP_CLOSING || ts->state == TCP_CLOSE) {
		return 0;
	}
	get_tcp_option(th, &ts->option);
	if (dir == DIR_OUT) {
		handle_out_pkt(ts, th, cap_time, len);
	}
	else {
		handle_in_pkt(ts, th, cap_time, len);
	}

	int thres = rtt_thres(&ts->rtt);

	// check whether there is a stall
	int duration = 0;
	if (dir == DIR_IN && IS_SYN(th)) {
		ts->start_time = cap_time;
	}
	else {
		duration = TIME_TO_TICK(cap_time - ts->last_time);
	}
	if (ts->tail == 0 && duration > MAX(200, thres)) { // tail case is not included
		// store the (partial) stall state in list
		ts->stall_cnt += 1;
		struct tcp_stall_state *tss = MALLOC(struct tcp_stall_state);
		
		// if the stall happened during recovery stage
		if (ts->ca_state == TCP_CA_RECOVERY ) {
			ts->ca_state = TCP_CA_RECOVERY_LOSS;
			ts->recovery_point = ts->rcv_max;
		}
		
		init_tcp_stall(ts, tss, TICK_TO_TIME(duration));
		tss->cur_pkt_dir = dir;
		list_add_tail(&tss->list, &ts->stall_list);

		if (ts->state == TCP_SYN_SENT || ts->state == TCP_SYN_RECV) {
			tss->head = 1;
		}
		if (duration > ts->rtt.rto) {
			ts->ca_state = TCP_CA_LOSS;
			ts->recovery_point = ts->rcv_max;
		}
	}

	if (dir == DIR_IN) {
		ts->last_in_time = cap_time;
		ts->last_len = len;
		// record in_time to the list
		insert_seq_rtt(seq, cap_time, &ts->in_time_list);
		ts->last_in_seq = seq;
	} else {
		ts->last_out_time = cap_time;
		ts->last_out_ack = ack_seq;
		insert_seq_rtt(ack_seq, cap_time, &ts->out_time_list);
	}

	if (ts->state == TCP_ESTABLISHED || ts->state == TCP_SYN_SENT || ts->state == TCP_SYN_RECV)
		ts->last_time = cap_time;
	ts->last_dir = dir;		

	return 0;
}

static inline void dump_list(FILE *fp, const char *fmt, \
		struct tcp_state *ts, struct list_head *list)
{
	struct list_head *p;
	struct range_t *r;
	fprintf(fp,"%s", fmt);
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
	fprintf(fp,"%s", fmt);
	list_for_each(p, list) {
		r = list_entry(p, struct seq_rtt_t, list);
		fprintf(fp, " (%d,%lf)", 
				r->ack_seq - ts->seq_base, 
			   	r->time - ts->start_time);
	}
	fprintf(fp, "\n");
}

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


void dump_ts_info(FILE *fp, struct tcp_state *ts)
{
//	dump_time_list(fp, "in_time_list:", ts, &ts->in_time_list);
//	dump_time_list(fp, "out_time_list:", ts, &ts->out_time_list);
//	dump_time_list(fp, "estimate_time:", ts, &ts->estimate_time_list);
	dump_list(fp, "retrans:", ts, &ts->retrans_list);
	dump_list(fp, "reorder:", ts, &ts->reordering_list);
	dump_list(fp, "spurious:", ts, &ts->spurious_retrans_list);
	fprintf(fp, "%s: \"%d\"\n", "pkt_cnt", ts->pkt_cnt);
	fprintf(fp, "%s: \"%lf\"\n", "rtt", TICK_TO_TIME(ts->rtt.srtt >> 3));
	fprintf(fp, "%s: \"%lf\"\n", "rto", TICK_TO_TIME(ts->rtt.rto));
	fprintf(fp, "%s: \"%d\"\n", "max_snd_seg_size", ts->max_snd_seg_size);
	fprintf(fp, "%s: \"%.3lf\"\n\n", "transfer_time", ts->transfer_time);
}

static void free_tcp_state(struct tcp_state *ts)
{
	//delete_rtt_list(&ts->rtt_list);

	delete_list(&ts->retrans_list, struct range_t, list);
	delete_list(&ts->reordering_list, struct range_t, list);
	delete_list(&ts->spurious_retrans_list, struct range_t, list);
	delete_list(&ts->disorder_list, struct range_t, list);
	delete_list(&ts->stall_list, struct tcp_stall_state, list);
	delete_rtt_list(&ts->in_time_list);
	delete_rtt_list(&ts->out_time_list);
	delete_rtt_list(&ts->estimate_time_list);

	// cleanup_rtt_hash_table(ts->tsp_table);
	FREE(ts);
}

void finish_tcp_state(struct tcp_state *ts)
{
	FILE *fp = stdout;
	if (ts->max_snd_seg_size != 0) {

		fill_tcp_stall_list(ts, &ts->stall_list);

		ts->transfer_time = ts->last_time - ts->start_time;

		fprintf(fp, "\nname: %s\n", ts->name);
		fprintf(fp, "#(stalls): %d\n", ts->stall_cnt);
		dump_ts_info(fp, ts);
		// dump tss info
		dump_tss_list(fp, &ts->stall_list);
	}

	free_tcp_state(ts);
}
