#include "tcp_stall_state.h"
#include "tcp_state.h"
#include "algorithm.h"

void init_tcp_stall(struct tcp_state *ts, struct tcp_stall_state *tss, double duration)
{
	tss->max_snd_seg_size = ts->max_snd_seg_size;
	tss->cur_len = ts->last_len;
	tss->last_dir = ts->last_dir;
	tss->tail = ts->tail;
	tss->ca_state = ts->ca_state;

	tss->cur_time = ts->last_time - ts->start_time;
	tss->duration = duration;
	tss->srtt = TICK_TO_TIME(ts->rtt.srtt >> 3);
	tss->rto = TICK_TO_TIME(ts->rtt.rto);

	tss->seq_base = ts->seq_base;
	tss->rcv_nxt = ts->rcv_nxt;
	tss->rcv_una = ts->rcv_una;
	tss->sacked = get_list_item_num(&ts->disorder_list);
	// tss->sacked = ts->dup_ack_cnt;
	tss->spurious = 0;
	if (tss->rcv_una == ts->third_dup_ack_time.ack_seq) {
		tss->third_dup_ack_time = ts->third_dup_ack_time.time - ts->start_time;
	} else {
		tss->third_dup_ack_time = tss->cur_time; // to  
	}
}

void fill_tcp_stall_list(struct tcp_state *ts, struct list_head *stall_list)
{
	struct list_head *pos;
	struct range_t *range;
	struct tcp_stall_state *tss;
	// stat totle number of lost node and spurious node
	int retrans_num = 0, spurious_num = 0;

	uint32_t *spurious_array = NULL;
	uint32_t *retrans_array = NULL;

	spurious_num = get_list_item_num(&ts->spurious_retrans_list);
	retrans_num = get_list_item_num(&ts->retrans_list);

	if (spurious_num != 0) {
		spurious_array = MALLOC_N(uint32_t, spurious_num);
		int itr = 0;
		list_for_each (pos, &ts->spurious_retrans_list) {
			range = list_entry(pos, struct range_t, list);
			spurious_array[itr++] = range->begin;
		}
	}

	if (retrans_num != 0) {
		retrans_array = MALLOC_N(uint32_t, retrans_num);
		int itr = 0;
		list_for_each (pos, &ts->retrans_list) {
			range = list_entry(pos, struct range_t, list);
			retrans_array[itr++] = range->begin;
		}
	}


	list_for_each (pos, stall_list) {
		tss = list_entry(pos, struct tcp_stall_state, list);

		// debug
		// tss->spurious_left = left_bound(spurious_array, spurious_num, MIN(tss->rcv_nxt-1, tss->rcv_una-1));
		// tss->spurious_right = left_bound(spurious_array, spurious_num, MAX(tss->rcv_nxt, tss->rcv_una));

		tss->retrans = array_range(retrans_array, retrans_num, MIN(tss->rcv_nxt-1, tss->rcv_una-1), MAX(tss->rcv_nxt+1, tss->rcv_una+1));
	 	tss->cur_pkt_retrans = array_range(retrans_array, retrans_num, tss->rcv_una - 1, tss->rcv_una + 1);
		tss->spurious = array_range(spurious_array, spurious_num, MIN(tss->rcv_nxt-1, tss->rcv_una-1), MAX(tss->rcv_nxt+1, tss->rcv_una+1)); 
		tss->cur_pkt_spurious = array_range(spurious_array, spurious_num, tss->rcv_una - 1, tss->rcv_una + 1);
	}
	if (spurious_num != 0) 
		FREE(spurious_array);
	if (retrans_num != 0)
		FREE(retrans_array);
}

void dump_tss_info(FILE *fp, struct tcp_stall_state *tss)
{
	fprintf(fp, "cur_len = %d, ", tss->cur_len);
	fprintf(fp, "max_snd_seg_size = %d, ", tss->max_snd_seg_size);
	fprintf(fp, "cur_time = %.3lf, ", tss->cur_time);
	fprintf(fp, "duration = %.3lf, ", tss->duration);
	// fprintf(fp, "last_dir = %d, ", tss->last_dir);
	// fprintf(fp, "cur_pkt_dir = %d, ", tss->cur_pkt_dir);
	// fprintf(fp, "srtt = %.3lf, ", tss->srtt);
	// fprintf(fp, "rto = %.3lf, ", tss->rto);
	fprintf(fp, "rcv_una = %u, ", tss->rcv_una - tss->seq_base);
	fprintf(fp, "rcv_nxt = %u, ", tss->rcv_nxt - tss->seq_base);
	fprintf(fp, "cur_pkt_spurious = %d, ", tss->cur_pkt_spurious);
	fprintf(fp, "spurious = %d, ", tss->spurious);
	fprintf(fp, "cur_pkt_retrans = %d, ", tss->cur_pkt_retrans);
	fprintf(fp, "retrans = %d, ", tss->retrans);
	fprintf(fp, "sacked = %d,", tss->sacked);
	fprintf(fp, "state = %d", tss->ca_state);
	// fprintf(fp, "tail = %d, ", tss->tail);
/*
	fprintf(fp, "packets_out = %u, ", tss->packets_out);
	fprintf(fp, "sacked_out = %u, ", tss->sacked_out);
	fprintf(fp, "holes = %u, ", tss->holes);
	fprintf(fp, "outstanding = %u, ", tss->outstanding);
	fprintf(fp, "cur_pkt_lost = %u, ", tss->cur_pkt_lost);
	fprintf(fp, "cur_pkt_spurious = %u, ", tss->cur_pkt_spurious);

	fprintf(fp, "head = %d\n", tss->head);
	fprintf(fp, "tail = %d\n", tss->tail);*/

}
