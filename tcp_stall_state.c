#include "tcp_stall_state.h"
#include "tcp_state.h"
#include "algorithm.h"

void init_tcp_stall(struct tcp_state *ts, struct tcp_stall_state *tss, double duration)
{
	tss->cur_time = ts->last_time - ts->start_time;
	tss->duration = duration;
	tss->srtt = TICK_TO_TIME(ts->rtt.srtt >> 3);
	tss->rto = TICK_TO_TIME(ts->rtt.rto);
	
	tss->seq_base = ts->seq_base;
	tss->rcv_nxt = ts->rcv_nxt;
	tss->rcv_una = ts->rcv_una;
	tss->sacked = get_list_item_num(&ts->disorder_list);
	tss->spurious = 0;
	/*tss->snd_una = ts->snd_una - ts->seq_base;
	tss->snd_nxt = ts->snd_nxt - ts->seq_base;

	tss->packets_out = ts->packets_out;
	tss->sacked_out = ts->sacked_out;
	tss->holes = ts->holes;
	tss->outstanding = ts->outstanding;
	
	tss->head = ts->head;
	tss->tail = ts->tail; 

	tss->cur_pkt_dir = DIR_UNDETERMINED;
	*/
	// XXX to be determined after the flow is finished
	/*tss->lost = 0;
	tss->spurious = 0;
	tss->cur_pkt_lost = 0;
	tss->cur_pkt_spurious = 0;
	*/
}

void fill_tcp_stall_list(struct tcp_state *ts, struct list_head *stall_list)
{
	struct list_head *pos;
	struct range_t *range;
	struct tcp_stall_state *tss;
	// stat totle number of lost node and spurious node
	int retrans_num = 0, spurious_num = 0;
	
	uint32_t *spurious_array = NULL;

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

	list_for_each (pos, stall_list) {
		tss = list_entry(pos, struct tcp_stall_state, list);

		if (retrans_num != 0) {
			struct list_head *pos1;
			struct range_t *range1;
			list_for_each (pos1, &ts->retrans_list) {
				range1 = list_entry(pos1, struct range_t, list);
				if(inside(tss->rcv_una, range1->begin-ts->seq_base, range1->end-ts->seq_base)
						|| inside(tss->rcv_nxt, range1->begin-ts->seq_base, range1->end-ts->seq_base )) {
					tss->retrans += 1;
				}
			}
		}
		tss->spurious_left = left_bound(spurious_array, spurious_num, tss->rcv_nxt-1);
		tss->spurious_right = left_bound(spurious_array, spurious_num, tss->rcv_una);

		tss->spurious = array_range(spurious_array, spurious_num, tss->rcv_nxt-1, tss->rcv_una-1); 
		tss->cur_pkt_spurious = array_range(spurious_array, spurious_num, tss->rcv_nxt - 1, tss->rcv_nxt + 1);
	}
	if (spurious_num != 0) 
		FREE(spurious_array);
}

void dump_tss_info(FILE *fp, struct tcp_stall_state *tss)
{
	/*fprintf(fp, "init_rwnd = %d, ", tss->init_rwnd);
	fprintf(fp, "max_snd_seg_size = %d, ", tss->max_snd_seg_size);
	fprintf(fp, "rwnd = %d, ", tss->rwnd);
	fprintf(fp, "ca_state = %s, ", tcp_ca_state[tss->ca_state]);*/
	fprintf(fp, "cur_time = %.3lf, ", tss->cur_time);
	fprintf(fp, "duration = %.3lf, ", tss->duration);
	fprintf(fp, "srtt = %.3lf, ", tss->srtt);
	fprintf(fp, "rto = %.3lf, ", tss->rto);
	fprintf(fp, "rcv_una = %u, ", tss->rcv_una - tss->seq_base);
	fprintf(fp, "rcv_nxt = %u, ", tss->rcv_nxt - tss->seq_base);
	fprintf(fp, "cur_pkt_spurious = %d, ", tss->cur_pkt_spurious);
	fprintf(fp, "cur_pkt_dir = %d, ", tss->cur_pkt_dir);
	fprintf(fp, "spurious = %d, ", tss->spurious);
	fprintf(fp, "spurious_left = %d, ", tss->spurious_left);
	fprintf(fp, "spurious_right = %d, ", tss->spurious_right);
	fprintf(fp, "retrans = %d, ", tss->retrans);
	fprintf(fp, "sacked = %d\n", tss->sacked);
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
