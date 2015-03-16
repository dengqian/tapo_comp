#include "rule_parser.h"


const char *stall_text[] = {
"HEAD_LOSS", "UNDETERMINED", "DOUBLE_RETRANSMISSION", "SMALL_CWND", "CONTINUOUS_LOSS", "ACK_DELAY", "ACK_LOSS", "PACKET_DELAY", "CLIENT_IDLE", "CONNECTION_CLOSING", "RECOVERY_LOSS",};
const char *stall_details[] = {
	"Stall happens when syn or syn-ack loss.",
	"This stall could not be determined.",
	"The retransmitted packet is dropped.",
	"Packet loss happens when the congestion window is smaller than 4 MSS.",
	"All the outstanding packets are lost.",
	"Delayed-ACKs at server.",
	"ACK loss happens.",
	"RTT jitter (current RTT is larger than (\\tau SRTT)).",
	"Client uploading another file.",
	"Connection closing.",
	"Stall happens at the recovery state.",
};
enum stall_type parse_stall(struct tcp_stall_state *tss)
{
			
	if (tss->retrans + tss->spurious > 0) {
		if (tss->head == 1)
			return HEAD_LOSS; 
		if (tss->tail == 1)
			return CLIENT_IDLE;
		if (tss->cur_pkt_retrans > 0) {
			if (tss->cur_pkt_spurious + tss->cur_pkt_retrans >= 2) {
				return DOUBLE_RETRANSMISSION;
			} else {
				if (tss->sacked >= 3) {
					if (tss->duration + tss->cur_time - tss->third_dup_ack_time > tss->rto + tss->srtt) 
						return DOUBLE_RETRANSMISSION;
					else
						return UNDETERMINED;
				} else {
				// 	if (tss->ca_state == TCP_CA_RECOVERY_LOSS)
				// 		return RECOVERY_LOSS;	

					return SMALL_CWND;
				}
			} 
		} else {
			if (tss->cur_pkt_spurious > 0) {
				/*if (tss->ack_delay_time > tss->rto - tss->srtt) {
					return ACK_DELAY;
				} else {
					return ACK_LOSS;
				}*/
				return ACK_LOSS;
			} else {
				return UNDETERMINED;
			}
		}
	} else {
		if (tss->cur_pkt_dir == DIR_IN) {
			if (tss->duration > tss->rto + tss->srtt) {
				return CONTINUOUS_LOSS;
			} else {
				return PACKET_DELAY;
			}
		} else {
			if (tss->last_dir == DIR_IN)
				return ACK_DELAY;
			else 
				return CLIENT_IDLE;
		} 
	}
}
