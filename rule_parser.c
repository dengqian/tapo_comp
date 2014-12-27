#include "rule_parser.h"


const char *stall_text[] = {
"UNDETERMINED", "DOUBLE_RETRANSMISSION", "SMALL_CWND", "CONTINUOUS_LOSS", "ACK_DELAY", "ACK_LOSS", "PACKET_DELAY", };
const char *stall_details[] = {
	"This stall could not be determined.",
	"The retransmitted packet is dropped.",
	"Packet loss happens when the congestion window is smaller than 4 MSS.",
	"All the outstanding packets are lost.",
	"Delayed-ACKs at server.",
	"ACK loss happens.",
	"RTT jitter (current RTT is larger than (\\tau SRTT)).",
};
enum stall_type parse_stall(struct tcp_stall_state *tss)
{
	if (tss->retrans + tss->spurious > 0) {
		if (tss->cur_pkt_spurious > 0) {
			if (tss->ack_delay_time > tss->rto - tss->srtt) {
				return ACK_DELAY;
			} else {
				return ACK_LOSS;
			}
		} else {
			if (tss->sacked > 3) {
				if (tss->duration > tss->rto + tss->srtt) {
					return DOUBLE_RETRANSMISSION;
				} else {
					return UNDETERMINED;
				}
			} else {
				return SMALL_CWND;	
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
			return ACK_DELAY;
		}
	}
}
