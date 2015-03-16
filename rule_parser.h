#ifndef __RULE_PARSER_H__
#define __RULE_PARSER_H__
#include "tcp_stall_state.h"

#define TCP_CA_OPEN 0
#define TCP_CA_RECOVERY 1
#define TCP_CA_LOSS 2
#define TCP_CA_RECOVERY_LOSS 3


enum stall_type { HEAD_LOSS, UNDETERMINED, DOUBLE_RETRANSMISSION, SMALL_CWND, CONTINUOUS_LOSS, ACK_DELAY, ACK_LOSS, PACKET_DELAY, CLIENT_IDLE,CONNECTION_CLOSING,RECOVERY_LOSS, };
extern const char *stall_text[];
extern const char *stall_details[];
extern enum stall_type parse_stall(struct tcp_stall_state *);

#endif
