#ifndef __RULE_PARSER_H__
#define __RULE_PARSER_H__

#include "tcp_stall_state.h"

enum stall_type { UNDETERMINED, DOUBLE_RETRANSMISSION, SMALL_CWND, CONTINUOUS_LOSS, ACK_DELAY, ACK_LOSS, PACKET_DELAY, };
extern const char *stall_text[];
extern const char *stall_details[];
extern enum stall_type parse_stall(struct tcp_stall_state *);

#endif
