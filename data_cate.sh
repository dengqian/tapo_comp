#!/bin/bash
echo `wc -l $1/ack_delay.txt` + `wc -l $1/ack_loss.txt` + `wc -l $1/continuous_loss.txt` \
	+ `wc -l $1/small_cwnd.txt` + `wc -l $1/client_idle.txt` + `wc -l $1/double_retransmission.txt`\
	+ `wc -l $1/packet_delay.txt` + `wc -l $1/undetermined.txt`
