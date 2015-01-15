#!/bin/bash
cut -d ',' -f 4 $1/ack_delay.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/ack_loss.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/continuous_loss.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/double_retransmission.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/client_idle.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/small_cwnd.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/undetermined.txt | cut -d '=' -f 2  | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/packet_delay.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'
cut -d ',' -f 4 $1/connection_closing.txt | cut -d '=' -f 2 | awk '{sum += $1} END {print sum}'

