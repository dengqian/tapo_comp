#!/bin/bash
echo 'small_cwnd:' `grep -i 'small_cwnd' $1 | wc -l`
echo 'continuous_loss:' `grep -i 'continuous_loss' $1 | wc -l`
echo 'packet_delay:' `grep -i 'packet_delay' $1 | wc -l`
echo 'double_retransmission:' `grep -i 'double_retransmission' $1 | wc -l`
echo 'ack_loss:' `grep -i 'ack_loss' $1 | wc -l`
echo 'undetetmined:' `grep -i 'undetermined' $1 | wc -l`
echo 'head_loss:' `grep -i 'head_loss' $1 | wc -l`
echo 'ack_delay:' `grep -i 'ack_delay' $1 | wc -l`
echo 'client_idle:' `grep -i 'client_idle' $1 | wc -l`
echo 'recovery_loss:' `grep -i 'recovery_loss' $1 | wc -l`

