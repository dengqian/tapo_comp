#!/bin/bash
ls $2 || mkdir $2
grep -i 'packet_delay' $1 >  $2/packet_delay.txt
grep -i 'ack_loss' $1 >  $2/ack_loss.txt
grep -i 'small_cwnd' $1 >  $2/small_cwnd.txt
grep -i 'double_retransmission' $1 >  $2/double_retransmission.txt
grep -i 'undetermined' $1 > $2/undetermined.txt
grep -i 'continuous_loss' $1 > $2/continuous_loss.txt
grep -i 'ack_delay' $1 > $2/ack_delay.txt
grep -i 'client_idle' $1 > $2/client_idle.txt

