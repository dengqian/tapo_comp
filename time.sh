#!/bin/bash
export sum1;
sum1=`grep 'transfer_time' $1.txt |cut -d ':' -f 2 | cut  -d '"' -f 2 | awk '{sum += $1} END {print sum}'`;  
echo $sum1
cut -d ',' -f 4 $1/ack_delay.txt | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"ack_delay:", sum/sum1}';
cut -d ',' -f 4 $1/ack_loss.txt | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"ack_lossi:", sum/sum1}'
cut -d ',' -f 4 $1/continuous_loss.txt | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"continuous_loss:", sum/sum1}'
cut -d ',' -f 4 $1/double_retransmission.txt | cut -d '=' -f 2 | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"double_retransmission:", sum/sum1}'
cut -d ',' -f 4 $1/client_idle.txt | cut -d '=' -f 2 | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"client_idle:", sum/sum1}'
cut -d ',' -f 4 $1/small_cwnd.txt | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"small_cwnd:", sum/sum1}'
cut -d ',' -f 4 $1/undetermined.txt | cut -d '=' -f 2  | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"undetermined:", sum/sum1}'
cut -d ',' -f 4 $1/packet_delay.txt | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"packet_delay:", sum/sum1}'

