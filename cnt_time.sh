#!/bin/bash
export sum1;
export time_sum;
sum1=`grep 'transfer_time' $1 |cut -d ':' -f 2 | cut  -d '"' -f 2 | awk '{sum += $1} END {print sum}'`;  
echo "total_time:$sum1"
grep -i 'ack_delay' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"ack_delay:", sum/sum1}';
grep -i 'ack_loss' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"ack_loss:", sum/sum1}'
grep -i 'continuous_loss' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"continuous_loss:", sum/sum1}'
grep -i 'double_retransmission' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"double_retransmission:", sum/sum1}'
grep -i 'client_idle' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"client_idle:", sum/sum1}'
grep -i 'small_cwnd' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"small_cwnd:", sum/sum1}'
grep -i 'undetermined' $1 | cut -d ',' -f 4 | cut -d '=' -f 2  | awk  -v sum1=$sum1 '{sum += $1} END {print sum,"undetermined:", sum/sum1}'
grep -i 'packet_delay' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"packet_delay:", sum/sum1}'
grep -i 'head_loss' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"head_loss:", sum/sum1}'
# grep -i 'recovery_loss' $1 | cut -d ',' -f 4 | cut -d '=' -f 2 | awk -v sum1=$sum1 '{sum += $1} END {print sum,"recovery_loss:", sum/sum1}'

