
grep 'transfer_time' $1 |cut -d ':' -f 2 | cut  -d '"' -f 2 | awk '{sum += $1} END {print "transfer_time:",sum}'
