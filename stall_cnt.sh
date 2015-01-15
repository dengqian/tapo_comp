#!/bin/bash
grep 'stalls' $1 | cut -d ':' -f 2 | awk '{sum += $1} END {print sum}'
