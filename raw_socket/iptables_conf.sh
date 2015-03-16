#!/bin/bash

   

sudo iptables -A INPUT -p tcp --dport 54321 -j DROP 
sudo iptables -A OUTPUT -p tcp --dport 54321 -j DROP


