#!/bin/bash

mkdir $1
echo $1 > $1/target.txt
echo $2 > $1/location.txt


session="bg_nmap"

# Check if the session exists, discarding output
# We can check $? for the exit status (zero for success, non-zero for failure)
tmux has-session -t $session 2>/dev/null

if [ $? != 0 ]; then
	  tmux new -d -s $session
fi

# Attach to created session
#tmux attach-session -t $session


tmux new-window -t $session -n "nmap_tcp_$1"
tmux send-keys -t $session:.+ "nmap -A -p- -T3 -Pn -n -oA ~/$1/nmap-$1-full-tcp $1" Enter
