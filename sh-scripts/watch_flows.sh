



# default
# watch -n 0.5 "ovs-ofctl dump-flows $1"

# reformatted with priority
# watch -n 0.5 "ovs-ofctl dump-flows $1 | sed 's/priority=[0-9]\+,/&\n/g;  s/priority=[0-9]\+ /&\n/g;   '" 

# lightweight
# watch -n 0.5 "ovs-ofctl dump-flows $1 | sed 's/priority=[0-9]\+,//g;  s/priority=[0-9]\+ //g; s/idle_age=[0-9]\+, //g; s/duration=[a-zA-Z0-9,.]\+ //g;  s/n_bytes=[a-zA-Z0-9,.]\+ //g;  s/cookie=[a-zA-Z0-9,.]\+ //g;  '" 

# lightweight
watch -n 0.5 "ovs-ofctl dump-flows $1 | sed 's/priority=[0-9]\+,/&----------/g;  s/priority=[0-9]\+ /&----------/g;  s/idle_age=[0-9]\+, //g; s/duration=[a-zA-Z0-9,.]\+ //g;  s/n_bytes=[a-zA-Z0-9,.]\+ //g;  s/cookie=[a-zA-Z0-9,.]\+ //g;  s/actions=.*\+/\n&/g;  '" 

