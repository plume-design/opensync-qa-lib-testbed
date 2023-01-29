#!/bin/sh
# Function to generate command string to insert an entry to Band_Steering_Clients OVSBDB table
gen_bsc_cmd()
{
    string=`echo $bsc_entry1 | sed s/$mac1/$new_mac/`
    cat << EOF
["Open_vSwitch",
    {
      "op": "insert",
      "table": "Band_Steering_Clients",
      "row": $string
    }
]
EOF
}

# Determine the MAC address of any connected client
mac1=`ovsh s Band_Steering_Clients -c | grep -m 1 mac | sed 's/[^:]*: //'`
# Gather all key/pair values for the client above in JSON format
bsc_entry1=`ovsh s Band_Steering_Clients -w mac==$mac1 -j | sed '1d;$d'`

# Insert a row for 90 fake clients with the same key/value pairs as above
for idx in `seq 10 99`
do
    new_mac="03:93:bc:ae:39:$idx"
    eval ovsh d Band_Steering_Clients -w mac==$new_mac
    eval ovsdb-client transact \'$(gen_bsc_cmd)\'
done
