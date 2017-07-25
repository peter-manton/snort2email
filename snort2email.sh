#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "Usage: snort2email.sh <database> <alert-threshold> <alert-email>"
    exit 1
fi

# args
AlertDatabase=$1
AlertThreshold=$2
AlertEmail=$3

function SendEmail() {
Subject="IDS Alert: $1"
Recipient="$AlertEmail"
Message="Details \n\nTimestamp: $2\nEvent Description: $1\nSource IP: $3\nDestination IP: $4"
Sender="snort@yourcompany.com"
ServerName="$HOSTNAME"

MAIL_TXT="Subject: $Subject\nFrom: $Sender\nTo: $Recipient\n\n$Message"  
echo -e $MAIL_TXT | sendmail -t  
}

if [[ -f /var/log/snort2email/checkpoint.file ]]
then CheckpointID=`cat /var/log/snort2email/checkpoint.file`
fi
QueriedID=$(psql -t -d $AlertDatabase -c "select id from event order by id desc limit 1;")
Events=""

# ensure checkpoint directory exists
if [ ! -d /var/log/snort2email ]
then mkdir /var/log/snort2email
touch /var/log/snort2email/checkpoint.file
fi

# verify the validity of the checkpoint file
numRegex='^[0-9]+$'
if ! [[ $CheckpointID =~ $numRegex ]]
then 
echo "The checkpoint file appears to be corrupted (or have been deleted) - writing new file..."
echo $QueriedID > /var/log/snort2email/checkpoint.file
fi

if [[ $CheckpointID -eq $QueriedID ]]
then printf "No new events have been detected.\nExiting...\n"
exit 0
else
# grab new events
Events="`psql -t -d $AlertDatabase -c "copy (select sid,cid,signature,timestamp from event where id > $CheckpointID) TO STDOUT CSV;"`"

# generate alerts
COUNT=0

echo "$Events" | while read -r LINE
do 
cid=$(echo "$LINE" | awk -F ',' '{print $2}')
signatureID=$(echo "$LINE" | awk -F ',' '{print $3}')
timestamp=$(echo "$LINE" | awk -F ',' '{print $4}')
event_desc=$(psql -t -d $AlertDatabase -c "select sig_name from signature where sig_id=$signatureID;")

echo "Found new event: $event_desc: $timestamp"
((COUNT++))

if [[ $COUNT -eq $AlertThreshold ]]
then
echo "Found over $AlertThreshold events - sending warning..."
SendEmail "MULTIPLE EVENTS FOUND (REVIEW WEB INTERFACE)" "See control panel." "See control panel." "See control panel."
exit 0
fi

# convert decimal to ip address
ipsrc=$(psql -t -d $AlertDatabase -c "select ip_src from iphdr where cid=$cid;")
ipdst=$(psql -t -d $AlertDatabase -c "select ip_dst from iphdr where cid=$cid;")
IFS=" " read -r a b c d  <<< $(echo  "obase=256 ; $ipsrc" |bc)
IFS2=" " read -r e f g h  <<< $(echo  "obase=256 ; $ipdst" |bc)
ipsrc_conv=${a#0}.${b#0}.${c#0}.${d#0}
ipdst_conv=${e#0}.${f#0}.${g#0}.${h#0}

SendEmail "$event_desc" "$timestamp" "$ipsrc_conv" "$ipdst_conv"
done 
fi

# update the checkpount file
echo "$QueriedID" | xargs >/var/log/snort2email/checkpoint.file
