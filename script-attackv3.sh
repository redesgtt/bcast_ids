# Para generar Datasets automaticos
#
atack()
{

	date >> $FILENAME.txt
	echo "$1" >> $FILENAME.txt
	while test -e ./flag2
	do
		sleep 0.1
	done
	> ./flag1
	$1
	/bin/mv ./flag1 ./flag2
	date >> $FILENAME.txt
	echo "################" >> $FILENAME.txt
}
####################################################
. ./config.txt
set -x
# https://www.cyberciti.biz/faq/bash-for-loop/
#
FECHA=`date`
echo "$FECHA-$NOTAS" >> $FILENAME.txt
echo "################" >> $FILENAME.txt
for (( b=1 ; b<= $BUCLES ; b++))
do
	#sleep $TIME2

	#while test -e ./flag2
	#do
	#	sleep 0.1
	#done
        #> ./flag1

	#/bin/mv ./flag1 ./flag2
	
	#sleep $TIME1
        atack "nmap -sn $NETdst"
	sleep $TIME1
        atack "arp-scan -I $IFACE $NETdst"
	sleep $TIME1
	atack "nmap -sP $NETdst"
	sleep $TIME1
	atack "nmap -sV $NETdst"
	sleep $TIME1
	atack "netdiscover -i $IFACE -P -r $NETdst"

        sleep $TIME2

done
