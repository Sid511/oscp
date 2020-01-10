#!/bin/bash
read -p "Enter the file for bad characters: "  file

strings $file |  tr  '[:upper:]' '[:lower:]' | awk  '{print $2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17 }' > tmpchartocompare1

cat tmpchartocompare1


cat tmpchartocompare1 | xargs | sed "s/ /\\n/g" > tmpchartocompare
#head tmpchartocompare
rm tmpchartocompare1 

count=$(cat tmpchartocompare | wc -l )

echo "Printing bad characters"
bad="\x00"
for i in $(seq 1 $count); do
char1="$(head -$i  allbadchar2 | tail -1 )"
char2="$(head -$i  tmpchartocompare | tail -1 )"

#echo "Comparing $char1 and $char2"
#sleep 1

if [ $char1 != $char2 ]; then
    #echo $char2
    bad+="\x$char1"
fi
done

echo $bad