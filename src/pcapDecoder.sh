#!/bin/bash
directory=$(cd ../ &&pwd)
logsDir=$directory/logs
srcDir=$directory/src
decodedDir=$directory/decoded

extract() {
    cd $logsDir
    ls *.pcap
    read -rep "Type pcap file from list: " fileName
    
    tshark -r $fileName --disable-protocol wsmp -Tfields -Eseparator=, -e data.data > pcap.txt
    cd $srcDir
}

decode() {
    python3 decodeJ2735.py $logsDir/$fileName
    mv *.txt $decodedDir
}

processing() {
    extract
    decode
}

processing
