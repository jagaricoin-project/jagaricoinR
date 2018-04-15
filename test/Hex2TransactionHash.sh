#!/usr/bin/zsh
# Copyright The 2017 JagaricoinR Core Developer
#
# Usage
#
#   $ ./Hex2TransactionHash.sh <hex>
#
# example
#
#   $ ./Hex2TransactionHash.sh 01000000031f5c38dfcf6f1a5f5a87c416076d392c87e6d41970d5ad5e477a02d66bde97580000000000ffffffff7cca453133921c50d5025878f7f738d1df891fd359763331935784cf6b9c82bf1200000000fffffffffccd319e04a996c96cfc0bf4c07539aa90bd0b1a700ef72fae535d6504f9a6220100000000ffffffff0280a81201000000001976a9141fc11f39be1729bf973a7ab6a615ca4729d6457488ac0084d717000000001976a914f2d4db28cad6502226ee484ae24505c2885cb12d88ac00000000
#
# For your information: https://qiita.com/onokatio/items/d471a11e9894d01624df

set -eu


p2=$(echo $1| xxd -ps -r|sha256sum|cut -c-64)

p3=$(echo $p2| xxd -ps -r|sha256sum|cut -c-64)

p4=$(for i in `seq 1 2 63`;do echo -n $p3|cut -c$((64-i))-$((64-i+1))|tr -d '\n';done)
echo $p4
