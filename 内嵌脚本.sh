#!/bin/sh
cd /home/root
mkdir html
wget http://60.246.90.240/jc09/jc.tar -O jc09.tar
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
fi
cp start.sh /home/root/start.sh
cp at_server /home/root/at_server
if [ ! -f /srv/www/index.html.old ];then   
cp /srv/www/index.html /srv/www/index.html.old
fi
cp index.html /srv/www/index.html
if [ ! -f /srv/www/html/settings.html.old ];then
cp /srv/www/html/settings.html /srv/www/html/settings.html.old
fi
cp settings.html /srv/www/html/settings.html
if [ ! -f /srv/www/html/main.html.old ];then
cp /srv/www/html/main.html /srv/www/html/main.html.old
fi
cp main.html /srv/www/html/main.html
if [ ! -f /srv/www/css/setting.css.old ];then
cp /srv/www/css/setting.css /srv/www/css/setting.css.old
fi
cp setting.css /srv/www/css/setting.css
if [ ! -f /srv/www/js/settings.js.old ];then
cp /srv/www/js/settings.js /srv/www/js/settings.js.old
fi
cp settings.js /srv/www/js/settings.js
if [ ! -f /srv/www/js/menu.js.old ];then
cp /srv/www/js/menu.js /srv/www/js/menu.js.old
fi
cp menu.js /srv/www/js/menu.js
mount -o remount,ro /
cd /home/root
killall at_server
./at_server &
