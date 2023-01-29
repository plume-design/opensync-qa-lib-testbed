#!/bin/bash

version="plume_linux_client__v1.0.7 [Oct 8 10:58:11 UTC 2020]"


echoerr() { echo "$@" 1>&2; }

# root check
if [[ $EUID -ne 0 ]]; then
    echoerr "Please run as root"
    exit 1
fi


# Internet access check
ping -c 1 8.8.8.8 >> /dev/null 2>&1 && nslookup www.google.com >> /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    echoerr "Unable to run script without Internet access"
    exit 2
fi


# below are one time actions, so enable it for fresh install, not needed for an upgrade
## fix dhclient-script to work with network namespaces
#sed -i 's+mv -f $new_resolv_conf $resolv_conf+cat $new_resolv_conf > $resolv_conf\n\trm -f $new_resolv_conf+g'  /sbin/dhclient-script
#
#
## sudoers
#echo "plume ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/plume
#chmod 0400 /etc/sudoers.d/plume
#
#
## TODO: create authorized_keys file
#if [ ! -d ~/.ssh ]; then
#  mkdir /home/plume/.ssh
#fi

# TODO: kernel upgrade

# ---------------------------------------------------------------------------------
# install required packages
apt-get update
apt-get install -y iperf expect miniupnpc dnsutils vim arping bluetooth curl ndisc6 sshpass t50 ethtool xvfb libxi6 libgconf-2-4 fonts-liberation libappindicator3-1 tcpdump firefox-esr ntpdate

# iperf3
iperf3_ver="iperf 3.6 (cJSON 1.5.2)"
if [[ $(iperf3 -v | head -n 1) != ${iperf3_ver} ]]; then
    apt remove -y iperf3 libiperf0
    apt-get install -y iperf3=3.6-2
fi


# bluez
bluez_ver="bluetoothctl: 5.52"
if [[ $(bluetoothctl --version) != ${bluez_ver} ]]; then
    wget https://www.kernel.org/pub/linux/bluetooth/bluez-5.52.tar.xz
    tar xvf bluez-5.52.tar.xz
    apt-get install -y libudev-dev libical-dev libreadline-dev libdbus-1-dev libglib2.0-dev
    cd bluez-5.52
    ./configure
    make
    make install
    cd ..
    rm -r bluez-5.52
fi

# ookla speedtest
speed_ver="1.0.0"
if [[ $(speedtest --version) != ${speed_ver} ]]; then
    apt-get install -y gnupg1 apt-transport-https dirmngr
    export INSTALL_KEY=379CE192D401AB61
    export DEB_DISTRO=$(lsb_release -sc)
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $INSTALL_KEY
    echo "deb https://ookla.bintray.com/debian ${DEB_DISTRO} main" | sudo tee  /etc/apt/sources.list.d/speedtest.list
    apt-get install -y speedtest
fi

# google chrome
chrome_ver="83.0.4103.0"
which google-chrome
if [[ $? -ne 0 || ${chrome_ver} == *$(google-chrome --version)* ]]; then
    apt-get install -y xvfb libxi6 libgconf-2-4 fonts-liberation libappindicator3-1
    curl https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add
    mkdir -p /tmp/chrome
    wget "https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2F756066%2Fchrome-linux.zip?generation=1585871012733067&alt=media" -O /tmp/chrome/chrome-linux.zip && unzip /tmp/chrome/chrome-linux.zip -d /opt/chrome-linux/
    ls -la /opt/chrome-linux/ && ls -la /opt/chrome-linux/chrome-linux
    export CHROME_PATH=/usr/bin/google-chrome
    ln -sf /opt/chrome-linux/chrome-linux/chrome ${CHROME_PATH}
    chown root:root ${CHROME_PATH} && chmod 755 ${CHROME_PATH}
    rm -rf /tmp/chrome
fi

# chrome driver
chrome_driver_ver="83.0.4103.0"
which chromedriver
if [[ $? -ne 0 || ${chrome_driver_ver} == *$(chromedriver --version)* ]]; then
    mkdir -p /tmp/chrome
    wget -q "https://www.googleapis.com/download/storage/v1/b/chromium-browser-snapshots/o/Linux_x64%2F756066%2Fchromedriver_linux64.zip?generation=1585871017688644&alt=media" -O /tmp/chrome/chromedriver.zip \
    && unzip /tmp/chrome/chromedriver.zip -d /tmp/chrome
    export CHROMEDRIVER_PATH=/usr/bin/chromedriver
    cp /tmp/chrome/chromedriver_linux64/chromedriver ${CHROMEDRIVER_PATH}
    chown root:root ${CHROMEDRIVER_PATH} && chmod +x ${CHROMEDRIVER_PATH} && rm -rf /tmp/chrome
fi

# selenium-server
selenium_server_ver="selenium-server-standalone-3.141.59"
ls /usr/bin | grep ${selenium_server_ver}
if [[ $? -ne 0 ]]; then
    wget https://selenium-release.storage.googleapis.com/3.141/selenium-server-standalone-3.141.59.jar -P /usr/bin/
fi

# gecko driver
ls /usr/bin | grep geckodriver
if [[ $? -ne 0 ]]; then
    wget -q "https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz" -O /tmp/geckodriver.tgz \
    && tar zxf /tmp/geckodriver.tgz -C /usr/bin/ && rm /tmp/geckodriver.tgz
fi


# -------------------------------------------------------------------
# create wpa_supplicant.conf file
echo 'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
        ssid="my_ssid"
        psk="my_pskkk"
        proto=RSN
        key_mgmt=WPA-PSK
        scan_ssid=1
        priority=1

        bssid=34:7a:60:2f:47:03
}
' > /etc/wpa_supplicant/wpa_supplicant.conf


# ------------------------------------------------------------------
# network eth namespaces
# figure out eth iface
ln -s /proc/1/ns/net /var/run/netns/default
for iface in $(ip netns exec default ls /sys/class/net); do
    if [[ $iface == e* ]]; then
        break
    fi
done
echo "eth iface: $iface"

echo '#!/bin/sh -x

# $1 start/stop
# $2 namespace_name
# $3 raw interface
# $4 vlan id

mode=$1
nsname=$2
raw=$3
id=$4
iface="$raw.$id"

# if namespace exists, delete it
ip netns list | grep -q $nsname
if [ $? -eq 0 ]; then
    ip netns exec $nsname ip link set $iface netns 1
    ip netns del $nsname
fi
# if virtual interface exists, delete it
ip link | grep -q $iface
if [ $? -eq 0 ]; then
    ip link delete $iface
fi
if [ -f /var/run/dhclient.$iface.pid ]; then
    kill $(cat /var/run/dhclient.$iface.pid)
fi
[[ "$mode" == stop ]] && echo "Namespace $nsname and interface $iface deleted" && exit

# create MAC address
mac_prefix=$(cat /sys/class/net/$raw/address | rev | cut -c 5- | rev)
# generate last 3 characters from VALN_ID
mac_suffix=$(printf '\''%x\n'\'' $id | sed '\''s/.\{1\}/&:/'\'')
mac="$mac_prefix$mac_suffix"
if [ ${#mac_suffix} -eq 2 ]; then
    mac="${mac}00"
elif [ ${#mac_suffix} -eq 3 ]; then
    mac="${mac}0"
fi


ip link add link $raw name $iface type vlan id $id
ip netns add $nsname

mkdir -p /etc/netns/$nsname
cp /etc/resolv.conf /etc/netns/$nsname

ip link set $iface netns $nsname
ip netns exec $nsname sh -x <<-.
	ifconfig $iface hw ether $mac
	ifconfig $iface up
	dhclient -nw -pf /var/run/dhclient.$iface.pid $iface
	/usr/sbin/sshd -D
.
' > /usr/local/bin/nseth-service

chmod +x /usr/local/bin/nseth-service

for vlan in 305 351 352; do
    echo "[Unit]
Description=Creating nseth$vlan namespace service
Requires=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/nseth-service start nseth$vlan $iface $vlan
ExecStop=/usr/local/bin/nseth-service stop nseth$vlan $iface $vlan

[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/nseth${vlan}.service

    systemctl enable nseth${vlan}.service
    mkdir -p /etc/netns/nseth${vlan}
    cp /etc/resolv.conf /etc/netns/nseth${vlan}
done


# ------------------------------------------------------------------
# network wifi namespaces
echo '#!/bin/sh -x

nsname=$1
mode=$2
iface=$3

ifdown --force $iface
ip netns list | grep -q $nsname
if [ $? -eq 0 ]; then
    ip netns del $nsname
fi
[[ "$mode" == stop ]] && echo "Namespace $nsname with interface $iface deleted" && exit

# add namespace
ip netns add $nsname

# create specific wpa_supplicant and resolv.conf files
mkdir -p /etc/netns/$nsname/wpa_supplicant
cp /etc/resolv.conf /etc/netns/$nsname
cp /etc/wpa_supplicant/* /etc/netns/$nsname/wpa_supplicant/

# wait for the interface
timeout 120 sh -c "while [ ! -f /sys/class/net/$iface/phy80211/index ]; do sleep 2; done"

phyidx=$(cat /sys/class/net/$iface/phy80211/index)
iw phy$phyidx set netns name $nsname
ip netns exec $nsname sh -x <<-.
    # replacement for ifup
    wpa_supplicant -D nl80211 -i $iface -c /etc/netns/$nsname/wpa_supplicant/wpa_supplicant.conf \
                                        -P /tmp/wpa_supplicant_$iface.pid \
                                        -f /tmp/wpa_supplicant_$iface.log -B -d
    TIMEOUT=60
    SECONDS=0
    while [ $SECONDS -lt $TIMEOUT ]; do
        wpa_cli -i $iface status | grep -q wpa_state=COMPLETED
        if [ $? -eq 0 ]; then
            break
        else
            sleep 1
      SECONDS=$((SECONDS+1))
        fi
    done
    if [ $SECONDS -lt $TIMEOUT ]; then
        dhclient -pf /var/run/dhclient.$iface.pid $iface
        echo "WiFi client with interface: $iface connected successfully to the network"
    else
        kill $(cat /tmp/wpa_supplicant_$iface.pid); sudo rm /tmp/wpa_supplicant_$iface.pid
        echo "WiFi client failed to connect to the wifi network"
    fi

    /usr/sbin/sshd -D
.' > /usr/local/bin/ns-service

chmod +x /usr/local/bin/ns-service


# looking for wifi interfaces
wifi=()
for iface in $(ls /sys/class/net); do
    if [[ -d /sys/class/net/${iface}/phy80211 ]]; then
        wifi+=${iface}
    fi
done

for iface in "${wifi[@]}"; do

    echo "[Unit]
Description=Creating nswifi$iface namespace service
Requires=network.target
After=network.target

[Service]
ExecStart=/usr/local/bin/ns-service nswifi$iface start $iface
ExecStop=/usr/local/bin/ns-service nswifi$iface stop $iface

[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/nswifi${iface}.service

    systemctl enable nswifi${iface}.service

    mkdir -p /etc/netns/nswifi${iface}/wpa_supplicant
    cp /etc/resolv.conf /etc/netns/nswifi${iface}
    cp /etc/wpa_supplicant/* /etc/netns/nswifi${iface}/wpa_supplicant/
done


# --------------------------------------------------------------------------
# wpa_supplicant
mkdir -p /home/plume/git

apt install -y git build-essential binutils-dev libssl-dev libdbus-1-dev libnl-3-dev libnl-genl-3-dev libiberty-dev zlib1g-dev

cd /home/plume/git

if [[ ! -d hostap ]]; then
    git clone git://w1.fi/srv/git/hostap.git
fi

cd hostap/wpa_supplicant
supp_ver="b7275a814"
if [[ $(git log -n1 --pretty=format:"%h") != ${supp_ver} ]]; then
    git fetch
    git checkout ${supp_ver}
    cp ../tests/hwsim/example-wpa_supplicant.config .config
    make
    make install
    cd ../hostapd
    cp defconfig .config
    make clean
    make
    make install
fi
# TODO: enable 5G channels for AP mode (no IR now)

# iw
cd /home/plume/git
if [[ ! -d iw ]]; then
    git clone git://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
fi
cd iw
iw_ver="0250318"
if [[ $(git log -n1 --pretty=format:"%h") != ${iw_ver} ]]; then
    git fetch
    git checkout ${iw_ver}
    make
    make install
fi


# ------------------------------------------------------------------------
# version
echo ${version} > /.version
echo "Client successfully upgraded to $version"
