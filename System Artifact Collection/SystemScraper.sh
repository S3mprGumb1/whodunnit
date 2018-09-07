#!/bin/bash

# Time Information 
TargetTime=$(date +"%T")
TargetTZ=$(date +"%:::z")
TargetUptime=$(uptime -p)

echo
echo 'Time Information'
echo 'Capture taken at: '$TargetTime
echo 'Target Timezone : '$TargetTZ
echo 'Target Uptime : '$TargetUptime
echo

# Version Information
OSVersionNumerical=$(uname -r)
OSVersionName=$(uname -s)
OSKernalVersion=$(uname -r)

echo 'Version Information'
echo 'OS Version Number: '$OSVersionNumerical
echo 'OS Version Name: '$OSVersionName
echo 'OS Kernal Version: '$OSKernalVersion
echo

# Hardware Information
CPUModel=$(cat /proc/cpuinfo | grep 'model name' | sed 's/.*://')
TotalRAM=$(cat /proc/meminfo | grep MemTotal)
TotalHDD="$(df --total -T . -h)"

echo 'Hardware Information'
echo 'CPU Model: '$CPUModel
echo 'RAM Total (kB): '$TotalRAM
echo
echo "$TotalHDD"
echo

# Hostname Information
Hostname=$(hostname)
Domain=$(domainname)

echo 'Hostname Information'
echo 'Hostname: '$Hostname
echo 'Domain: '$Domain
echo 

# User Information
for User in `cat /etc/passwd | cut -d":" -f1`
do
	CreatedDate=$(ls -lad /home/$User/ 2>/dev/null | awk '{print $6,$7,$8}')
	LastLogin=$(last $User | awk '{print $3,$4,$5,$6,$7}')
	echo "Username: $User"  
	echo "Created: $CreatedDate"
	echo Last Login:$LastLogin
	echo
done

# Boot Information
echo "----Boot Daemons----"
level=$(runlevel | awk '{print $2}')
ls -ld /etc/rc${level}.d/* | awk {'print $11'}

# Chron Tasks
ChronHourly=$(ls /etc/cron.hourly/)
ChronDaily=$(ls /etc/cron.daily/)
ChronWeekly=$(ls /etc/chron.weekly/)
ChronMontly=$(ls /etc/chron.monthly/)

echo 
echo "Hourly Tasks:"
echo "$ChronHourly"
echo
echo "Daily Tasks:"
echo "$ChronDaily"
echo
echo "Weekly Tasks:"
echo "$ChronWeekly"
echo
echo "Monthly Tasks:"
echo "$ChronMontly"
echo

# Network Information
ARPTable=$(arp)
MACAddresses=$(ip a | grep -o "link/[a-z0-9.]* [a-f0-9]*\:[a-f0-9]*\:[a-f0-9]*\:[a-f0-9]*\:[a-f0-9]*\:[a-f0-9]*")
RoutingTable=$(route)
IPv4=$(ip addr show | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")
IPv6=$(ip addr show | grep -o "inet6 [a-f0-9:]*")
DHCP=$(grep dhcp-server-identifier /var/lib/dhcp/dhclient.leases 2>/dev/null)
DNS=$(cat /etc/resolv.conf | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")
Gateways=$(route -n | grep '[ \t]' | awk '{print $2}' | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")
Listeners=$(netstat -pWtuna | grep 'LISTEN')
EstablishedConnections=$(netstat -pWtunav | grep 'ESTABLISHED')

echo "MAC Addresses in use"
echo "$MACAddresses"
echo
echo "IP Addresses in use"
echo "$IPv4"
echo "$IPv6"
echo
echo "DHCP Server"
echo "$DHCP"
echo
echo "Default Gateways"
echo "$Gateways"
echo
echo "Listening Services"
echo "$Listeners"
echo
echo "Established Connections"
echo "$EstablishedConnections"
echo

DNSCache=$(cat /etc/resolv.conf)
echo "DNS Cache"
echo "$DNSCache"
echo

# Wifi Information
echo "Wifi Access Profiles"
echo $(ls /etc/NetworkManager/system-connections)

# Printer Information
echo 'Printers: '$(lpstat -p -d 2>&1)
echo

echo "Installed Packages"
# echo $(apt list)
echo $(compgen -c)

echo "Processes"
echo $(ps -eHo ppid,pid,comm,user)


for driver in `lsmod`
do
	check=`modinfo $driver 2>/dev/null`
	if [ $? -eq 0 ]
	then
		ProviderName=$(modinfo $driver | grep 'author')
		Version=$(modinfo $driver | grep 'vermagic')
		FileLocation=$(modinfo $driver | grep 'filename')
		echo "Driver Name: $driver"
		echo " $ProviderName"
		echo " $Version"
		echo " $FileLocation"
		echo
	fi
done

for user in `ls /home/`
do
	echo 'User: '$user
	echo 'Downloads'
	echo $(ls /home/$user/Downloads/)
	echo 'Desktop'
	echo $(ls /home/$user/Desktop/)
	echo
done

echo "Grub Bootload Entries"
echo "$(awk -F\' '/menuentry / {print $2}' /boot/grub/grub.cfg)"
echo

echo "Known Hosts"
echo "$(cat /etc/hosts)"
echo
echo "$(cat /etc/hosts.allow)"
echo

echo "Firewall Configuration"
echo "$(iptables -L)"
echo

