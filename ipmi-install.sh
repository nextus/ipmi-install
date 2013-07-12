#/usr/bin/env bash

# v. 0.4

if [[ $UID -ne 0 ]]; then
    echo "You need root permissions to run this script. Exiting..."
    exit 1
fi

IPMI=$(command -v ipmitool)

if [[ "$?" -ne 0 ]]; then
    echo "ipmitool not installed"
    exit 1
fi

# password for IPMI access through network
PASSWORD=""

OS=$(uname -s)
IP="10.0.0."

MODULES_LINUX="ipmi_devintf ipmi_si ipmi_msghandler"

# create ipmi user and configuring network
initIPMI() {
   
    # block default user with empty password
    $IPMI user disable 1
    
    # create remote user with custom password and permissions
    $IPMI user set name 2 root
    $IPMI user set password 2 $PASSWORD
    $IPMI channel setaccess 1 2 ipmi=on link=on privilege=4
    $IPMI user priv 2 4 1
    
    # configure network preferences
    $IPMI lan set 1 ipaddr $IP
    $IPMI lan set 1 netmask 255.255.255.0
    $IPMI lan set 1 arp respond on
    $IPMI lan set 1 auth admin md5
    $IPMI lan set 1 cipher_privs aaaaaaaaaaaaaaa
    $IPMI lan set 1 access on
    
    # enable our root user
    $IPMI user enable 2
}

# don't used in programm right now
# some vendor specific tricks
SCAN_VENDOR() {
    VENDOR=$($IPMI fru print 0 | egrep "Board Mfg[ ]+:" | awk '{print $4}')

    if [[ $VENDOR = "DELL" ]]; then
    	SMBIOS=$(/usr/bin/which smbios-token-ctl 2> /dev/null | cut -d' ' -f1)
	    if [[ -z $SMBIOS ]]; then
    		echo "smbios-utils is not installed."
	    	exit 0
		    #wget -q -O - http://linux.dell.com/repo/community/bootstrap.cgi | bash
    		#wget -q -O - http://linux.dell.com/repo/hardware/latest/bootstrap.cgi | bash
	    	#sed -i -r '/^\[dell\-omsa\-.+\]$/,/^$/s/^(exclude=.*)$// ; /^\[dell\-omsa\-.+\]$/,/^$/s/^(bootstrapurl=.*)$/\1\nexclude=ipmitool\*/ ' /etc/yum.repos.d/dell-omsa-repository.repo
    		#yum install smbios-utils
	    	#SMBIOS=$(/usr/bin/which smbios-token-ctl 2> /dev/null | cut -d' ' -f1)
    	fi
	    # Console Redirection Failsafe BAUD Rate (115200)
    	$SMBIOS --activate -i 0x4033
	    # Serial Communication (On with Console Redirection via COM2)
    	$SMBIOS --activate -i 0x017a
	    # Console Redirection Emulation Type (VT100)
    	$SMBIOS --activate -i 0x401a
	    # Console Redirection After Boot (Enabled)
    	$SMBIOS --activate -i 0x401c
    elif [[ $VENDOR != "Intel" ]]; then
	    echo "Unknown server board: $VENDOR. Exiting..."
    	exit 0
    fi
}

SOL_linux() {
    # define wich ttyS[01] is serial over lan port
    SETSERIAL=$(command -v setserial)

    if [[ "$?" -ne 0 ]]; then
        echo "setserial not installed"
        exit 1
    fi

    TTY=$($SETSERIAL -g /dev/ttyS[01] | grep -v unknown | tail -1 | sed 's:^/dev/ttyS\([01]\).*:\1:')

    # get centos major version
    CENTOS=$(rpm -qa centos-release | cut -d"-" -f3)

    if [[ $CENTOS -le 5 ]]; then
        # sysv
    	sed -i.bak -r "/^S$TTY:[2-5]+:.*ttyS$TTY.*$/Id" /etc/inittab
	    echo "S$TTY:23:respawn:/sbin/agetty -L ttyS$TTY 115200 vt100" >> /etc/inittab
    	telinit q
    elif [[ $CENTOS -eq 6 ]]; then
        # upstart
        cat <<EOF > /etc/init/serial-ttyS$TTY.conf
# ttyS$TTY - agetty
#
# This service maintains a agetty on ttyS$TTY.
#
stop on runlevel [S016]
start on runlevel [23]
#
respawn
exec /sbin/agetty -L ttyS$TTY 115200 vt100
EOF
	    /sbin/stop serial-ttyS$TTY 2>&1 > /dev/null
    	/sbin/start serial-ttyS$TTY
	
	    sed -i.bak -e "/^ttyS$TTY$/d" /etc/securetty
    	echo ttyS$TTY >> /etc/securetty
    else
        echo "Unsupported CentOS version: $CENTOS"
        exit 1
    fi

    sed -i.bak -e "/^[[:space:]]*kernel / s/[[:space:]]*console=tty[^[:space:]]*//g" -e "s/\(^[[:space:]]*kernel .*\)$/\1 console=ttyS$TTY,115200 console=tty0/" -e "s/\(^[[:space:]]*splashimage=.*\)$/#\1/" /boot/grub/grub.conf
}

SOL_freebsd() {
    # get freebsd major version
    FREEBSD=$(uname -r | cut -c1)
    
    if [[ $FREEBSD -lt 6 ]]; then 
        echo "Unsupported version"
        exit 1
    fi

    # determine our COM port
    ID=$(vmstat -i | grep uart | head -1 | cut -d' ' -f2 | cut -c5)
    sed -i '' "/^ttyu${ID}[[:space:]]/d" /etc/ttys
    echo "ttyu${ID} \"/usr/libexec/getty std.115200\"   vt100  on secure" >> /etc/ttys

    kill -HUP 1

    for i in 'boot_multicons="YES"' 'boot_serial="YES"' 'comconsole_speed="115200"' 'console="comconsole,vidconsole"'; do
        OPT=$(echo $i | cut -d'=' -f1)
        sed -i '' "/^${OPT}=/d" /boot/loader.conf
        echo "${i}" >> /boot/loader.conf
    done

    echo '-PDh -S115200' > /boot.config
}

case $OS in 
    Linux)
        MODPROBE=$(command -v modprobe)
        for i in $MODULES_LINUX; do
			$MODPROBE $i
            if [[ $? -ne 0 ]]; then
                echo "Error loading module: $i"
                exit 1
            fi
		done
        # waiting until kernel modules is load: modprobe returns tty before the module is really loaded
        sleep 2
		IP=$IP`ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | head -1 | cut -d: -f2 | awk '{ print $1}' | awk -F. '{print $4}'`
        initIPMI
        SOL_linux
		;;
	FreeBSD)
        KLDLOAD=$(command -v kldload)
		$KLDLOAD ipmi 2> /dev/null
		IP=$IP`ifconfig  | grep -E 'inet.[0-9]' | grep -v '127.0.0.1' | head -1 | awk '{ print $2}' | awk -F. '{print $4}'` 
        initIPMI
        SOL_freebsd
		;;
	*)
		echo "Unsupported OS"
		exit 1
		;;
esac

###############
# SOL Section #
###############

# set console speed
$IPMI sol set non-volatile-bit-rate 115.2 1
$IPMI sol set volatile-bit-rate 115.2 1
$IPMI sol payload enable 1 2

# it shit doesn't work for some reason!
#$IPMI sol set privilege-level admin 1

# finally, enabling SOL
$IPMI sol set enabled true 1

exit 0
