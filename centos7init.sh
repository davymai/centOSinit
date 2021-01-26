#!/bin/bash
#################################################
#  --Info
#      Panda Initialization CentOS 7.x script
#################################################
#   File: centos7-init.sh
#
#   Usage: sh centos7-init.sh
#
#   Auther: PandaMan ( i[at]davymai.com )
#
#   Link: https://xmyunwei.com
#
#   Version: 3.0
#################################################
# set parameter
export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
clear

function INFO() {
    echo -e "\e[$1;49;1m $3 \033[39;49;0m"
    sleep "$2"
    echo ""
}
#安装目录
ENV_PATH="/usr/local"
#源码包存放目录
SOURCE_PATH="$(cd $(dirname -- $0); pwd)/install_tar"
#LNMP配置文件的目录
CONF_PATH="$(cd $(dirname -- $0); pwd)/conf"
#逻辑CPU个数
THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

printf "
 +------------------------------------------------------------------------+
 |                      熊猫 CentOS 7.x 初始化脚本                        |
 |       To initialization the system for security and performance        |
 |                     初始化系统以提高安全性和性能                       |
 +------------------------------------------------------------------------+
                           version: 3.0
                      updated date: 2020-10-31

        Initialization begin after \e[31;1m5 \e[32;0mseconds, press Ctrl C to cancel.
                 初始化脚本 \e[31;1m5 \e[32;0m秒后开始, 按 ctrl C 取消。
"
echo ""

# Check if user is root
if [ $(id -u) != "0" ]; then
    INFO 31 1 "Error: You must be root to run this script, please use root to initialization OS.\n 错误：您必须是 root 用户才能运行此脚本，请使用 root 用户身份来初始化操作系统。"
    exit 1
fi
sleep 5

# start Time
startTime=$(date +%s)

# 更新系统并安装软件包
system_update() {
    INFO 35 2 "*** Starting update system && install tools pakeage... ***\n        *** 正在启动更新系统 && 安装工具包... ***"
    curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
    yum -y upgrade
    command -v lsb_release > /dev/null 2>&1 || {
        [ -e "/etc/euleros-release" ] && yum -y install euleros-lsb || yum -y install redhat-lsb-core
    }
    command -v gcc > /dev/null 2>&1 || yum -y install gcc
    # install openssh-server openssh-clients
    yum -y install openssh-server openssh-clients
    # install vim authconfig libselinux-utils initscripts net-tools
    yum install -y vim authconfig libselinux-utils initscripts net-tools
    rm -rf /var/cache/yum/*
    [ $? -eq 0 ] && INFO 36 2 "System upgrade && install pakeages complete.\n 系统升级和程序安装完成。"
}

# 删除无用的用户和组
user_del() {
    INFO 35 2 "Delete useless user\n 删除无用的用户和组"
    userdel -r adm
    userdel -r lp
    userdel -r games
    userdel -r ftp
    groupdel adm
    groupdel lp
    groupdel games
    groupdel video
    groupdel ftp
    echo ""
    INFO 36 2 "Delete useless user is successful...\n删除无用的用户完成。"
}

# 配置DNS服务器
config_nameserver() {
    nameserver=$(grep nameserver /etc/resolv.conf | wc -l)
    if [ $nameserver -ge 1 ]; then
        INFO 31 2 "nameserver is exist.\nDNS服务器已存在。"
    else
        INFO 32 2 "add nameserver in /etc/resolv.conf"
        echo "nameserver 223.5.5.5" >> /etc/resolv.conf
        INFO 36 2 "nameserver config complete.\nDNS服务器配置完成。"
    fi
}

# 设置时区同步
timezone_config() {
    INFO 35 2 "Setting timezone: Asia/Shanghai...\n设置时区为: Asia/Shanghai"
    /usr/bin/timedatectl | grep "Asia/Shanghai"
    if [ $? -eq 0 ]; then
        INFO 33 1 "System timezone is Asia/Shanghai.\n系统时区为Asia/Shanghai。"
    else
        timedatectl set-local-rtc 0 && timedatectl set-timezone Asia/Shanghai
    fi
    # config chrony
    #yum -y install chrony
    #sed -i '/server 3.centos.pool.ntp.org iburst/a\\server ntp1.aliyun.com iburst\nserver ntp2.aliyun.com iburst\nserver ntp3.aliyun.com iburst\nserver ntp4.aliyun.com iburst\nserver ntp5.aliyun.com iburst\nserver ntp6.aliyun.com iburst\nserver ntp7.aliyun.com iburst' /etc/chrony.conf
    #systemctl enable chronyd.service && systemctl start chronyd.service
    INFO 36 2 "Setting timezone & Sync network time complete.\n设置时区和同步网络时间完成。"
}



# 禁用 selinux
selinux_config() {
    if [ -e "/etc/selinux/config" ]; then
        INFO 31 2 "selinux not installed.\n未安装selinux。"
    else
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
        INFO 36 2 "Dsiable selinux complete.\n禁用selinux完成。"
    fi
}

# 配置 ulimit
ulimit_config() {
    INFO 35 2 "Starting config ulimit...\n开始配置ulimit..."
    if [ ! -z "$(grep ^ulimit /etc/rc.local)" -a "$(grep ^ulimit /etc/rc.local | awk '{print $3}' | head -1)" != '655360' ]; then
        sed -i 's@^ulimit.*@ulimit -SHn 655360@' /etc/rc.local
    else
        sed -i '$ a\ulimit -SHn 655360' /etc/rc.local
    fi
    cat > /etc/security/limits.conf << EOF
* soft nproc 102400
* hard nproc 102400
* soft nofile 102400
* hard nofile 102400
EOF
    ulimit -n 102400
    [ $? -eq 0 ] && INFO 36 2 "Ulimit config complete!\nUlimit配置完成！"
}

# 配置 bashrc
bashrc_config() {
    INFO 35 2 "Starting bashrc config...\n开始配置系统变量..."
    cp -f /etc/bashrc /etc/bashrc-bak
    echo "export PS1='\[\e[37;1m\][\[\e[35;49;1m\]\u\[\e[32;1m\]@\[\e[34;1m\]\h \[\e[37;1m\]➜ \[\e[31;1m\]\w \[\e[33;1m\]\t\[\e[37;1m\]]\[\e[32;1m\]$\[\e[m\] '" >> /etc/bashrc
    sed -i '$ a\set -o vi\nalias vi="vim"\nalias ll="ls -ahlF --color=auto --time-style=long-iso"\nalias ls="ls --color=auto --time-style=long-iso"\nalias grep="grep --color=auto"\nalias fgrep="fgrep --color=auto"\nalias egrep="egrep --color=auto"' /etc/bashrc
    INFO 36 2 "bashrc set OK!!\n系统变量设在完成！！"
}

# 配置 sshd
sshd_config() {
    INFO 35 2 "Starting config sshd...\n开始配置系统权限..."
    sed -i '/^#Port/s/#Port 22/Port '$sshp'/g' /etc/ssh/sshd_config
    sed -i '/^#UseDNS/s/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
    #禁用密码登陆
    #sed -i '/^PasswordAuthentication yes/s/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    sed -i '/^#PubkeyAuthentication/s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
    sed -i "s/UsePAM.*/UsePAM yes/g" /etc/ssh/sshd_config
    sed -i '/^GSSAPIAuthentication/s/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
    #if you do not want to allow root login,please open below
    #sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    systemctl restart sshd
    [ $? -eq 0 ] && INFO 36 2 "SSH port $sshp config complete.\nSSH 端口: $sshp 设置完毕。"
}

# 配置 firewalld
config_firewalld() {
    INFO 35 2 "Starting config firewalld...\n开始配置firewallD防火墙..."
    rpm -qa | grep firewalld >> /dev/null
    if [ $? -eq 0 ]; then
        #systemctl stop firewalld && systemctl disable firewalld
        firewall-cmd --permanent --add-port=$sshp/tcp
        firewall-cmd --rel
        firewall-cmd --list-all
        [ $? -eq 0 ] && INFO 36 2 "Config firewalld complete.\n防火墙配置完成。"
    else
        INFO 35 2 "Firewalld not install.\n没有安装FirewallD。"
    fi
}

# 配置vim
vim_config() {
    INFO 35 2 "Starting vim config...\n开始配置vim..."
    /usr/bin/egrep pastetoggle /etc/vimrc >> /dev/null
    if [ $? -eq 0 ]; then
        INFO 35 2 "vim already config\nvim已经配置"
    else
        sed -i '$ a\set pastetoggle=<F9>\nsyntax on\nset nu!\nset tabstop=4\nset softtabstop=4\nset shiftwidth=4\nset expandtab\nset bg=dark\nset ruler\ncolorscheme ron' /etc/vimrc
        INFO 36 2 "vim configuration is successful...\nvim配置成功..."
    fi
}

# 配置sysctl
config_sysctl() {
    INFO 35 2 "Staring config sysctl...\n开始配置sysctl..."
    cp -f /etc/sysctl.conf /etc/sysctl.conf.bak
    cat /dev/null > /etc/sysctl.conf
    cat > /etc/sysctl.conf << EOF
fs.file-max = 655350
vm.swappiness = 0
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
fs.suid_dumpable = 0
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144
# 开启SYN洪水攻击保护
net.ipv4.tcp_syncookies = 1
# 开启重用。允许将TIME-WAIT sockets 重新用于新的TCP 连接
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
# timewait的数量，默认18000
net.ipv4.tcp_max_tw_buckets = 8000
net.ipv4.tcp_fin_timeout = 30
# 当keepalive 起用的时候，TCP 发送keepalive 消息的频度。缺省是2 小时
net.ipv4.tcp_keepalive_time = 600
# 开启反向路径过滤
net.ipv4.conf.all.rp_filter = 1
EOF
    INFO 36 2 "sysctl config complete.\nsysctl 配置完成。"
}

# 禁用IPv6
disable_ipv6() {
    INFO 35 2 "Starting disable IPv6...\n开始禁用IPv6..."
    sed -i '$ a\net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
    sed -i '$ a\AddressFamily inet' /etc/ssh/sshd_config
    systemctl restart sshd
    /usr/sbin/sysctl -p
    sleep 3
    INFO 36 2 "disable IPv6 complete.\nIPv6禁用完成。"
}

# 密码配置
password_config() {
    INFO 35 2 "Starting config password rule...\n启动配置密码规则..."
    # /etc/login.defs  /etc/security/pwquality.conf
    sed -i '/PASS_MIN_LEN/s/5/8/g' /etc/login.defs
    #at least 8 character
    authconfig --passminlen=8 --update
    #at least 2 kinds of Character class
    authconfig --passminclass=2 --update
    #at least 1 Lowercase letter
    authconfig --enablereqlower --update
    #at least 1 Capital letter
    authconfig --enablerequpper --update
    INFO 36 2 "Config password rule complete(8 characters, must contain uppercase and lowercase letters).\n密码规则设置完成（8个字符，必须包含大小写字母）。"
}

# 禁用不使用服务
disable_serivces() {
    INFO 35 2 "Disable postfix service.\n禁用 postfix 服务。"
    systemctl stop postfix && systemctl disable postfix
    INFO 36 2 "Disable postfix service complete.\n禁用postfix服务完成。"
}

#创建新用户
user_create() {
    INFO 35 2 "Create User\n创建新用户"
    sleep 1
    read -p "输入用户名：" name
    printf "输入密码：\n"
    read -s -r pass
    printf "再次确认密码：\n"
    read -s -r passwd
    if [ $pass != $passwd ]
    then
        printf "两次密码输入有误, 请重新输入\n"
        user_create
    else
    printf "输入您的公钥(*重启后仅允许密钥登陆，禁止root用户登陆)：\n"
    read rsa
    printf "输入ssh端口号：\n"
    read sshp
    useradd -G wheel $name && echo $Password | passwd --stdin $name &> /dev/null
    cd /home/$name && mkdir .ssh && chown $name:$name .ssh && chmod 700 .ssh && cd .ssh
    echo "$rsa" >> authorized_keys && chown $name:$name authorized_keys && chmod 600 authorized_keys
    echo "$name ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
    history -cw
    sleep 3
    echo ""
    INFO 36 2 "User: \e[33;1m$name \e[36;1mcreate is successful..."
    echo ""
fi
}

other() {
    # Record command
    # lock user when enter wrong password root 10s others 180s
    sed -i '1aauth       required     pam_tally2.so deny=3 unlock_time=180 even_deny_root root_unlock_time=10' /etc/pam.d/sshd
    yum clean all
    sleep 3
}

#main function
main() {
    system_update
    config_nameserver
    timezone_config
    selinux_config
    ulimit_config
    bashrc_config
    vim_config
    config_sysctl
    disable_ipv6
    password_config
    disable_serivces
    user_del
    user_create
    sshd_config
    config_firewalld
    other
}
# execute main functions
main

endTime=$(date +%s)
((installTime = (endTime - startTime) / 60))
printf "
 Total initialization Install Time: \e[35;1m${installTime} \e[32;0mminutes
 +------------------------------------------------------------------------+
 |               To initialization system all completed !                 |
 |                        系统初始化全部完成 ！                           |
 +------------------------------------------------------------------------+
"
ipadd=$(ifconfig eth0 | awk '/inet/ {print $2}' | cut -f2 -d ":" | awk 'NR==1 {print $1}')
INFO 32 1 "Initialization is complete, please \e[31;1mreboot \e[32;1mthe system!!\n 系统初始化完成，请确认无误之后执行 \e[31;1mreboot \e[32;1m重启系统！\n================================\nssh端口号：\e[33;1m$sshp\n\e[32;1m服务器IP：\e[33;1m$ipadd\n\e[32;1m用户名：\e[33;1m$name\n\e[32;1m密码：\e[33;1m$passwd\n\e[32;1m请牢记您的密码!!!\n================================\n远程访问：\e[33;1mssh -p $sshp -i ~/.ssh/私钥文件 $name@$ipadd"
cat /dev/null > ~/.bash_history && history -c