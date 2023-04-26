# Linux 資訊安全檢測與漏洞分析
###### 【Linux Information Security Scanning And Vulnerability Assessment】
:::info
- **Study: Linux資訊安全檢測與漏洞分析**
- **Author: [name=張呈顥(武田奈々)][$_{link}$](https://windware1203.github.io/takeda.github.io/html/about.html)**
- **Advisor: [name=盧東華][$_{link}$](http://dhluserver.utaipei.edu.tw/)**
:::
## Keypoint
- Linux 防火牆系統與設定
- 資安弱點掃描與檢測
- 自動化腳本撰寫
- 漏洞利用與原理

---
:::danger
**All BASH commands are executed in the ==root== permission necessarily.**
:::


## Lynis
> ***Lynis, an introduction
> Auditing, system hardening, compliance testing***

### 1. Install
```bash=
# Github
git clone https://github.com/CISOfy/lynis
cd lynis
chmod +x ./lynis
./lynis

# yum
yum install lynis -y
```
>executing screen
>![](https://i.imgur.com/SFLTDKF.png)

### 2. Updating Check
```bash=
lynis update info
```
>It shows that is the least version.
>![](https://i.imgur.com/uaVIHUA.png)

### 3. Start the audit
```bash=
sudo lynis audit system
```
>Then, we got the scan details
>![](https://i.imgur.com/0xlKMHc.png)


---

## polkit之pkexec指令可進行提權
> - [第一次業師報告](https://www.canva.com/design/DAFeAKyP_Ss/sYjOtouW9QDGm4vOc395GQ/view#1)(CVE-2021-4034)
### polkit簡介
`polkit` 是一個在Unix like作業系統中，用來控制系統process權限的一套工具。它提供非特權processes以一個有系統性的方式與特權processes進行溝通；也可以使用`polkit`裡面具有提升權限的指令`pkexec`，來取得root特權(與`sudo`不同，polkit並沒有賦予完全的root權限)。
> "Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged ones.  It is also possible to use polkit to execute commands with elevated privileges using the command pkexec followed by the command intended to be executed (with root permission)." (Wikipedia)

[Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)研究員形容此漏洞是攻擊者的美夢成真：
- pkexec被預設安裝在Linux的各個發行版上
- 此漏洞自2009年5月就存在了(commit c8c3d83,"Add a `pkexec(1)` command")
- 任何非特權使用者都可以取得完整的root權限
- 就算polkit本身沒有運作，此漏洞也可以被利用


另外，pkexec是一個sudo-like, SUID(SetUID)-root 工具，它的相關宣告如下：
```
NAME
       pkexec - Execute a command as another user

SYNOPSIS
       pkexec [--version] [--disable-internal-agent] [--help]

       pkexec [--user username] PROGRAM [ARGUMENTS...]

DESCRIPTION
       pkexec allows an authorized user to execute PROGRAM as another user. 
       If PROGRAM is not specified, the default shell will be run.
       If username is not specified, then the program will be executed as the administrative super user, root.
```  

### 漏洞分析
接著，我們要觀察[pkexec.c](https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.120/src/programs/pkexec.c)







### 漏洞復現

#### 環境
:::success
- **Linux版本:** Linux localhost.localdomain 3.10.0-1160.21.1.el7.x86_64 #1 SMP Tue Mar 16 18:28:22 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
![](https://i.imgur.com/QOoKszB.png)

- **pkexec版本:** 0.112
![](https://i.imgur.com/v3A9Ftv.png)

:::

> 提權前狀況
![](https://i.imgur.com/E3nJJ1K.png)

> 執行破解程式後
![](https://i.imgur.com/5uSU5QJ.png)

### 文獻
- [1] [pkexec.c](https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.120/src/programs/pkexec.c)
- [2] [PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
- [3] [CVE-2021-4034 polkit（pkexec）提权漏洞复现](https://cloud.tencent.com/developer/article/1945253)
- [4] [CVE-2021-4034 pkexec 本地提权漏洞利用解析](https://www.anquanke.com/post/id/267774#h3-5)
- [5] [Qualys Security Advisory](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
- [6] [NIST](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
- [7] [RedHat](https://access.redhat.com/security/vulnerabilities/RHSB-2022-001)
- [8][深入分析](https://xz.aliyun.com/t/10870)

## chkrootkit

Chkrootkit – Linux Rootkit掃瞄器

Chkrootkit亦是一個免費及開源的rootkit掃瞄工具，它能夠在Unix系統上進行本機檢查rootkit的跡象。它有助於檢測隱藏的安全漏洞。Chkrootkit包含一個shell腳本及一個程序，Shell腳本將會檢查系統二進制文件以進行rootkit修改，而程序將會檢查各種安全問題。

*chkrootkit工具於Debian的系統下安裝得比較簡單*

$ sudo apt install chkrootkit

於CentOS系統中你需要透過以下指令去下載。
```
# yum update
# yum install wget gcc-c++ glibc-static
# wget -c ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
# tar –xzf chkrootkit.tar.gz
# mkdir /usr/local/chkrootkit
# mv chkrootkit-0.53/* /usr/local/chkrootkit
 (請檢查解壓後會是什麼版本，自行套落0.5X)
# cd /usr/local/chkrootkit
# make sense
```
現在可以開始運行Chkrootkit！
```
$ sudo chkrootkit （Debian）
OR
# /usr/local/chkrootkit/chkrootkit （CentOS）
```
完成運作後您就能夠在報告中看到自己的伺服器有沒有惡意軟件及Rootkit。

如上，如果您想要每晚自動運行及收到電郵通知，可以透過以下cron job在晚上3點自動運行並將報告發送到您的電子郵件地址。
```
0 3 * * * /usr/sbin/chkrootkit 2>&1 | mail -s "chkrootkit Reports of My Server" name@example.com
```
## ClamAV
```
# yum -y update
 （CentOS 第1步）
# yum -y install clamav （CentOS 第2步）

安裝後啟動是十分簡單的。

# freshclam
# clamscan -r -i DIRECTORY
```
## LMD


[ref](https://www.ltsplus.com/linux/centos-7-install-lmd-clam-antivirus)
