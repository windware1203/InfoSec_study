# Linux 資訊安全檢測與漏洞分析

[![hackmd-github-sync-badge](https://hackmd.io/n57-QrYMQlutygt1StYxiw/badge)](https://hackmd.io/n57-QrYMQlutygt1StYxiw)

###### 【Linux Information Security Auditing And Exploitation Analysis】
:::info
- **Study: Linux資訊安全檢測與漏洞分析**
- **Author: [name=張呈顥(武田奈々)][$_{link}$](https://windware1203.github.io/takeda.github.io/html/about.html)**
- **Advisor: [name=盧東華][$_{link}$](http://dhluserver.utaipei.edu.tw/)**
- **[GitHub](https://github.com/windware1203/InfoSec_study)**
:::
## :star: Keypoint
- 資安弱點掃描與檢測
- 自動化腳本撰寫
- Linux kernel and applications 漏洞利用與原理(CVE-2021-4034)
- Looney Tunables: Local Privilege Escalation in the glibc's `ld.so`(CVE-2023-4911)



:::danger
**All BASH commands are executed in the ==root== permission necessarily.**
:::

## :star: yum update
### $\rm I、$ auto-update

Switch to the root user's crontab:

```bash
sudo crontab -e
```

Add the following line to schedule monthly system updates, ensuring that it runs with sudo:

```bash
0 3 1 * * sudo /usr/bin/yum -y update
```

In this line:

0 3 1 * * specifies the timing to run the update on the 1st day of every month at 3:00 AM.

sudo /usr/bin/yum -y update is the command to update all installed packages using yum. The -y flag answers "yes" to any prompts that may come up during the update process.

## :star: Lynis
> ***Lynis, an introduction
> Auditing, system hardening, compliance testing***

### $\rm I、$ Install
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

### $\rm II、$ Updating Check
```shell=
lynis update info
```
>It shows that is the least version.
>
>![](https://i.imgur.com/uaVIHUA.png)

### $\rm III、$ Start the audit
```shell=
sudo lynis audit system
```
>Then, we got the scan details
>
>![](https://i.imgur.com/0xlKMHc.png)

### $\rm IV、$ Auto-scanning one a month
Open your terminal and run the following command to edit your crontab file:

```bash=
crontab -e
```

Add the following line to schedule a monthly Lynis scan with a dynamic log file name that includes the month:

```bash=
0 3 1 * * /usr/sbin/lynis audit system --cronjob > /var/log/lynis_$(date +\%Y\%m).log
```
In this modified cron job:

- `0` : Specifies the minute (0-59).
- `3` : Specifies the hour (0-23).
- `1` : Specifies the day of the month (1-31).
- `*` : Specifies the month (1-12).
- `*` : Specifies the day of the week (0-6, where 0 is Sunday).

`0 3 1 * *` specifies the timing to run the Lynis scan on the 1st day of every month at 3:00 AM.

`/usr/sbin/lynis audit system --cronjob` runs Lynis with the `--cronjob` flag to prevent Lynis from prompting for user input.

> /var/log/lynis_$(date +\%Y\%m).log redirects the output of the Lynis scan to a log file with a name that includes the current year and month (e.g., "lynis_202309.log" for September 2023).

Save the file and exit the text editor.
With this setup, each time the cron job runs, it will create a new log file with a name that includes the current year and month, ensuring that you have separate log files for each month.

## :star: polkit 之 **pkexec** 指令提權漏洞

> - **keyword: Local Privilege Escalation, out-of-bounds read/write, Memory corruption, SUID-root program**
> - **CVSS v. 3.x: $\color{red}{7.8\,\,\,\, HIGH}$**
> - [第一次業師報告](https://www.canva.com/design/DAFeAKyP_Ss/sYjOtouW9QDGm4vOc395GQ/view#1)(CVE-2021-4034)

### $\rm I、$ polkit簡介
`polkit` 是一個在Unix like作業系統中，用來控制系統process權限的一套工具。它提供非特權processes以一個有系統性的方式與特權processes進行溝通；也可以使用`polkit`裡面具有提升權限的指令`pkexec`，來取得root特權(與`sudo`不同，polkit並沒有賦予完全的root權限)。
> "Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged ones.  It is also possible to use polkit to execute commands with elevated privileges using the command pkexec followed by the command intended to be executed (with root permission)." (Wikipedia)

[Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)研究員形容此漏洞是攻擊者的美夢成真：
- **pkexec被預設安裝在Linux的各個發行版上**
- **此漏洞自2009年5月就存在了**
    - (commit c8c3d83,"Add a `pkexec(1)` command")
- **任何非特權使用者都可以取得完整的root權限**
- **就算polkit本身沒有運作，此漏洞也可以被利用**


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

### $\rm II、$ 漏洞分析
要分析此漏洞，我們要觀察source code-- [pkexec.c (ver. 0.120)](https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.120/src/programs/pkexec.c)，先從`main`函數著手：
```cpp
 435 main (int argc, char *argv[])
 436 {
 ...
 534   for (n = 1; n < (guint) argc; n++)
 535     {
 ...
 568     }
 ...
 610   path = g_strdup (argv[n]);
 ...
 629   if (path[0] != '/')
 630     {
 ...
 632       s = g_find_program_in_path (path);
 ...
 639       argv[n] = path = s;
 640     }
```
名詞解釋：
- `int argc`: argument count，意即引數的個數；根據`C99`規範 "The value of argc shall be nonnegative." argc的值應為非負整數。
- `char *argv[]`: argument value，引數的值。

此程式乍看之下並無任何問題，但在些許非正常使用情況下將造成漏洞威脅。  

正常情況下，`argc`的值至少為 $1$ ，因為argument list最少包括程式自身名稱；但不幸的是，若我們使用`execve()`進行系統呼叫的時候，傳遞給它的值為空的 i.e. `{NULL}`，此時的`argc`為 $0$，`argv[0]`為`NULL`，並且：
- line 534, 整數 `n` 將永遠是 $1$
- line 610, 指標 `path` 將因`argv[1]`造成越界讀取
- line 639, 指標`s`將越界寫入到`argv[1]`


那我們實際越界存取到的這個`argv[1]`究竟是什麼位置呢？要解答這個問題，必須先了解我們呼叫`execve()`的時候，kernel做了甚麼動作。當我們使用它新增了一個程式時，kernel會將引數、環境變數字串以及指標們（argv, envp）複製到此程式的堆疊結尾，圖例如下：
```
|---------+---------+-----+------------|---------+---------+-----+------------|
| argv[0] | argv[1] | ... | argv[argc] | envp[0] | envp[1] | ... | envp[envc] |
|----|----+----|----+-----+-----|------|----|----+----|----+-----+-----|------|
     V         V                V           V         V                V
 "program" "-option"           NULL      "value" "PATH=name"          NULL
```
因為`argv`及`envp`指標在記憶體中是連續的，我們可以輕易的觀察到，若`arcg`是 $0$，這個越界`argv[1]`其實是`envp[0]`，這個指標指向我們的第一個環境變數`value`。

- 在第610行，從`argv[1]`（即`envp[0]`）中讀取的程式路徑超出了範圍，並指向 "value"；
- 在第632行，這個路徑 "value" 被傳遞給`g_find_program_in_path()`（因為 "value" 不以斜線開頭，所以在第629行）；
- `g_find_program_in_path()`在我們的 PATH 環境變數的目錄中搜尋名為 "value" 的可執行檔；
    如果找到這樣的可執行檔，則將其完整路徑返回到 pkexec 的 main() 函數（在第632行）；
- 並且在第639行，將這個完整路徑寫出到`argv[1]`（即`envp[0]`），從而覆蓋我們的第一個環境變數。

更精確地說：

- 如果我們的`PATH`環境變數是`"PATH=name"`，而且十分剛好的這個目錄`name`存在在當前工作目錄，又更剛好的裡面有個可執行檔案`value`，然而此指向這個字串`"name/value"`會被越界寫入到`envp[0]`。
    > "PATH=name" 可替換成 "PATH=name=" 亦成立
- 換言之，此類的越界寫入允許我們重新引入這些不安全的環境變數到`pkexec`中(e.g., LD_PRELOAD)；此類不安全的變數通常在呼叫`main()`會被`ld.so`從SUID程式中移除。
- 此外，值得注意的是polkit也支援非Linux作業系統，如：Solaris、BSD；然而在OpenBSD中，因為其kernel不接受`argc`為 $\color{green}0$ 的`execve()`，此漏洞不可被利用。

至於要利用何種不安全的環境變數呢？這裡的選項是很有限的，因為在越界寫入後（at line 639）不久後，pkexec會==完全地==清除了他的環境變數（at line 702）。
```c
 639       argv[n] = path = s;
 ...
 657   for (n = 0; environment_variables_to_save[n] != NULL; n++)
 658     {
 659       const gchar *key = environment_variables_to_save[n];
 ...
 662       value = g_getenv (key);
 ...
 670       if (!validate_environment_variable (key, value))
 ...
 675     }
 ...
 702   if (clearenv () != 0)
```

[Qualys](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)指出，為了印出錯誤訊息到stderr， pkexec 呼叫了GLib的`g_printerr()`；
>the GLib is a [GNOME](https://www.gnome.org/) library, not the GNU C Library, aka glibc

e.g., `validate_environment_variable()` 和
`log_message()` 呼叫了 `g_printerr()` (at lines 126 and 408-409)：

```c!
  88 log_message (gint     level,
  89              gboolean print_to_stderr,
  90              const    gchar *format,
  91              ...)
  92 {
 ...
 125   if (print_to_stderr)
 126     g_printerr ("%s\n", s);
 ...
 383 validate_environment_variable (const gchar *key,
 384                                const gchar *value)
 385 {
 ...
 406           log_message (LOG_CRIT, TRUE,
 407                        "The value for the SHELL variable was not found the /etc/shells file");
 408           g_printerr ("\n"
 409                       "This incident has been reported.\n");
```
`g_printerr()`通常會輸出UTF-8的錯誤訊息，但是若他的環境變數CHARSET不是UTF-8，他也可以輸出其他的字元集。
> 這裡的CHARSET與安全無關，他不是不安全的環境變數之一。

為了轉換錯誤訊息從UTF-8到其他字元集，pkexec呼叫了glibc的`iconv_open()`。

要將一種字元集的訊息轉換為另一種字元集，我們使用`iconv_open() `函數來執行相關的共享library來進行轉換操作。通常，這個函數會使用預設設定檔（通常在/usr/lib/gconv/gconv-modules）中的設定，包括來源字元集、目的字元集以及library name。不過，您也可以透過設定環境變數GCONV_PATH 來強制`iconv_open()` 使用其他設定檔案。需要注意的是，GCONV_PATH屬於一個「不安全」的環境變數，因為它有潛在的風險，可能會執行任意函式庫。因此，在SUID 程序的環境中，系統會自動刪除GCONV_PATH 變數，以確保安全性。


### $\rm III、$ 漏洞復現

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

### $\rm IV、$ 漏洞修補
>[pkexec.c (ver. 0.121)](https://gitlab.freedesktop.org/polkit/polkit/-/blob/121/src/programs/pkexec.c?ref_type=tags)

由於此CVE風險分數高達 **7.8**，修補十分迅速，邏輯也十分簡單明瞭。
```cpp=493
  /*
   * If 'pkexec' is called THIS wrong, someone's probably evil-doing. Don't be nice, just bail out.
   */
  if (argc<1)
    {
      exit(127);
    }
```
你沒有看錯，就是加上一個`if`進行`argc`的判斷，並且拋出`exit(127)`，如此暴力、簡單就能化解高風險漏洞；因此程式設計師對於變數、指標的變化必須要精確的掌控，以免發生此種越界讀寫的安全性問題。

> 會直接觸發`if`，拋出`exit()`
> ![](https://hackmd.io/_uploads/SJXNvjRy6.png)

### $\rm V、$ 文獻
- [1] [pkexec.c](https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.120/src/programs/pkexec.c)
- [2] [PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
- [3] [CVE-2021-4034 polkit（pkexec）提权漏洞复现](https://cloud.tencent.com/developer/article/1945253)
- [4] [CVE-2021-4034 pkexec 本地提权漏洞利用解析](https://www.anquanke.com/post/id/267774#h3-5)
- [5] [Qualys Security Advisory](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
- [6] [NIST](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
- [7] [RedHat](https://access.redhat.com/security/vulnerabilities/RHSB-2022-001)
- [8][深入分析](https://xz.aliyun.com/t/10870)

## :star: **Looney Tunables**: Local Privilege Escalation in the glibc's `ld.so`
> - **keywords: glibc, buffer overflow, SUID permission,**
> - **CVSS v. 3.x: $\color{red}{7.8\,\,\,\, HIGH}$** 
> - date: 2023/10/03
> - [CVE-2023-4911](https://www.ithome.com.tw/news/159146) 

> A buffer overflow was discovered in the GNU C Library’s dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

### reference
- [cve.mitre.org](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911)
- [Ubuntu](https://ubuntu.com/security/CVE-2023-4911)
- [qualys](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt)


## :star: chkrootkit

> Chkrootkit – Linux Rootkit Scanner

Chkrootkit亦是一個免費及開源的rootkit掃描工具，它能夠在Unix系統上進行檢查rootkit的跡象。它有助於檢測隱藏的安全漏洞。Chkrootkit包含一個shell腳本及一個程式，Shell腳本將會檢查系統二進位文件以進行rootkit修改，而程式將會檢查各種安全問題。

> *chkrootkit工具於Debian的系統下安裝得比較簡單*

```bash
$ sudo apt install chkrootkit
```

於CentOS系統中你需要透過以下指令去下載。
```bash
yum update
yum install wget gcc-c++ glibc-static
wget -c ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
tar –xzf chkrootkit.tar.gz
mkdir /usr/local/chkrootkit
mv chkrootkit-0.53/* /usr/local/chkrootkit
# (請檢查解壓後會是什麼版本，自行套落0.5X)
cd /usr/local/chkrootkit
make sense
```
現在可以開始run Chkrootkit！
```bash
sudo chkrootkit （Debian）
#OR
/usr/local/chkrootkit/chkrootkit （CentOS）
```
跑完後您就能夠在報告中看到自己的伺服器有沒有惡意軟體及Rootkit。

如上，如果您想要每晚自動運行及收到電郵通知，可以透過以下cron job在晚上3點自動執行並將報告發送到您的電子郵件地址。
```bash
0 3 * * * /usr/sbin/chkrootkit 2>&1 | mail -s "chkrootkit Reports of My Server" name@example.com
```
## :star: ClamAV
>ClamAV, short for "Clam AntiVirus," is an open-source antivirus software toolkit designed to detect and combat various forms of malware, including viruses, trojans, worms, and other malicious software. ClamAV is widely used in both personal and professional settings to provide an additional layer of security against malware threats.
```bash
yum -y update
yum -y install clamav

安裝後啟動是十分簡單的。

freshclam
clamscan -r -i DIRECTORY
```
## LMD


[ref](https://www.ltsplus.com/linux/centos-7-install-lmd-clam-antivirus)

## 外部掃描
- Nessus

## 漏洞
Nessus偵測之漏洞： HTTP TRACE / TRACK Methods Allowed
CVSS V3.0: 5.3 



HTTP TRACE/TRAC 通常用於 Debug，如何驗證系統是否真的有開啟 TRACE/TRACK 之功能，可使用telnet 網頁所在  80 port：
`telnet 127.0.0.1 80`
之後輸入
`TRACE / HTTP/1.1
Host: localhost.localdomain`
再連續按兩下 Enter

若系統有回應：
`HTTP/1.1 200 OK`

表示確實HTTP TRACE / TRACK Methods Allowed。
那該如何關閉呢？可在 Apache 之設定檔 httpd.conf 加上 TraceEnable off 即可。
`vi /etc/httpd/conf/httpd.conf`
加上字串：`"TraceEnable off"`

接著重新啟動 Apache 即可 `service httpd restart`



使用 telnet 再測試一次，系統直接回應錯誤訊息：
`HTTP/1.1 403 Forbidden` 表示HTTP TRACE / TRACK 確實已關閉

## :star: 待研究 
- ~~[Shellshock](https://devco.re/blog/2014/09/30/shellshock-CVE-2014-6271/)~~
- [Exim Off-by-one RCE](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/)
