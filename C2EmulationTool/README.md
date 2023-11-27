# GobRAT C2 Emulation Tool
This tool is a C2 emulation tool that supports analysis of GobRAT malware. Since GobRAT uses gob, a data serialization protocol, to send and receive data, it is necessary to emulate it using the go language, which is supported. For more information on GobRAT, please refer to the JPCERT/CC blog.

## HOW TO INSTALL
```
git clone https://github.com/JPCERTCC/GobRAT-Analysis
cd GobRAT-Analysis/C2EmulationTool
go build GobRAT_Server.go
go build GobRAT_Client.go
```
- Prepare Self-Signed Certificate With **OpenSSL**.
    - `server.crt`
    - `server.key`

## USAGE
- Server
```
./GobRAT_Server [CommandID]
```

- Client
```
./GobRAT_Client
```

## DEMO GobRAT-Server (about 30s)

![](https://github.com/JPCERTCC/GobRAT-Analysis/blob/main/Demo/Emu_GobRAT-Server.gif)

## DEMO Client-Server (about 30s)

![](https://github.com/JPCERTCC/GobRAT-Analysis/blob/main/Demo/Emu_Client-Server.gif)

--- 

## Commands
The command emulation of this tool does not fully support command execution. Please use this tool only for the purpose of debugging or checking the operation for malware analysis:)

|Command ID| Content | Availability of tools| 
|:-----------:|:-----------|:-----------:|
 | 0x0	 | Update json data held in malware and acquire update results | <ul><li>- [x] </li></ul> | 
 | 0x1	 | Retrieve json data held in malware |  <ul><li>- [x] </li></ul> | 
 | 0x3	 | Start reverse shell |  <ul><li>- [x] </li></ul> | 
 | 0x4	 | End of reverse shell connection |  <ul><li>- [x] </li></ul> | 
 | 0x6	 | Confirmation of reverse shell connection |  <ul><li>- [x] </li></ul> | 
 | 0x7	 | Execute shell command for daemon |  <ul><li>- [x] </li></ul> | 
 | 0x8	 | Execute shell command |  <ul><li>- [x] </li></ul> | 
 | 0xD	 | Read/write specified file |  <ul><li>- [x] </li></ul> | 
 | 0x34	 | Get the specified file information |  <ul><li>- [ ] </li></ul> | 
 | 0x10,0x11 | Read/write specified file |  <ul><li>- [x] </li></ul> | 
 | 0x16	 | Obtain various machine information such as df command |  <ul><li>- [x] </li></ul> | 
 | 0x17	 | Set new communication channel for TCP |  <ul><li>- [x] </li></ul> | 
 | 0x18	 | Execute SOCKS5 proxy server with specified port, password and cipher |  <ul><li>- [x] </li></ul> | 
 | 0x19	 | Execute SOCKS5 proxy server with  specified port |  <ul><li>- [x] </li></ul> | 
 | 0x1a	 | New communication channel setting for UDP |  <ul><li>- [x] </li></ul> | 
 | 0x1b	 | Execute frpc after executing SOCKS5 proxy on port 5555 |  <ul><li>- [x] </li></ul> | 
 | 0x1f	 | Check for the existence of the specified file |  <ul><li>- [x] </li></ul> | 
 | 0x25	 | Login attempts for SSH, telenet, redis, mysql, postgres |  <ul><li>- [ ] </li></ul> | 
 | 0x27	 | Configuration of specified goroutine |  <ul><li>- [ ] </li></ul> | 
 | 0x2a	 | Scan to HTTP/HTTPS service of specified URL |  <ul><li>- [ ] </li></ul> | 
 | 0x2D	 | Dictionary attack to HTTP/HTTPS service of specified IP by use of basic and digest authentication |  <ul><li>- [ ] </li></ul> | 
 | 0x30	 | C2 configuration related |  <ul><li>- [ ] </li></ul> | 
 | 0x31	 | DDoS attacks on SYN, TCP, UDP, HTTP, ICMP, SSL, DNS, SOCKSTRESS |  <ul><li>- [ ] </li></ul> | 
 | 0x34	 | Get process information and Kill wget, curl, nc, ftp, tftp, ftpget and tftpget processes |  <ul><li>- [ ] </li></ul> | 
 | 0x35	 | Stop routine for command 0x34 |  <ul><li>- [ ] </li></ul> | 
 | 0x36	 | ICMP/TCP scan for internal network |  <ul><li>- [ ] </li></ul> | 
 | 0x39	 | Scan for loging SSH, telenet, redis, mysql, postgres and login attempts (using cuckoo filter) |  <ul><li>- [ ] </li></ul> | 
 | 0x3A	 | Add parameter on json data held in malware |  <ul><li>- [ ] </li></ul> | 
 | 0x3B	 | Reverse shell-related settings |  <ul><li>- [ ] </li></ul> | 
 | 0x3F	 | Check reverse shell status. |  <ul><li>- [ ] </li></ul> | 
 | 0x40	 | Execute shell commands in a reverse shell |  <ul><li>- [ ] </li></ul> | 
 | 0x41	 | Execute shell commands in a reverse shell |  <ul><li>- [ ] </li></ul> | 

--------

## Reference
- Gobs of data ![https://go.dev/blog/gob](https://go.dev/blog/gob)

## LICENSE
Please read the [LICENSE](https://github.com/JPCERTCC/aa-tools/blob/master/LICENSE.txt) page.






