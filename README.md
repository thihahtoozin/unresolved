# Unresolved
*A lightweight DNS resolver written in C*

## Description
**Unresolved** is a lightweight DNS resolver written in C. It  resolves local domains defined in the zone file and forwards unknown queries to an external resolver.

![image](images/unresolved.png)

## How it Works

1. The server loads the zone file under the `config/` directory at startup.

2. When a DNS client sends a request to the server
	- the server responds with the appropriate response if the domain is defined.
	- the server will forward the request to the external DNS resolver and relay the response back to the client if the domain is not found.


```                 
 +------------+ -----(request)--> +------------+                     +------------------+
 | DNS Client |                   | Unresolved | -----(forward)----> | External Resolver|
 +------------+ <---(response)--- +------------+                     +------------------+
       ^                              |                                    |
       |                              |                                    v
       |<------------(relay)----------|<-----------(response)--------------+
```


## Installation
Clone this repository and compile the code.
```bash
git clone https://github.com/thihahtoozin/unresolved.git
cd unresolved
make build/unresolved
```
Run the server.
```bash
./build/unresolved <ip> <udp:port>
```
Example:
```bash
./build/unresolved 127.0.0.1 5353
```

## Configuration
### Editing Zone File
**Unresolved** uses a zone file to define local domains. You can edit the file under the `config/` directory to customize your DNS zones.

```zone
$TTL 86400 ;
$ORIGIN segfault.local. ;
@   IN  SOA     ns1.segfault.local. hostmaster.segfault.local. (
            2024111401   ; Serial
            3600         ; Refresh
            1800         ; Retry
            1209600      ; Expire
            86400 )      ; Minimum TTL
@   IN  NS      ns1.segfault.local.
@   IN  A       172.20.10.14

ns1 IN  A       172.20.10.14      ; Replace with your server IP
ssh IN	A	    172.20.10.14      ; SSH Server

www IN  CNAME   segfault.local.   ; www is an alias of the root domain

```

Modify the IP address and the domain name to you needs or you can copy the file contents, pate them to your desired file location edit the address information.
Then you change the path in the `include/config.h` file.

```c
#define ZONE_FILE "config/zones/segfault.local.zone"    // Edit this line for changing the zone file path
#define EXT_SERV "8.8.8.8"                              // Edit this line for changing external server IP
#define EXT_SERV_PORT 53                                // Edit this line for changing external server PORT 
```
Here you can also change the address of external DNS resolver.

After editing the zone file, restart the program to apply changes.

## Examples Queries

Start the server
```bash
./build/unresolved 127.0.0.1 5353
```

Query local domains:
```bash
dig @127.0.0.1 -p 5353 segfault.local
dig @127.0.0.1 -p 5353 segfault.local NS
dig @127.0.0.1 -p 5353 www.segfault.local
```

Query external domains:
```bash
dig @127.0.0.1 -p 5353 www.archlinux.org
dig @127.0.0.1 -p 5353 www.raspberrypi.com
```