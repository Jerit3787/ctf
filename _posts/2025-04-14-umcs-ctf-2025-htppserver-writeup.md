---
title:  "UMCS CTF 2025 (Preliminary) - Writeup (Reverse Engineering - htpp-server)"
date:   2025-04-14 11:20:00 +0800
categories: [CTF Writeup, Reverse Engineering]
tags: [UMCS CTF 2025 (Preliminary)]
---
> This challenge was completed during the CTF.
{: .prompt-info}

## The problem

![](assets/img/image18.png)

The challenge is about a http server created by the author of the challenge. 

Different from web challenges, RE usually gives out binary for users to check their code etc.

In this challenge, it is provided the server's ip address and binary associated with the server created.

## Step 1 (Initial Analysis)

Upon inspection, the binary is `server.unknown` with an unknown extension which hides from us which platform the binary was supposed to run and also we don't know if it is a binary or compressed files. As this is my first time trying out a RE challenge, I scouted to the internet in identifying what tools are usually used to check the internals. I only have heard Ghindra which is the US Military/Cyber Military? tools for decompiling these binary. But, returned from the internet, people have been using `ida` which is a paid tool btw (have an education level for students to use for free).

Other than that, I also tried to run in my kali linux enviroment. By making it executable via `chmod +x <file>`, I was able to get some hints.

![](assets/img/image19.png)

It shows that it tries to create an socket and bind it with an IP Address. It does not tell what IP to bind with and what port does the software use. Thus, from this point, it is better we open up a decompiler to see whats up.

## Step 2 (Analyse the binary)

I started by opening IDA that i just installed in my kali linux and decompile the binary given.

![](assets/img/image20.png)

This is the interface of IDA it decompiles partially to its function name and you can see hierarchy of the function, which one does things first and where it would reference to. People usually decompile complete to create psedocode to be able to read the machine code better. I tried to create the psedocode and this is the main function.

> I'll just write here in case I forgot how to jump to the pseudocode view `Jump > Pseudocode` or `Tab` shortcut
{: .prompt-tip}

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  socklen_t addr_len; // [rsp+4h] [rbp-3Ch] BYREF
  int fd; // [rsp+8h] [rbp-38h]
  int v5; // [rsp+Ch] [rbp-34h]
  struct sockaddr s; // [rsp+10h] [rbp-30h] BYREF
  sockaddr addr; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  fd = socket(2, 1, 0);
  if ( fd <= 0 )
    puts("[!]Failed! Cannot create Socket!");
  else
    puts("[*]Socket Created!");
  memset(&s, 0, sizeof(s));
  s.sa_family = 2;
  *(_WORD *)s.sa_data = htons(0x1F90u);
  inet_aton("10.128.0.27", (struct in_addr *)&s.sa_data[2]);
  if ( bind(fd, &s, 0x10u) >= 0 )
  {
    puts("[*]IP Address and Socket Binded Successfully!");
    if ( listen(fd, 3) >= 0 )
    {
      puts("[*]Socket is currently Listening!");
      while ( 1 )
      {
        puts("[*]Server Started....");
        puts("[*]Waiting for client to connect.....");
        addr_len = 16;
        v5 = accept(fd, &addr, &addr_len);
        if ( v5 <= 0 )
          break;
        puts("[*]Client Connected!");
        if ( !fork() )
          sub_154B((unsigned int)v5);
      }
      puts("[!]Failed! Cannot accept client request");
      exit(1);
    }
    puts("[!]Failed! Cannot listen to the Socket!");
    exit(1);
  }
  puts("[!]Failed! IP Address and Socket did not Bind!");
  exit(1);
}
```
{: file="main"}

Based on the code, it tries to bind to `10.128.0.27` which is presumably an internal IP at its server, thus the IP wouldn't work on my machine.

Next, we decompile next important function

```c
unsigned __int64 __fastcall sub_154B(int a1)
{
  int v1; // eax
  size_t v2; // rax
  size_t v3; // rax
  size_t v4; // rax
  void *ptr; // [rsp+20h] [rbp-440h]
  FILE *stream; // [rsp+30h] [rbp-430h]
  size_t n; // [rsp+38h] [rbp-428h]
  _BYTE buf[1032]; // [rsp+50h] [rbp-410h] BYREF
  unsigned __int64 v10; // [rsp+458h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[*]Handling a Connection!");
  ptr = malloc(0x400u);
  v1 = malloc_usable_size(ptr);
  if ( (int)recv(a1, ptr, v1, 0) < 0 )
  {
    puts("[!]Failed! No Bytes Received!");
    exit(1);
  }
  if ( strstr((const char *)ptr, "GET /goodshit/umcs_server HTTP/13.37") )
  {
    stream = fopen("/flag", "r");
    if ( stream )
    {
      memset(buf, 0, 0x400u);
      n = fread(buf, 1u, 0x3FFu, stream);
      fclose(stream);
      v3 = strlen("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
      send(a1, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n", v3, 0);
      send(a1, buf, n, 0);
    }
    else
    {
      v2 = strlen("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nCould not open the /flag file.\n");
      send(a1, "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nCould not open the /flag file.\n", v2, 0);
    }
  }
  else
  {
    v4 = strlen("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot here buddy\n");
    send(a1, "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot here buddy\n", v4, 0);
  }
  return v10 - __readfsqword(0x28u);
}
```
{: file="sub_154B"}

Here, it shows that it has a path that can be accessed which is `/goodshit/umcs_server` that is accessible via `GET` request to the server. There is also a message `Not here buddy` if some might able to bind the IP address and able to access the server. Also, there is something wierd about how to access the path. It shows it was expecting `HTTP/13.37` which is an invalid HTTP version btw. So, we should try to access the server by specifying that version of HTTP.

> If you wanted to try out locally, you can add the ip address alias using this command. Which loops back to localhost and try accessing the server locally.
> ```bash
> sudo ip addr add 10.128.0.27/24 dev lo
> ```
{: .prompt-tip}

## Step 3 (Exploitation)

Since we already know all the contraints, we could just craft the command to fetch the flag on the target server. This time we can't use curl (i think?), because it uses a non-standard HTTP version (I think we could change the header btw I haven't tried yet.). Thus this netcat(nc) command works and allows to correctly craft the header etc.

```bash
printf "GET /goodshit/umcs_server HTTP/13.37\r\nHost: 34.133.69.112\r\n\r\n" | nc 34.133.69.112 8080
```

> After this, you should get the flag which is `umcs{http_server_a058712ff1da79c9bbf211907c65a5cd}`
{: .prompt-tip}

![](assets/img/image21.png)

## Closing

I didn't expect that RE challenge to be this easy. I was expecting something more difficult than this. So far, this is the last challenge that I was able to solve. I was trying another one but wasn't successful. I was so close to resolve it but yeah it always happens at every ctf that I keep avoiding doing something harder like setuping server etc. which interupts me and leaves me at a hook. So, thank you for reading till this point and I'll see you in the next one. Bye!