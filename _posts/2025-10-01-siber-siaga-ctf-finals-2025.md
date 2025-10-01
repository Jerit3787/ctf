---
title:  "Siber Siaga CTF 2025 (Finals) - Writeup"
date:   2025-10-01 13:52:00 +0800
categories: [CTF Writeup]
tags: [Siber Siaga CTF 2025]
authors: [jerit3787, mynz, rizzykun]
---
*By Team pulupuluultraman - Mynz, Jerit3787 & rizzykun*

> This challenge was completed during the CTF.
{: .prompt-info}

## Storyline
Theres a organisation discover that a threat group is planning a cyberwarfare against the nation. This poses a great danger for the country. You the players has been assigned as Bahagian Siber dan Elektromagnetik Pertahanan (BSEP) agent to find out who is responsible for this threat. The team have found one of the suspect that may have some sort of relation with the actual threat actor. Due to his poor Opsec, the team has targetted him as the starting point for this investigation.

## Challenge 1: The Starting Point

*By Rizzykun*

**Category:** OSINT

**Description:**

One of our agents managed to locate one of the suspects. We lost contact before he could tell us where he was. This snapshot was the only documentation he could send. Can you find where this place is?

Note: Use the google map name if you have found the location.

Flag format: SIBER25{main_street-town_name-state_name-country}

**Answer:**

Resource:

![](assets/img/siber-siaga-25-finals/image4.png)

So, this is the last place the suspect was seen, okay, Let's lock in!!
First, we need to identify where is this place, maybe the shops could help?

![](assets/img/siber-siaga-25-finals/image2.png)

So, he is near these shops. Let's try locating every single store.
When googling each of the store names, almost every single one returns that it is a part of multiple branches of a store chain in Russia except for Клубника, салон фотопечати (Strawberry, Photo Printing Salon). This store in an independent and unique store, then, I find a city website named chaykovsky which holds info about the store.

![](assets/img/siber-siaga-25-finals/image6.png)

![](assets/img/siber-siaga-25-finals/image3.png)

The website pinpoint the exact location of the store and give the address. Then, I enter the address in Google Maps and it gave the result:

![](assets/img/siber-siaga-25-finals/image5.png)

Then, we get the address and the following is the flag format we got:

>Flag: `SIBER25{ulitsa_sovetskaya-chaykovsky-perm_krai-russia}`
{: .prompt-tip}

The suspect was last seen located near mall named ТЦ (Мега).

## Challenge 2: Interceptosis

*By Jerit3787*

**Category:** Cryptography, Network Forensics
**Description:** 
Our team was able to intercept the suspect's message to his group. They may have sent something sensitive in the process, discover a way to decrypt the communication and figure out what their chat is about.

**Answer:**

We have a pcap file with files embedded inside.

As we follow one of the WebStream stream, we noticed this conversation has taken place.

```
Hey, you there?
Yeah, what's up solarizzer?
I'm at the depot... Now I'm locked out.
Did he tell you how he encrypted the firmware?...
Yeah, probably. I need to check the group chat history. Thanks.
```

And then the suspect downloaded a log conversation between them.

The conversation is encrypted and is unreadable. But, the image gave us a hint on which encryption is being used. 

![](assets/img/siber-siaga-25-finals/image7.jpeg)

The function is as follows.

```py
def encrypt_conversation(plaintext_message, key, nonce): 
#Pwease note that we are using same key and nonce for convenience :3 cipher = AES.new(key, AES.MODE_CTR, nonce=nonce) 
ciphertext = cipher.encrypt(plaintext_message.encode('utf-8')) 
return ciphertext.hex()
```

This confirms that the encryption is using `AES (CTR MODE)` and using a repeated key during encryption which leads to a vulnerability.

Another hint was that the conversation starts with `!init <MyUsername>`. If we have a plaintext-ciphertext combination, we could use XOR/Known Plain Text Attack to decrypt the other parts of the conversation. But, due to the known text being too short, we opted to use Repeated Key Attack with AES CTR statistical method that guesses until a proper or near to an english word is formed. This produced better results.

>Get to know better about AES CTR Mode with its associated attack from https://book.jorianwoltjer.com/cryptography/aes#repeated-key-attack. Sample code are taken from this guide!
{: .prompt-tip}

```py
#!/usr/bin/env python3


import re
from string import ascii_letters, digits, punctuation


# Extended alphabet for scoring - includes common chat characters
ALPHABET = list(b" {}_Ee3Aa@4RrIi1Oo0Tt7NnSs25$LlCcUuDdPpMmHhGg6BbFfYyWwKkVvXxZzJjQq89-,.!?'\"\n\r#%&()*+/\\:;<=>[]^`|~")


def parse_chat_log(filename):
   """Parse the chat log and extract hex-encoded messages"""
   messages = []
  
   with open(filename, 'r') as f:
       content = f.read()
  
   # Extract hex messages (find lines with usernames and hex data)
   lines = content.strip().split('\n')
   for line in lines:
       if ' : ' in line and not line.startswith('---'):
           parts = line.split(' : ', 1)
           if len(parts) == 2:
               username, hex_data = parts
               # Validate that it's hex data
               try:
                   bytes.fromhex(hex_data.strip())
                   messages.append((username.strip(), hex_data.strip()))
               except ValueError:
                   continue
  
   return messages


def hex_to_bytes(hex_string):
   """Convert hex string to bytes"""
   return bytes.fromhex(hex_string)


def bytes_to_hex(data):
   """Convert bytes to hex string"""
   return data.hex()


def byte_xor(ba1, ba2):
   """XOR two byte arrays"""
   return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def score_text(s):
   """Score text based on character frequency"""
   if not s:
       return 0
   try:
       # Convert bytes to characters and score
       text = s.decode('utf-8', errors='ignore')
       score = sum(len(ALPHABET) - ALPHABET.index(ord(c)) for c in text if ord(c) < 256 and chr(ord(c)).encode('latin1') in ALPHABET)
       return score / len(text) if len(text) > 0 else 0
   except:
       # Fallback: score as raw bytes
       score = sum(len(ALPHABET) - ALPHABET.index(c) for c in s if c in ALPHABET)
       return score / len(s) if len(s) > 0 else 0


def attack_stream_cipher(ciphertexts):
   """Attack stream cipher with reused key using frequency analysis"""
   # Convert hex strings to bytes
   encrypted_messages = [hex_to_bytes(msg) for _, msg in ciphertexts]
  
   # Find the longest message
   max_length = max(len(msg) for msg in encrypted_messages)
   print(f"Found {len(encrypted_messages)} messages, max length: {max_length} bytes")
  
   # For each position, try all possible key bytes
   recovered_key = b""
  
   for position in range(max_length):
       best_score = 0
       best_key_byte = 0
      
       for key_byte in range(256):
           # XOR this key byte with all messages at this position
           decrypted_chars = []
           for msg in encrypted_messages:
               if position < len(msg):
                   decrypted_chars.append(msg[position] ^ key_byte)
          
           if decrypted_chars:
               # Score this potential decryption
               score = score_text(bytes(decrypted_chars))
              
               if score > best_score:
                   best_score = score
                   best_key_byte = key_byte
      
       recovered_key += bytes([best_key_byte])
      
       # Progress indicator
       if (position + 1) % 10 == 0 or position == max_length - 1:
           print(f"Processed {position + 1}/{max_length} positions...")
  
   return recovered_key, encrypted_messages


def decrypt_messages(key, encrypted_messages, usernames):
   """Decrypt all messages using the recovered key"""
   print(f"\nRecovered key (first 32 bytes): {key[:32].hex()}")
   print(f"Full key length: {len(key)} bytes")
   print("\nDecrypted messages:")
   print("=" * 50)
  
   for i, (msg, username) in enumerate(zip(encrypted_messages, usernames)):
       # XOR with key (truncate key if message is shorter)
       key_slice = key[:len(msg)]
       decrypted = byte_xor(msg, key_slice)
      
       try:
           # Try to decode as UTF-8
           text = decrypted.decode('utf-8', errors='replace')
           print(f"{username}: {text}")
       except:
           # Fallback: show as hex and attempt latin-1
           try:
               text = decrypted.decode('latin-1', errors='replace')
               print(f"{username}: {text} [raw: {decrypted.hex()}]")
           except:
               print(f"{username}: [hex: {decrypted.hex()}]")


def main():
   # Parse the chat log
   chat_file = "/Users/danishhakim/Desktop/SIBER/exported/4e3c53f3d49203cf5a75e91638ff8680.log"
  
   print("Parsing chat log...")
   messages = parse_chat_log(chat_file)
  
   if not messages:
       print("No encrypted messages found in the log file!")
       return
  
   print(f"Found {len(messages)} encrypted messages")
  
   # Extract usernames for later use
   usernames = [username for username, _ in messages]
  
   # Perform the attack
   print("\nAttempting to recover the key...")
   recovered_key, encrypted_messages = attack_stream_cipher(messages)
  
   # Decrypt and display messages
   decrypt_messages(recovered_key, encrypted_messages, usernames)
  
   print("\n" + "=" * 50)
   print("Note: This assumes the messages are encrypted with a stream cipher")
   print("using a reused key/nonce. The quality of decryption depends on")
   print("having enough ciphertext and the correctness of this assumption.")


if __name__ == "__main__":
   main()
```

After that, we replaced broken words with its correct word manually and used the XOR/Known Plain Text Attack to get better results.

```py
#!/usr/bin/env python3


def parse_chat_log(filename):
   """Parse the chat log and extract hex-encoded messages"""
   messages = []
  
   with open(filename, 'r') as f:
       content = f.read()
  
   lines = content.strip().split('\n')
   for line in lines:
       if ' : ' in line and not line.startswith('---'):
           parts = line.split(' : ', 1)
           if len(parts) == 2:
               username, hex_data = parts
               try:
                   bytes.fromhex(hex_data.strip())
                   messages.append((username.strip(), hex_data.strip()))
               except ValueError:
                   continue
  
   return messages


def hex_to_bytes(hex_string):
   return bytes.fromhex(hex_string)


def byte_xor(ba1, ba2):
   return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def known_plaintext_attack(ciphertexts, known_pairs):
   """Use known plaintext-ciphertext pairs to recover the key"""
  
   print("=== Known Plaintext Attack ===")
  
   encrypted_messages = [hex_to_bytes(msg) for _, msg in ciphertexts]
   usernames = [username for username, _ in ciphertexts]
  
   # Find the maximum message length
   max_length = max(len(msg) for msg in encrypted_messages)
  
   # Initialize key array
   recovered_key = bytearray(max_length)
   key_confidence = [0.0] * max_length  # Track confidence for each key byte
  
   # Process each known plaintext pair
   for i, (expected_plaintext, msg_index) in enumerate(known_pairs):
       if msg_index >= len(encrypted_messages):
           print(f"Warning: Message index {msg_index} out of range")
           continue
          
       ciphertext = encrypted_messages[msg_index]
       plaintext_bytes = expected_plaintext.encode('utf-8')
      
       if len(plaintext_bytes) > len(ciphertext):
           print(f"Warning: Plaintext longer than ciphertext for message {msg_index}")
           continue
      
       # Calculate key bytes for this segment
       key_segment = byte_xor(ciphertext[:len(plaintext_bytes)], plaintext_bytes)
      
       print(f"\nMessage {msg_index} ({usernames[msg_index]}):")
       print(f"  Expected: '{expected_plaintext}'")
       print(f"  Key segment ({len(key_segment)} bytes): {key_segment.hex()}")
      
       # Update the recovered key with high confidence
       for j, key_byte in enumerate(key_segment):
           if j < len(recovered_key):
               recovered_key[j] = key_byte
               key_confidence[j] = 1.0  # High confidence from known plaintext
  
   # For remaining positions, try to extend the pattern or use frequency analysis
   print(f"\nKey recovery status:")
   known_positions = sum(1 for conf in key_confidence if conf > 0)
   print(f"  Known positions: {known_positions}/{len(recovered_key)}")
  
   # Try to recover remaining key bytes using frequency analysis on unknown positions
   for pos in range(len(recovered_key)):
       if key_confidence[pos] == 0:  # Unknown position
           # Get all bytes at this position from all messages
           position_bytes = []
           for msg in encrypted_messages:
               if pos < len(msg):
                   position_bytes.append(msg[pos])
          
           if len(position_bytes) >= 2:
               # Try all possible key bytes and score them
               best_score = -1
               best_key_byte = 0
              
               for key_candidate in range(256):
                   decrypted_bytes = [b ^ key_candidate for b in position_bytes]
                  
                   # Score based on printable ASCII and common English characters
                   score = 0
                   for b in decrypted_bytes:
                       if 32 <= b <= 126:  # Printable ASCII
                           score += 3
                       if chr(b) in 'etaoinshrdlu ETAOINSHRDLU':  # Common letters
                           score += 2
                       if chr(b) in ' \n\r\t':  # Whitespace
                           score += 1
                  
                   if score > best_score:
                       best_score = score
                       best_key_byte = key_candidate
              
               recovered_key[pos] = best_key_byte
               key_confidence[pos] = 0.5  # Medium confidence from frequency analysis
  
   return bytes(recovered_key), key_confidence


def decrypt_all_messages(key, key_confidence, ciphertexts):
   """Decrypt all messages using the recovered key"""
  
   print("\n=== DECRYPTED MESSAGES ===")
   print(f"Key length: {len(key)} bytes")
   print(f"Key (hex): {key.hex()}")
  
   # Show key confidence
   high_conf = sum(1 for conf in key_confidence if conf >= 0.9)
   med_conf = sum(1 for conf in key_confidence if 0.4 <= conf < 0.9)
   low_conf = sum(1 for conf in key_confidence if conf < 0.4)
   print(f"Key confidence: {high_conf} high, {med_conf} medium, {low_conf} low confidence bytes")
   print("="*80)
  
   for username, hex_data in ciphertexts:
       ciphertext = hex_to_bytes(hex_data)
       key_slice = key[:len(ciphertext)]
      
       decrypted = byte_xor(ciphertext, key_slice)
      
       try:
           text = decrypted.decode('utf-8', errors='replace')
          
           # Calculate quality score
           printable_chars = sum(1 for c in text if c.isprintable())
           quality = printable_chars / len(text) if text else 0
          
           if quality >= 0.95:
               print(f"{username:12}: {text}")
           else:
               print(f"{username:12}: {text} [Quality: {quality:.1%}]")
              
       except Exception as e:
           print(f"{username:12}: [DECODE ERROR]")
  
   print("="*80)


def verify_key_with_known_plaintexts(key, ciphertexts, known_pairs):
   """Verify the recovered key against known plaintexts"""
  
   print("\n=== KEY VERIFICATION ===")
  
   encrypted_messages = [hex_to_bytes(msg) for _, msg in ciphertexts]
   usernames = [username for username, _ in ciphertexts]
  
   all_correct = True
  
   for expected_plaintext, msg_index in known_pairs:
       if msg_index >= len(encrypted_messages):
           continue
          
       ciphertext = encrypted_messages[msg_index]
       key_slice = key[:len(ciphertext)]
       decrypted = byte_xor(ciphertext, key_slice)
      
       try:
           decrypted_text = decrypted.decode('utf-8', errors='strict')
           expected_bytes = expected_plaintext.encode('utf-8')
          
           if decrypted[:len(expected_bytes)] == expected_bytes:
               print(f"✓ Message {msg_index} ({usernames[msg_index]}): CORRECT")
           else:
               actual_start = decrypted_text[:len(expected_plaintext)]
               print(f"✗ Message {msg_index} ({usernames[msg_index]}): MISMATCH")
               print(f"    Expected: '{expected_plaintext}'")
               print(f"    Got:      '{actual_start}'")
               all_correct = False
              
       except UnicodeDecodeError:
           print(f"✗ Message {msg_index} ({usernames[msg_index]}): DECODE ERROR")
           all_correct = False
  
   if all_correct:
       print("✓ All known plaintexts verified successfully!")
   else:
       print("⚠ Some verifications failed - key may need refinement")
  
   return all_correct


def main():
   # Parse the chat log
   chat_file = "/Users/danishhakim/Desktop/SIBER/exported/4e3c53f3d49203cf5a75e91638ff8680.log"
  
   print("Parsing chat log...")
   messages = parse_chat_log(chat_file)
  
   if not messages:
       print("No encrypted messages found in the log file!")
       return
  
   print(f"Found {len(messages)} encrypted messages")
  
   # Known plaintext-ciphertext pairs
   # Format: (expected_plaintext, message_index)
   known_pairs = [
       ("!init solarizzer", 0),   # First message
       ("!init WaderPaw", 1),     # Second message 
       ("!init PenguinDog", 2),   # Third message
       ("I am starting a full diagnostic on all the compromised network nodes. Early reports show that our entry points are holding strong without any detection from their outside intrusion systems", 3),  # Fourth message
       ("Excellent. The initial phase is complete. The transportation grid is now showing major failures across all major city areas.", 4),
   ]
  
   print("\nUsing known plaintext pairs:")
   for plaintext, msg_idx in known_pairs:
       print(f"  Message {msg_idx}: '{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}'")
  
   # Perform known plaintext attack
   recovered_key, key_confidence = known_plaintext_attack(messages, known_pairs)
  
   # Verify the key
   verification_passed = verify_key_with_known_plaintexts(recovered_key, messages, known_pairs)
  
   # Decrypt all messages
   decrypt_all_messages(recovered_key, key_confidence, messages)
  
   if verification_passed:
       print("\n🎉 SUCCESS: Key recovery and verification completed!")
   else:
       print("\n⚠ PARTIAL SUCCESS: Key recovered but some verifications failed")


if __name__ == "__main__":
   main()
```

After all of that, the result produced is as follows:

```
solarizzer  : !init solarizzer
WaderPaw    : !init WaderPaw
PenguinDog  : !init PenguinDog
solarizzer  : I am starting a full diagnostic on all the compromised network nodes. Early reports show that our entry points are holding strong without any detection from their outside intrusion systemss>
WaderPaw    : Excellent. The initial phase is complete. The transportation grid is now showing major failures across all major city areas.
WaderPaw    : Their emergency response teams are completely overwhelmed, running in circles chasing the ghost signals we planted. The public transit data feeds are pure gibberish. ^|7sd+b{sso|smn0bkhb&
solarizzer  : Good. Chaos is the objective. Let them feel the ground shifting beneath their feet. We are demonstrating that we control the very arteries of their city. This is not vju0ijuhb!&h:scy'pjqud 9U]e~ ANd QRi1H`A tihAit nEA 
solarizzer  : Maintain active surveillance on their network recovery teams. I want a full report on their every move, no matter how small.
PenguinDog  : We have a problem. A local one. I'm at the East-side depot to prep the hardware for phase two, but I am completely locked out.
PenguinDog  : I pushed the new firmware update to the door's RFID scanner last night, but it is not accepting any of our authentication cards.
solarizzer  : Explain. This is an unacceptable setback. That hardware is critical to our timeline. What did you do to the firmware?
PenguinDog  : For security, I encrypted the firmware with AES-CTR before uploading it. It is our standard operational procedure to prevent reverse-engineering if the unit is physicvd|yd*fjrrtb/
PenguinDog  : The problem is, I was juggling three different tasks, and I honestly cannot recall the exact key I used. I have tried our standard rotation of keys, but nothing is woecyn#g'Nnb&|om+scy'tnxest LOlu USelRNhrEoRa sdOs haDR 
WaderPaw    : PenguinDog, you idiot. You actually forgot the key? Unbelievable.
WaderPaw    : Nevermind that. Just send a GET request to our cloud server. 
WaderPaw    : It is at 5.223.49.127. 
solarizzer  : Use the method our leader demonstrated for extracting the key from the key file you got.
WaderPaw    : Surely you have not forgotten that basic exploitation technique yet, have you?
PenguinDog  : Oh, right. That method. The request should be sent on port 4510 if I remember correctly.
WaderPaw    : Yes, that is the correct port. And remember the API is at /getkey. 
WaderPaw    : Also, do not forget that the key is always Base64 encoded. 
WaderPaw    : It is also quite funny how the firmware is encrypted so insecurely.
solarizzer  : Yeah with the nonce being just the first 12 bytes of the key.
WaderPaw    : I swear, if the higher ups knew we were still using such a predictable nonce generation scheme, we would soon find ourselves in very deep trouble.
PenguinDog  : That's it! Man, thank you. I knew it was something simple. Okay, I can retrieve the key easily. I'll have the scanner operational in twenty minutes. Sorry for the alaee>
solarizzer  : This is your only warning, PenguinDog. Document your procedures. Such a trivial mistake could have jeopardized the entire operation. Get it done, and let's get back oy(cc,,cojb(:Ri+!o*pxdr reiTE aoRE eEOt R
```

After this, we can deduce some few things
- The key is stored at `https://5.223.49.127:4510/getkey`
- From the key, we can get a Base64 key which the first 12 bytes (nonce) of it are being used to encrypt the firmware.
- The firmware is encrypted using the same AES-CTR method.

After fetching the key from their server, we'll get its public RSA key.

```
N = 80064298978462407383798317162436781093994471350579452979755551925699110407722847337022626636111768206949635337820734381876595113101771246563611333323966076585178560758685342595382089773409298492098705455798598770328990819349599651425350413511087525067191186974532502875933941450650782774466277244594801934529
e = 56244737645424606423630755035696761067160138378199901552435773496318038347981281868841511916303173595619572443469066091189752839582779636637271110496078191503663696396693953634445846784544055881804957814432185419168285703748389080819145114444225165890785870350614903997339099218915082533601982037101859951539
c = 6883193118218029672595578272558993778522264906324192666645865981626866680407002937048867751738966987773768206013680117002620923930065884668659961711241935368737363566007645336314135482954249969501386832468587023389499520661471593582680440355859070289754124545263389522761634778894773485661367725273852580891
```

From the public key, we can use a vulnerability (Wiener's condition - due to using less secure RSA private exponents) to deduce private key. For this, I asked ChatGPT to create a script for it and produce the private key. The private key is in Base64, decode from Base64 gets the key and can be used inside for decryption.

```py
# wiener_recover.py
# pip install gmpy2   # optional, but Python's builtins are fine for moderate size
from math import isqrt
from math import gcd

def cont_frac(numer, denom):
    a = []
    while denom:
        q = numer // denom
        a.append(q)
        numer, denom = denom, numer - q*denom
    return a

def conv_from_cf(a):
    convs = []
    for i in range(len(a)):
        num, den = 1, 0
        for x in reversed(a[:i+1]):
            num, den = x*num + den, num
        convs.append((num, den))
    return convs

def modinv(a, m):
    # extended gcd
    a = a % m
    if a == 0:
        return None
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

# put your numbers here
N = ...  # big int N
e = ...  # big int e
c = ...  # big int c

cf = cont_frac(e, N)
convs = conv_from_cf(cf)

for k, d_candidate in convs:
    if k == 0:
        continue
    if (e * d_candidate - 1) % k != 0:
        continue
    phi_candidate = (e * d_candidate - 1) // k
    s = N - phi_candidate + 1
    disc = s*s - 4*N
    if disc >= 0:
        t = isqrt(disc)
        if t*t == disc and (s + t) % 2 == 0:
            p = (s + t)//2
            q = (s - t)//2
            if p*q == N:
                print("Found factors!")
                print("p =", p)
                print("q =", q)
                phi = (p-1)*(q-1)
                d = modinv(e, phi)
                print("Recovered d =", d)
                m = pow(c, d, N)
                print("Recovered plaintext (hex):", hex(m))
                break
```

After the private key is obtained, essentially we obtain the key that has been Base64 first. Then, we need to decode from Base64 and decrypt the firmware file just like how they explain. The script is as follows.

```py
# decrypt_firmware_with_recovered_key.py
# pip install pycryptodome
import base64
from Crypto.Cipher import AES


# recovered values
key_b64 = "tCncHUA7iMUCHqQ9bMGTjg=="
key = base64.b64decode(key_b64)          # 16 bytes
nonce = key[:12]                         # first 12 bytes of key per chat


print("Key (hex):", key.hex())
print("Nonce (hex):", nonce.hex())


# read ciphertext
with open("exported/firmwareLatest.enc", "rb") as f:
   ct = f.read()


cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
pt = cipher.decrypt(ct)


# write plaintext
with open("firmware.dec", "wb") as f:
   f.write(pt)


print("Decrypted firmware written to firmware.dec")
```

After we decrypt the firmware file, we will get a file that is ZIP compatible. Unzipping the file produces two files, the firmware itself and an instruction. The instructions only contain the flag as below.

>Flag: `SIBER25{WuZZl3_l0v3S_AES}`
{: .prompt-tip}

After all of this, we managed to decrypt their secret conversation and plan.

For better explaination on the attack, please refer to our ChatGPT conversation [here](https://chatgpt.com/share/68db8b0a-45f4-8006-97a3-4cc0b8506f30)

## Challenge 3: Key to the Other Side

*By Mynz*

>This challenge was unfinished due to skill issue with OSINT :( Hope to improve better later on!
{: .prompt-tip}

**Category:** RFID, OSINT

**Description:**

The suspect's door is protected by an RFID security device. To minimize the impact of our breach, we must find a way to acquire access. Perhaps the suspect might have a way to communicate with his members on how to gain entry to his base?

**Answer:**

So, we are trying to unlock the locked door which protected by RFID. interesting..
Based on the previous challenge, we get the sesamedoor_dist file, after further decryption, we found that the program searches for an environment call My Favourite Animal. The environment is used to determine the correct content of the RFID Card.

We need to know what are the favourite animal for one of the hackers, and one of the hackers PenguinDog has a Twitter social media, but after a thorough finding, we not find anything, then we try to find it in Archive.com https://archive.fo/Ip5he, we found this image, meaning the hacker choose penguins as their favourite animal.

![](assets/img/siber-siaga-25-finals/image1.png)

Based on the storyline, this suggest that the user PenguinDog is the suspect for this investigation that has relation with the threat actor due to his/her poor OPSEC (Operations Security)

## Closing

I think our team has reached our all time high at least reaching the finals of CTF despite we are still in our second year. We hope to win at least once later on and thanks to C0UGH1NGB4BY for some tips in OSINT and hope you'll win this. We'll see you in the next one, CIAO!