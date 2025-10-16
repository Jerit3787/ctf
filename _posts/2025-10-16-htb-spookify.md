---
title:  "Weekly HTB Writeup (W1 - C1) - Spookify (Web)"
date:   2025-10-16 23:00:00 +0800
categories: [HTB Writeup, Web Explotation]
tags: [Weekly HTB Writeup]
---

Hello everyone! Welcome to my first weekly writeup where I will start to write all the challenges that I've done inside the HTB platform each week. Hopefully, this will help me sharpen my skills and also help you guys in terms of learning to solve your first CTF challenge. I'll try my best to include as much information into tiny bite sized just like this one. ehek :)

I will start off with a very easy challenge focusing on Web Exploitation. For HTB, very easy means *would be easy if you have some experience in solving CTF challenge* but if you're a newbie, this could be a bit overhead for you to learn just like if you're encountering a new subject to learn. If you think you have some knowledge to begin with, easy challenges would be the place you can start. Without further ado, we'll enter this 1 of 3 challenges this week which titled *Spookify*. For documentation purposes, I'll attach the information from HTB.

## Challenge Details

> Name: Spookify
>
> Category: Web
>
> Challenge Description: 
>
> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?

## Step 1 - Initial analysis

So for this challenge, we were given a page where it allows users to enter a text and the website will produce the same text in different fonts for you to select which one you'll like.

![](assets/img/htb-spookify/image1.png)

Just for fun, let's enter a text here.

![](assets/img/htb-spookify/image2.jpeg)

Just like inside the image, we entered "Sigma Boy" into the field and obtain 3 different fonts and the last one looks like a normal one. If you're a seasonal CTF player, you'll think there is already a vulnerability here. This is because the user input is directly rendered into the HTML page. This could either be template injection or XSS injection or could be anything with code execution. Since this challenge is a white-box which means that you'll have access to the source code that we could verify any vulnerability with this webpage.

## Step 2 - Source code review

Going through the source code, we'll see on one of the route, it uses `spookify` to convert the text and will pass to `render_template` which could be a vulnerable function. 

```python
from flask import Blueprint, request
from flask_mako import render_template
from application.util import spookify

web = Blueprint('web', __name__)

@web.route('/')
def index():
    text = request.args.get('text')
    if(text):
        converted = spookify(text)
        return render_template('index.html',output=converted)
    
    return render_template('index.html',output='')
```
{: file="routes.py"}

If the website renders a context directly without any filtering, they would be suseptible to vulnerability which in this case is `template injection`. We can continue to verify by looking at the `spookify` function.

```python
from mako.template import Template

font1 = {
	'A': '𝕬',
	'B': '𝕭',
	'C': '𝕮',
	'D': '𝕯',
	'E': '𝕰',
	'F': '𝕱',
	'G': '𝕲',
	'H': '𝕳',
	'I': '𝕴',
	'J': '𝕵',
	'K': '𝕶',
	'L': '𝕷',
	'M': '𝕸',
	'N': '𝕹',
	'O': '𝕺',
	'P': '𝕻',
	'Q': '𝕼',
	'R': '𝕽',
	'S': '𝕾',
	'T': '𝕿',
	'U': '𝖀',
	'V': '𝖁',
	'W': '𝖂',
	'X': '𝖃',
	'Y': '𝖄',
	'a': '𝖆',
	'b': '𝖇',
	'c': '𝖈',
	'd': '𝖉',
	'e': '𝖊',
	'f': '𝖋',
	'g': '𝖌',
	'h': '𝖍',
	'i': '𝖎',
	'j': '𝖏',
	'k': '𝖐',
	'l': '𝖑',
	'm': '𝖒',
	'n': '𝖓',
	'o': '𝖔',
	'p': '𝖕',
	'q': '𝖖',
	'r': '𝖗',
	's': '𝖘',
	't': '𝖙',
	'u': '𝖚',
	'v': '𝖛',
	'w': '𝖜',
	'x': '𝖝',
	'y': '𝖞',
	'z': '𝖟',
	' ': ' '
}

font2 = {
	'A': 'ᗩ', 
	'B': 'ᗷ',
	'C': 'ᑢ',
	'D': 'ᕲ',
	'E': 'ᘿ',
	'F': 'ᖴ',
	'G': 'ᘜ',
	'H': 'ᕼ',
	'I': 'ᓰ',
	'J': 'ᒚ',
	'K': 'ᖽᐸ',
	'L': 'ᒪ',
	'M': 'ᘻ',
	'N': 'ᘉ',
	'O': 'ᓍ',
	'P': 'ᕵ',
	'Q': 'ᕴ',
	'R': 'ᖇ',
	'S': 'S',
	'T': 'ᖶ',
	'U': 'ᑘ',
	'V': 'ᐺ',
	'W': 'ᘺ',
	'X': '᙭',
	'Y': 'Ɏ',
	'Z': 'Ⱬ',
	'a': 'ᗩ', 
	'b': 'ᗷ',
	'c': 'ᑢ',
	'd': 'ᕲ',
	'e': 'ᘿ',
	'f': 'ᖴ',
	'g': 'ᘜ',
	'h': 'ᕼ',
	'i': 'ᓰ',
	'j': 'ᒚ',
	'k': 'ᖽᐸ',
	'l': 'ᒪ',
	'm': 'ᘻ',
	'n': 'ᘉ',
	'o': 'ᓍ',
	'p': 'ᕵ',
	'q': 'ᕴ',
	'r': 'ᖇ',
	's': 'S',
	't': 'ᖶ',
	'u': 'ᑘ',
	'v': 'ᐺ',
	'w': 'ᘺ',
	'x': '᙭',
	'y': 'Ɏ',
	'z': 'Ⱬ',

	' ': ' '
}

font3 = {
	'A': '₳', 
	'B': '฿',
	'C': '₵',
	'D': 'Đ',
	'E': 'Ɇ',
	'F': '₣',
	'G': '₲',
	'H': 'Ⱨ',
	'I': 'ł',
	'J': 'J',
	'K': '₭',
	'L': 'Ⱡ',
	'M': '₥',
	'N': '₦',
	'O': 'Ø',
	'P': '₱',
	'Q': 'Q',
	'R': 'Ɽ',
	'S': '₴',
	'T': '₮',
	'U': 'Ʉ',
	'V': 'V',
	'W': '₩',
	'X': 'Ӿ',
	'Y': 'y̷',
	'Z': 'z̷',
	'a': '₳', 
	'b': '฿',
	'c': '₵',
	'd': 'Đ',
	'e': 'Ɇ',
	'f': '₣',
	'g': '₲',
	'h': 'Ⱨ',
	'i': 'ł',
	'j': 'J',
	'k': '₭',
	'l': 'Ⱡ',
	'm': '₥',
	'n': '₦',
	'o': 'Ø',
	'p': '₱',
	'q': 'Q',
	'r': 'Ɽ',
	's': '₴',
	't': '₮',
	'u': 'Ʉ',
	'v': 'V',
	'w': '₩',
	'x': 'Ӿ',
	'y': 'y̷',
	'z': 'z̷',
	' ': ''
} 

font4 = {
	'A': 'A', 
	'B': 'B',
	'C': 'C',
	'D': 'D',
	'E': 'E',
	'F': 'F',
	'G': 'G',
	'H': 'H',
	'I': 'I',
	'J': 'J',
	'K': 'K',
	'L': 'L',
	'M': 'M',
	'N': 'N',
	'O': 'O',
	'P': 'P',
	'Q': 'Q',
	'R': 'R',
	'S': 'S',
	'T': 'T',
	'U': 'U',
	'V': 'V',
	'W': 'W',
	'X': 'X',
	'Y': 'Y',
	'Z': 'Z',
	'a': 'a', 
	'b': 'b',
	'c': 'c',
	'd': 'd',
	'e': 'e',
	'f': 'f',
	'g': 'g',
	'h': 'h',
	'i': 'i',
	'j': 'j',
	'k': 'k',
	'l': 'l',
	'm': 'm',
	'n': 'n',
	'o': 'o',
	'p': 'p',
	'q': 'q',
	'r': 'r',
	's': 's',
	't': 't',
	'u': 'u',
	'v': 'v',
	'w': 'w',
	'x': 'x',
	'y': 'y',
	'z': 'z',
	'1': '1',
	'2': '2',
	'3': '3',
	'4': '4',
	'5': '5',
	'6': '6',
	'7': '7',
	'8': '8',
	'9': '9',
	'0': '0',
	'!': '!',
	'@': '@',
	'#': '#',
	'$': '$',
	'%': '%',
	'^': '^',
	'&': '&',
	'*': '*',
	'(': '(',
	')': ')',
	'-': '-',
	'_': '_',
	'+': '+',
	'=': '=',
	'{': '{',
	'}': '}',
	'[': '[',
	']': ']',
	'\\': '\\',
	'|': '|',
	';': ';',
	':': ':',
	'\'': '\'',
	'"': '"',
	'<': '<',
	',': ',',
	'>': '>',
	'.': '.',
	'?': '?',
	'/': '/',
	' ': ' '
}

def generate_render(converted_fonts):
	result = '''
		<tr>
			<td>{0}</td>
        </tr>
        
		<tr>
        	<td>{1}</td>
        </tr>
        
		<tr>
        	<td>{2}</td>
        </tr>
        
		<tr>
        	<td>{3}</td>
        </tr>

	'''.format(*converted_fonts)
	
	return Template(result).render()

def change_font(text_list):
	text_list = [*text_list]
	current_font = []
	all_fonts = []
	
	add_font_to_list = lambda text,font_type : (
		[current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
		) and None

	add_font_to_list(text_list, 'font1')
	add_font_to_list(text_list, 'font2')
	add_font_to_list(text_list, 'font3')
	add_font_to_list(text_list, 'font4')

	return all_fonts

def spookify(text):
	converted_fonts = change_font(text_list=text)

	return generate_render(converted_fonts=converted_fonts)
```
{: file="util.py"}

Now, we saw like on the page where font 1-3 is a custom font and font 4 is the regular text. Font 4 would be the attack surface due to no filtering from the user side. The vulnerability is located on this line.

```python
    return Template(result).render()
```
{: file="util.py"}

## Step 3 - The vulnerability & exploitation

By using `render` function, it will render any HTML/Template format given to it. Since font 4 does nothing and returns the same text, we can include malicious code for the library to render. So, now we need to craft our own payload from here. Since this is a simple challenge with no barriers or we called *blockage or challenges* along the way, we can just use any payload.

> A simple learning about payload is written here - payload are written based of here [https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation) and a list of payloads would be here [https://github.com/payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads) - good for future reference
{: .prompt-tip}

Just for POC, we can use the golden standard which is `7*7` to see if it is rendered correctly. For template injection, we need to wrap it with a template format according to its library. For this challenge, we can see that it imports `Template` object from `mako` library. Thus, for mako, the format will be as such `${ CODE HERE }`. Another one, if it is running under Flask/Jninja2 library, the format will be {% raw %}`{{ CODE HERE }}`{% endraw %}. Thus, our payload will be `${ 7*7 }` and if it shows 49, then we can confirm that template injection vulnerability is there and move to creating a more specific payload to fetch the flag.

![](assets/img/htb-spookify/image3.jpeg)

Based on above screenshot, we can see that the input were changed to 49 which means that our vulnerability is there. Now, we will continue to craft our own payload to fetch the flag.

Inside the website linked above, you can see various examples on payload that you can use depending on the situations like some imported function might not be available, if the payload were filtered and so on. So, as I've found mine, the payload would be `${ open('/flag.txt').read() }`. This will open the flag, read the contents of the folder and outputs the result. But, this can be done if you actually know the location of the flag. Usually the flag is inside the web challenge folder or inside the root. If you do not know where is the flag, you can just use a linux command like `ls` to get the directory listing to better understand the structure. The example below is running with payload `${ self.module.cache.util.os.popen('ls /').read()` which will read the root directory.

![](assets/img/htb-spookify/image4.jpeg)

We can confirm with it listing `flag.txt` as one of the files available in the root or `/` directory. Thus running the payload above will show as follows:

![](assets/img/htb-spookify/image5.jpeg)

I am not going to show the flag due to the challenge can be solved by anyone. To be fair, I'll only show evidence where the flag is output into the site. The flag for HTB is usually `HTB{f4k3_fl4g}` and differs for each CTF competitions.

## Conclusion

Thus, this is the end of the writeup. Hopefully you'll learn something form this writeup and may this be a point where you can continue to solve more challenge in the future on. So, stay tuned for another 2 writeup that I might or may not upload huhu. Till then, ciao!