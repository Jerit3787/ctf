---
title:  "ASEAN-Japan Cyber SEA Game - Green Lane (Web)"
date:   2026-11-02 00:00:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [ASEAN-Japan Cyber SEA Game 2026]
media_subpath: /assets/img/asean-cyber-sea-games-26/
mermaid: true
---
*By Team Malaysia - Jerit3787, whiteusagi, hikki & w_11*

![](team.png)

> This challenge was completed during the CTF & presented during the writeup session at the event
{: .prompt-info}

# Green Lane
**Category:** Web

**Points/Level:** 750/hard

**Flag:** CSG_FLAG{us3r1nf0_tr1ck_0p3n3d_th3_gr33n_lan3}

## Enumeration
![](image1.png)
We were given a page where you can request a preview via the textbox with a link. At first glance, this could be vulnerable to SSRF or it is called Server-Side Template Injection.

To test our theory, clicking "Fetch preview" would fetch the internal service.

![](image2.png)

And indeed, it did fetch the internal preview of the site. Next, would be to see if the SSRF would be possible with external address. A quick fetch of domain like "google.com" would prove this.

![](image3.png)

And you can see that we have meet with our first blockage.

## Reasoning

![](image4.png)

In a typical SSRF fashion of CTF challenges, it is noted that usually it is guarded with some type of filtering, either it may be URL filtering or something. Looking back at the screenshot, you'll see that it is blocked with following text:

>refused: the label fetcher only speaks the http:// scheme (got https://)

This is a typical block, testing it with `http` protocol instead.

![](image5.png)

Now, we are served with another error which is:

> refused: upstream host is not in the partner allow-list (expected a label url beginning with http://labels.svc.internal)

## Getting the foothold

Now we see the what is being filtered, this is actually a good challenge because it gave us the insights to what it is being blocked. In typical blind SSRF, you would test it until you found what the filter misses. Since we already got the hint, I scouted the internet to fetch a payload for it.

We tried typicals of payload like URL encode which it does not normalize in the backend, this usually shows that it is direct written as such:

```
input(url):
    filtered_url = filter(url)
    output = await fetch(url)
    textbox_content = output
```

Thus, it does not exhibit browser behaviour. Thus, next would be to abuse the URI/URL spec.

![](image6.png)

URL allows for use of `UserInfo` for usually authenticated access, you'll usually see this in ssh like this CTF:

> kali@kalicsg2026.local

Thus, with this information, we can test if we can bypass the filter with the payload:

> http://labels.svc.internal@test

![](image7.png)

With this, we got another error which is:

>refused: upstream fetch failed: ConnectionError

Noticed that is is `ConnectionError`, it means that the server attempted to fetch it. Testing it with `google.com` also gives out the same result which indicates no external network access.

## Next steps?

Now we have a working bypass, with no external access, it is important us to find leads for internal services.

![](image8.png)

Noticed that at the end of the page, you'll see that we have a path at `/api/upsteams`. Going to that path reveals:

```json
{
  "service": "green-lane-preclearance",
  "upstreams": [
    {
      "name": "labels.svc.internal",
      "role": "partner label CDN",
      "scope": "allow-listed for /api/label/preview",
      "status": "up"
    },
    {
      "name": "metadata.svc.internal",
      "role": "platform instance metadata service",
      "scope": "internal only -- not reachable from the edge",
      "status": "up"
    }
  ],
  "version": "1.4.2"
}
```
Now we see we have `metadata.svc.internal`, with this we can try with the payload that is:

> http://labels.svc.internal@metadata.svc.internal

![](image9.png)

Fetching that reveals a path `latest`, continuing into that path.

![](image10.png)

And again reveals a few more paths. `dynamic` reveals more configuration, as does `meta-data`; the one with the most interesting information is `user-data`. Pulling `user-data`:

![](image11.png)

Now we see this bash script, and noticing another URL to go to which is `http://seals.svc.internal/v1/seal`. Going for another one again reveals:

![](image12.png)

Now we see that it reveals the requirement to access the path. We need to supply `?token=<token>` with this request. We've seen the token before on the config page before, using the same token.

![](image13.png)

And with that we got the token, we got the flag.

> CSG_FLAG{us3r1nf0_tr1ck_0p3n3d_th3_gr33n_lan3}

p/s: we would like to say thank you to everyone for the prayers and wishes, and alhamdulillah we achieved 2nd runner up or 3rd place for Malaysia! So happy able to bring the country flag and show to the others that we also have good people working in the community. This is for you, Malaysia! That's all, see you again in a next one!
