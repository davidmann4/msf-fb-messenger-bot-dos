# msf-fb-messenger-bot-dos
metasploit framework module module for dos fb bots.This module generates a 100kb payload which contains around 600 messages which a bot 
with wrong X-Hub-Signature implementation will handle like they came from facebook.That will cause the bot to start serveral http calls to facebook and 3rd party servers which have most likely a rate limiting of 1 request per second. That means one request keeps the server busy for 10 minutes.

![vid-gif-4 1](https://cloud.githubusercontent.com/assets/1736570/19968830/7db63d9c-a1d6-11e6-943e-e2553950c69a.gif)

To use this module you can either pass this parameter to msfconsole:

```console
msfconsole -m ~/path/to/this/repo
```

or you could use the loadpath command:

```console
loadpath ~/path/to/this/repo
```

just set RHOST and RPORT and run exploit. In some cases you can also use the app scoped user id to start an attack against a fb user of this bot. You can use rounds to adjust the amount of requests sent to the server. One request keeps one thread busy for 10 minutes. 

