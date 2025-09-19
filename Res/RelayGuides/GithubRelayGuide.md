# Github Relay

## Configuring Github

1. Using a temporary email, create a Github account
2. Go to [https://github.com/settings/tokens/new](https://github.com/settings/tokens/new)
3. Give the token a meaningful name
4. Set a reasonable exparation
5. Grant it the following permissions:
    - repo (including all sub permissions)
    - delete_repo
6. Scroll down and click Generate Token, the next page to load should contain your Personal access token

## Configuring C3

1. Click your Gateway then click Command Center
2. Select `AddNegotiationChannelGitHub` from the "Select command" dropdown and paste in your Github Personal Access Token. Remember to give the `Repository Name` and `Negotiation Identifier` a meaningful name without spaces. I also found that the Gateway and Relay would refuse to checkin without a `User-Agent Header` so I entered “Firefox” in this field, then click "Send command". You should now see the channel added to the UI
3. Click your Gateway and New Relay
4. Select `AddNegotiationChannelGithub` from the "Select command" dropdown and fill in the information with the exact same information you used for your Gateway and then click Create And Downloa
5. Run this newly downloaded Relay binary on the target machine and you should now see it connected in the C3 UI

<aside>
⚠️ Rate limiting is implemented on the Github API. Each channel instance will send a GET request every 3 to 6 seconds, to receive packets from server. Multiple channels accessing 1 Github account can consume whole limit causing other connections to throttle. Refer to [https://developer.github.com/v3/rate_limit/](https://developer.github.com/v3/rate_limit/) for more information.
</aside>