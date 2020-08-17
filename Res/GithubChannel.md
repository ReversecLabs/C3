# Github Channel

## Setup

Prior to using Github API within C3, the steps below must be taken.
1. Create a Github account
2. Generate Personal Access Token with API Permissions (repo, delete_repo)
3. Insert the generated Personal Access Token to C3 channel.

## Rate Limit

There is rate limiting implemented for Github API. Each channel instance will send GET request every 3 to 6 seconds, to receive packets from server. Multiple channels accessing one Github account can consume whole limit causing other connections to throttle. Refer to https://developer.github.com/v3/rate_limit/ for more information.


