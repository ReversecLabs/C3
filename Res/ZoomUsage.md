Create a Server to Server OAUTH account on https://marketplace.zoom.us

* Click Develop in the top bar
* Select Build App
* Select Server to Server OAuth App > Create > Give it a name

Take a note of the following:

* Account ID
* Client ID
* Client Secret
* Account Email

Add Scopes:

* Select All Team Chat Permissions

Or individual scopes:

(to be completed)

* team_chat:read:list_user_channels:admin
* team_chat:write:user_message:admin
* team_chat:read:list_user_messages:admin
* team_chat:delete:user_message:admin
* team_chat:delete:file:admin
* team_chat:delete:user_channel:admin
* team_chat:write:user_channel:admin
* team_chat:write:message_files:admin
* team_chat:update:user_message:admin
* team_chat:delete:channel:admin


In C3 add negotiation channel zoom:

* User Agent - Optional - no user agent sent if not specified
* Account ID
* Client ID
* Client Secret
* Email - Optional - the user that is invited to the channel - only tested with a single ID, doesn't appear to matter if it doesn't exist in tenant
* Vanity Domain - Optional - It is possible to register vanitydomain.zoom.us, and domain fronting appears to work

Consider increasing the Jitter time from the default 3.5-6s. Consider the following rate limits depending on the account used, and the number of relays in action. Most of the chat actions are classed as Medium APIs:


| Rate Limit Type | Free | Pro | Business+ |
| --- | --- | --- | --- | 
| Light APIs | 4/second, 6000/day| 30/second | 80/second |
| Medium APIs | 2/second, 2000/day | 20/second | 60/second |
| Heavy APIs | 1/second, 1000/day | 10/second | 40/second |
| Resource-intensive APIs | 10/minute, 30,000/day | 10/minute | 20/minute |


# Testing

Using the linter:

```
Bin\ChannelLinter_d64.exe -n Zoom  -a "inputid" -a "outputid" -a "useragent" -a "ACCOUNT_ID" -a "CLIENT_ID" -a "CLIENT_SECRET"  -a "EMAIL_OPTIONAL" -a "VANITY_DOMAIN_OPTIONAL" -a "c3test" -i
```