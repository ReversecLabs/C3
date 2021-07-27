# Discord C3 Channel Setup

1. Sign up for Discord
2. Create an application (https://discord.com/developers/applications)
3. Add a bot
4. Set bot to not-public and doesn't require OAuth2 code flow
5. Add bot to server using link below, filling in:
	- APPLICATION_ID (18 digit number seen in URL and at:https://discord.com/developers/applications/[APPLICATION_ID]/information) 
	- GUILD_ID (number seen in the bottom left of the chat window preceeded by a #).

https://discord.com/oauth2/authorize?client_id=[APPLICATION_ID]&scope=bot&permissions=109584&guild_id=[GUILD_ID]

6. Use 18-digit Client ID (i.e. the one present in the chat home page - https://discord.com/channels/[CLIENT_ID]/) and Bot token for C3 channel creation.
