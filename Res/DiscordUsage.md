# Discord C3 Channel Setup

1. Sign up for Discord
2. Create an application (https://discord.com/developers/applications)
3. Add a bot
4. Set bot to not-public and doesn't require OAuth2 code flow
5. Add bot to server using link below, filling in CLIENT_ID (18 digit number) and GUILD_ID (4 digit number).
	- https://discord.com/oauth2/authorize?client_id=[CLIENT_ID]&scope=bot&permissions=109584&guild_id=[GUILD_ID]
6. Use longer Client ID and Bot token for C3 channel creation.