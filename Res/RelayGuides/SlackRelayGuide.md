# Slack Relay

## Configuring Slack

1. Download the Slack client and install it
2. Launch the client and when you hit the login page select "Need to get your group started on Slack? Create a new workspace"
3. Using a temporary email create a new workplace
4. Once you have gone through the workplace setup and created the default channel go back to your browser and navigate to [https://api.slack.com/apps](https://api.slack.com/apps)
5. Click "Create new app", name it and then select the workspace you just created
6. Once you hit create you should be brought to configuration page,
select the box called "Permissions" and then scroll down to the section
labeled "User Token Scopes" and add the following scopes:
    - files : read
    - files : write
    - chat : write
    - channels : history
    - channels : read
    - channels : write
7. Scroll back up the page and press "Install to Workspace", you
should now see a confirmation page: press apply and then the page that
pops up should show your Oath Token (the token should look like:
(xoxp-1582649926837-1585737590066-1585700000000)

## Configuring C3

1. Click your Gateway then click Command Center
2. Select `AddNegotiationChannelSlack` from the "Select command" dropdown and paste in your Slack API token. Remember to give the `Channel Name` and `Negotiation Identifier` a meaningful name without spaces, then click "Send command". You should now see the channel added to the UI (`AddNegotiationChannelSlack` can have multiple agents connect back, where `AddChannelSlack` can only have one)
3. Click your Gateway and New Relay
4. Select `AddNegotiationChannelSlackn` from the "Select command" dropdown and fill in the information with the exact same information you used for your Gateway and then click Create And Download
5. Run this newly downloaded Relay binary on the target machine and you should now see it connected in the C3 UI