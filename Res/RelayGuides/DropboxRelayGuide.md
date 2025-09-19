# Dropbox Relay

## Configuring Dropbox

1. Using a temporary email create a new Dropbox account
2. Go to [https://www.dropbox.com/developers](https://www.dropbox.com/developers) and click Create Apps
3. Select the following permissions:
    - Scoped Access
    - App Folder
4. Give the app a meaningful name the click Create App
5. Go to the Permissions tab and grant the following permissions:
    - All Account Info permissions
    - All Files and folders permissions
    - All Collaboration permissions
6. Go to the Setting tab and scroll down to Generated access token and click Generate

## Configuring C3

1. Click your Gateway then click Command Center
2. Select `AddNegotiationChannelDropbox` from the "Select command" dropdown and paste in your Dropbox Access Token. Remember to give the `Folder Name` and `Negotiation Identifier` a meaningful name without spaces, then click "Send command". You should now see the channel added to the UI (`AddNegotiationChannelDropbox` can have multiple agents connect back, where `AddChannelDropbox` can only have one)
3. Click your Gateway and New Relay
4. Select `AddNegotiationChannelDropbox` from the "Select command" dropdown and fill in the information with the exact same information you used for your Gateway and then click Create And Download
5. Run this newly downloaded Relay binary on the target machine and you should now see it connected in the C3 UI