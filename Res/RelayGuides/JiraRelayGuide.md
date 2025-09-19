# Jira Relay

## Configure Jira

1. Navigate to [https://atlassian.com](https://atlassian.com) and click the “Try Now”
2. Scroll down to the “Plan & Track” section, the first product should be “Jira Software”, click “Try Cloud” for this product
3. The next page will prompt you for a second product but you can ignore this and press “Next”
4. The next page should be a signup screen. Using a temporary email you can sign up
5. After you have verified your email and entered a password you will be promped confirm your “Site Name” (Set a good site name as your C3 traffic will be going to https://site-name.atlassian.com)
6. After this there will be a collection of prompts to discribe your business, since we’re not a business we can just press skip and ignore all of these questions
7. After this you should be on an “Add Project Details” page. Enter a name and a key (the key is just an alias of your name, save this key as it is used as the Project Key in the C3 interface) then press “Complete”
8. If everything was done correctly you should now see a Kanban style dashboard
9. Open a new tab and navigate to [https://id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
10. Press “Create API Token” and then give it a name (save this token as it is used as the Password/API Token in the C3 interface)

## Configure C3

1. Click your Gateway then click Command Center
2. Select `AddNegotiationChannelJiraIssue` from the "Select command" dropdown and fill in the following information:
    - `Negotiation Identifier` - Any meaningful string
    - `Jira URL` - this should be in the following format: https://site-name.atlassian.net (replace site-name with your project’s name)
    - `Project Key` - this is the alias of the project from step 7 of the section above
    - `Issue Name` - you can set this to whatever you want, this is the Jira Issue that C3 will create to put the payloads into
    - `Username` - this is the email address you used to sign up with
    - `Password/API Token` - this is the API Token you created in the final step of the section above
    - Click your Gateway and New Relay
    - Select `AddNegotiationChannelJiraIssue` from the "Select command" dropdown and fill in the information with the exact same information you used for your Gateway and then click Create And Download
3. Run this newly downloaded Relay binary on the target machine and you should now see it connected in the C3 UI