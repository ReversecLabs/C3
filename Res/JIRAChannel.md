# JIRA C3 Channel setup

1. Sign up for a free tier account, selecting your atlassian.net subdomain of choice.
2. create an initial project (tested with a Kanban style template) and name accordingly.
3. navigate to https://id.atlassian.com/manage-profile/security/api-tokens and create an API token.
4. Input fields into C3
    - URL is your full atlassian.net domain: "https://[domain].atlassian.net/"
    - project key is the shortened project name identifier i.e. https://[domain].atlassian.net/jira/software/projects/[<-This value->]/boards/1
    - issue name is arbitrary and either created or an existing issue reused.
    - username is the email address used for sign up (or other if you've added additional users to the JIRA instance)
    - API token is from step 3, or the user's password if using an on-prem instance of JIRA.