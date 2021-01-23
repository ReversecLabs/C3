# CloudFlare Channel

## Setup

Prior to using CloudFlare's WorkerKV API within C3, the steps below must be taken.

1. Create a CloudFlare account.
2. Generate an API Token with Worker KV Permissions (this just needs the 'Account -> Workers KV Storage -> Edit' permission, don't use your account-wide CloudFlare API token).
3. Insert the generated API Token to C3 channel.

## Usage Limits

The free tier has [limits](https://developers.cloudflare.com/workers/platform/limits) in place that caps on reads/writes/lists. Most notably here is the 1000 lists/day, so every checkin from gateway and relay will count towards this.

Realistically, if you are using this in anger, a paid tier account ($5/month) will serve you best. This has unlimited reads and writes.