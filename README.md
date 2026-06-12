PhishSwift


I got so tired of the manual phishing response checklist that I finally just built this tool to do it for me. Instead of spending an hour jumping between Entra, Exchange, and Defender for every single compromise, this thing automates the forensics and lets me clean it up in one go.

What it does
You give it a user's email, and it runs a deep dive:

Forensics: Checks sign-ins, inbox rules, sneaky OAuth apps, and who they've been sharing files with.

Cleanup: If the account is toast, it handles the annoying parts: blocks the user, wipes their MFA, kills their session, and deletes those forwarding rules.

Why this exists
I'm submitting this for the AI League Hackathon (Creative Apps track). It's a work-in-progress, so don't expect it to be perfect. Sometimes it flags normal travel as "suspicious" because the logic is a bit sensitive, and some things (like Defender's restricted entities) don't have a public API yet, so I left those as manual steps.

It's not magic, but it saves me a ton of time.

How to use it
Clone this thing.

pip install -r requirements.txt

Rename .env.template to .env and fill in your Azure keys (you'll need your Graph API credentials).

Run python main.py

Notes for the judges
If you're looking at this for the hackathon, I'm currently trying to bridge this with Foundry IQ to make the AI better at reading audit logs. If you don't have the AI tokens setup, it just falls back to a heuristic check, so it should still work fine for the demo.

Feedback is super welcome, seriously. If you find a bug (and you probably will), let me know.
