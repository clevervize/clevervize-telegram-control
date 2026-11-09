# Clever Vize Telegram Control

Telegram webhook relay for the Clever Vize mail-control workflow.

Required Render environment variables are documented in `.env.example`; secrets are never committed.

FounderMail is the live mailbox provider. The service lists/creates/deletes real
`@clevervize.com` mailboxes, uses the `info` mailbox for sending, and polls every
mailbox including Junk so Telegram receives new-mail notices.

The future IMAP pool belongs in the separate Randevu Ajanda service, not in this repository.
