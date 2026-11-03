# Security policy

## Supported versions

Only the latest release (`3.x` from the
[releases page](https://github.com/JohnWatsoon/WatTunnel/releases)) is supported. Update both servers — old and
new versions are wire-compatible, but a fix only helps the end that runs it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab → "Report a vulnerability"), or contact
[@watxox](https://t.me/watxox) on Telegram. Do not open a public issue.

Please include: the version on each end (`wattun -version`), the carrier, the config with the key and token
removed, and the relevant logs.

## Scope notes

WatTunnel protects the content of the tunnel, not its existence: the server's address, packet volume and timing
stay visible, and it is not an anonymity tool. The full model — key schedule, forward secrecy, what each carrier
adds and what none of it hides — is documented in
[docs/TECHNICAL.md, "Security model"](docs/TECHNICAL.md#security-model).
