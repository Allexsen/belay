# Security

## belay is not a security sandbox

Today belay records and reports; it contains nothing. Its session engine, when it ships, is meant
as a **safety** boundary, not a **security** boundary. It is built to catch accidents — a bad
`rm`, an unexpected package install, an agent editing files you didn't expect — and to report what
changed.

It does **not** contain hostile code. A process that is actively trying to escape a belay session
can do so. Do not use belay to run untrusted or adversarial programs, and do not rely on it as an
isolation mechanism. Use a VM or a real sandbox for that.

belay itself contains no malicious code, no telemetry, and no remote calls.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Please do not open a public issue for
anything exploitable.

Include what you did, what happened, and what you expected. A reproduction case helps most.

Since belay is pre-alpha with no releases, there is no supported-versions table yet and no fixed
response window. Reports will be read and answered.
