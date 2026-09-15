# Screenshot privacy checklist

Screenshots are **optional post-release documentation**. ZEN Control does not require screenshots as release evidence, and synthetic UI imagery must not be presented as proof of real product behaviour.

When real screenshots are added, use deliberately sanitized captures and check for:

- household names, usernames and account identifiers;
- real device names, MAC addresses and private IP addresses;
- private DNS/activity domains and notification destinations;
- deployment hostnames or public/private service URLs;
- QR codes, TOTP seeds, recovery material or session information;
- passwords, API tokens, tunnel tokens and webhook secrets;
- identifying audit, incident, support or telemetry text.

Prefer a purpose-built demo/synthetic household configuration when capturing documentation images. Cropping or blurring after capture is a secondary control, not permission to expose secrets during the capture process.
