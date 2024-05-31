# Breach Shield

A MyBB plugin that rejects compromised passwords during login attempts, protecting against [credential stuffing](https://en.wikipedia.org/wiki/Credential_stuffing) attacks.

Submitted values are checked against a list of compromised passwords from the [HIBP API](https://haveibeenpwned.com/API/v3#PwnedPasswords) using a partial hash. Recognized passwords produce an [error message](https://github.com/dvz/mybb-breachshield/blob/main/inc/languages/english/breachshield.lang.php#L3) directing users to reset their password using e-mail.

The length of automatically generated passwords during password reset is set to 20.

## Requirements
- MyBB ≥ 1.8
- PHP ≥ 7.1
