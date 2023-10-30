# Keycloak Multistep Registration

This POC is aimed at addressing the shortcomings in the Keycloak registration process by adding the following functionalities:

1. Username first registration process - the user can start the registration process just by inputting his username.
2. Email OTP - An email is sent to the username (email) provided above, such that Keycloak can verify ownership. Some credits go to https://github.com/p2-inc/keycloak-magic-link for the Email OTP implementation.
3. User Details registration - After successful verification, the rest of the details can be entered by the user. **Only after this stage is completed the user is persisted to the database! This ensures that the Keycloak data store is not littered with spam registrations.**
4. If someone inputs an existing username during the registration process, the Email OTP still kicks in, this ensures that we do not leak whether a user exists in our database or not!

An example of a Registration Flow setup is as follows:

![](/docs/img/img.png)