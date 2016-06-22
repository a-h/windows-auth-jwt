Windows Auth JWT
================

Uses Windows Authentication to create a signed JWT - used to create a single-sign-on system for Web applications.

* Users are first authenticated against by IIS using Windows authentication.
* The .Net code then:
 - Creates a JWT to represent the user.
 - Loads a private key from the configuration and uses it to sign the JWT.
 - Redirects the user to the external service.
   - The external service must be configured to validate the JWT using the public key which corresponds to the private key in the configuration.

To generate private and public PEM files, the following openssl commands can be used:

```
# Create the private key.
openssl genrsa -out private.pem 2048
# Extract the public key from the private key.
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

The JWT created by this application can be validated using https://jwt.io
