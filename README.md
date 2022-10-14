# UNDER CONSTRUCTION

# Integrate GitLab with Conjur Enterprise using the JWT authenticator

## Introduction

[PLACEHOLDER]

## How does GitLab integration with Conjur using JWT work?

[PLACEHOLDER]

- Example JWT

```console
{
  "namespace_id": "2",
  "namespace_path": "cybr",
  "project_id": "2",
  "project_path": "cybr/aws-access-key-demo",
  "user_id": "1",
  "user_login": "root",
  "user_email": "joe.tan@cyberark.com",
  "pipeline_id": "2",
  "pipeline_source": "push",
  "job_id": "6",
  "ref": "main",
  "ref_type": "branch",
  "ref_protected": "true",
  "jti": "e8c142e7-fbc3-437f-a6c1-4aeccf6de6b4",
  "iss": "https://gitlab.vx",
  "iat": 1665704185,
  "nbf": 1665704180,
  "exp": 1665707785,
  "sub": "project_path:cybr/aws-access-key-demo:ref_type:branch:ref:main",
  "aud": "https://gitlab.vx"
}
```

# Conjur policies for GitLab JWT

## Load the Conjur policies and prepare Conjur for GitLab JWT

- Login to Conjur

```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```

- Download and load the Conjur policies

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/authn-jwt.yaml
curl -O https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/authn-jwt-hosts.yaml
conjur policy load -b root -f authn-jwt.yaml && rm -f authn-jwt.yaml
conjur policy load -b root -f authn-jwt-hosts.yaml && rm -f authn-jwt-hosts.yaml
```

- Enable the JWT Authenticator

- ☝️ **Note**: This step requires that the `authenticators` section in `/etc/conjur/config/conjur.yml` to be configured (Ref: 2.5 <https://joetanx.github.io/conjur-master#25-allowlist-the-conjur-default-authenticator>)

```console
podman exec conjur sed -i -e '/authenticators:/a\  - authn-jwt/gitlab' /etc/conjur/config/conjur.yml
podman exec conjur evoke configuration apply
```

- Inject the CA certificate into a environment variable to be set into Conjur variable
- The Jenkins server certificate in this demo is signed by a personal CA (`central.pem`), you should use your own certificate chain in your own environment
- ☝️ **Note**: The `authn-jwt/<service-id>/ca-cert` variable is implemented begining from Conjur version 12.5. If you are using an older version of Conjur, the CA certificates needs to be trusted by the Conjur container. Read the `Archived - Trusting CA certificate in Conjur container` section at the end of this page.

```console
CA_CERT="$(curl https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/central.pem)"
```

- Populate the variables
- Assumes that the secret variables in `world_db` and `aws_api` are already populated in step 2 (Setup Conjur master)

```console
conjur variable set -i conjur/authn-jwt/gitlab/jwks-uri -v https://gitlab.vx/-/jwks/
conjur variable set -i conjur/authn-jwt/gitlab/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-jwt/gitlab/token-app-property -v project_path
conjur variable set -i conjur/authn-jwt/gitlab/identity-path -v jwt-apps/gitlab
conjur variable set -i conjur/authn-jwt/gitlab/issuer -v https://gitlab.vx
```

# Archived - Trusting CA certificate in Conjur container

- For Conjur versions before 12.5, the `authn-jwt/<service-id>/ca-cert` variable was not yet implemented.
- If you are using a self-signed or custom certificate chain in your jenkins like I did in this demo, you will encounter the following error in Conjur, because the Jenkins certificate chain is not trusted by Conjur applicance.

```console
USERNAME_MISSING failed to authenticate with authenticator authn-jwt service cyberark:webservice:conjur/authn-jwt/jenkins:
**CONJ00087E** Failed to fetch JWKS from 'https://jenkins.vx:8443/jwtauth/conjur-jwk-set'.
Reason: '#<OpenSSL::SSL::SSLError: SSL_connect returned=1 errno=0 state=error: certificate verify failed (self signed certificate in certificate chain)>'
```

- Import your Jenkins certificate or the root CA certificate to Conjur appliance
- **Note**: The hash of my CA certificate is **a3280000**, hence I need to create a link **a3280000.0** to my CA certificate. You will need to get the hash of your own CA certificate from the openssl command, and link the certificate to `/etc/ssl/certs/<your-ca-hash>.0`
- This procedure is documented in: <https://cyberark-customers.force.com/s/article/Conjur-CONJ0087E-Failed-to-fetch-JWKS-from-GitLab-certificate-verify-failed>

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-jenkins/main/central.pem
podman cp central.pem conjur:/etc/ssl/certs/central.pem
podman exec conjur openssl x509 -noout -hash -in /etc/ssl/certs/central.pem
podman exec conjur ln -s /etc/ssl/certs/central.pem /etc/ssl/certs/a3280000.0
```

# Configure GitLab

## Configure MySQL Demo project

```console
getDatabases:
  stage: test
  script:
    - 'export SESSIONTOKEN=$(curl -X POST https://conjur.vx/authn-jwt/gitlab/cyberark/authenticate -H "Content-Type: application/x-www-form-urlencoded" -H "Accept-Encoding: base64" --data-urlencode "jwt=$CI_JOB_JWT_V2")'
    - 'export MYSQLUSER=$(curl -H "Authorization: Token token=\"$SESSIONTOKEN\"" https://conjur.vx/secrets/cyberark/variable/world_db/username)'
    - 'export MYSQLPASSWORD=$(curl -H "Authorization: Token token=\"$SESSIONTOKEN\"" https://conjur.vx/secrets/cyberark/variable/world_db/password)'
    - mysql --host=mysql.vx --user=$MYSQLUSER --password=$MYSQLPASSWORD -e "SHOW DATABASES;"
```

## Configure AWS Access Key Demo project

```console
awsListUsers:
  stage: test
  script:
    - export AWS_DEFAULT_REGION=ap-southeast-1
    - 'SESSIONTOKEN=$(curl -X POST https://conjur.vx/authn-jwt/gitlab/cyberark/authenticate -H "Content-Type: application/x-www-form-urlencoded" -H "Accept-Encoding: base64" --data-urlencode "jwt=$CI_JOB_JWT_V2")'
    - 'export AWS_ACCESS_KEY_ID=$(curl -H "Authorization: Token token=\"$SESSIONTOKEN\"" https://conjur.vx/secrets/cyberark/variable/aws_api/awsakid)'
    - 'export AWS_SECRET_ACCESS_KEY=$(curl -H "Authorization: Token token=\"$SESSIONTOKEN\"" https://conjur.vx/secrets/cyberark/variable/aws_api/awssak)'
    - aws iam list-users
```
