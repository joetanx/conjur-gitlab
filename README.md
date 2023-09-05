## 1. Introduction

### 1.1. How does GitLab integration with Conjur using JWT work?

![image](https://github.com/joetanx/conjur-gitlab/assets/90442032/e387104e-d70e-472d-a374-0105b0b6d618)

① Every GitLab CI/CD pipeline has a `CI_JOB_JWT_V2` JSON web token in the [predefined variables](https://docs.gitlab.com/ee/ci/variables/predefined_variables.html)

- Example JWT

```json
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

> [!Note]
> 
> The value of `CI_JOB_JWT_V2` is masked on GitLab jobs
> 
> To get the value:
> 
> - use `echo ${CI_JOB_JWT_V2} | base64`
> 
> - [decode](https://www.base64decode.org/) the base64 output
> 
> - then [decode](https://jwt.io/) the JWT

② The GitLab runner sends an authentication request to Conjur using REST API to the JWT authenticator URI (`<Conjur-Appliance-URL>/authn-jwt/<service-id>`)

- The URI for this demo is `https://conjur.vx/authn-jwt/gitlab`

③ Conjur fetches the public key from the GitLab JWKS URI

- The GibLab JWKS URI is at `<GitLab-URL>/-/jwks/`
- This JWKS URI is set in the `jwks-uri` variable of the JWT authenticator in Conjur so that Conjur knows where to find the JWKS

④ Conjur verifies that the token is legit with the JWKS public key and authenticates application identity

- Conjur identifies the application identity via the `token-app-property` variable of the JWT authenticator
- The `token-app-property` variable is set in Conjur as the `project_path` claim in this demo
- Conjur further verifies the applications details as configured in the `annotations` listed in the `host` (application identity) declaration
- Annotation `sub` is defined for the application identity in this demo - the JWT claims from GitLab needs to tally with the declaration for application authentication to be successful
  - The `sub` claim from Gitlab is a combination of `project_path` + `ref_type` + `ref` attributes of the project (see example JWT above)

⑤ Conjur returns an access token to the GitLab runner if authentication is successful

⑥ The GitLab runner will then use the access token to retrieve the secrets using REST API to the secrets URI

## 2. Preparation

### 2.1. Lab details

#### Software Versions

- RHEL 9.2
- Podman 4.4.1
- GitLab 16.2.4
- Conjur Enterprise 13.0

#### Servers

|Hostname|Role|
|---|---|
|conjur.vx|Conjur master|
|gitlab.vx|Gitlab node + GitLab runner|

### 2.2. Setup Conjur master

Setup Conjur master according to this guide: https://github.com/joetanx/setup/blob/main/conjur.md

### 2.2. Setup GitLab

Setup Gitlab community edition according to this guide: https://github.com/joetanx/setup/blob/main/gitlab.md

## 3. Conjur policies for GitLab JWT

### 3.1. Details of Conjur policies used in this demo

#### 3.1.1. JWT authenticator policy

The policy `authn-jwt-gitlab.yaml` performs the following:
- Configures the JWT authenticator (https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Operations/Services/cjr-authn-jwt.htm)
- Defines the authenticator webservice at `authn-jwt/gitlab`
  - The format of the authenticator webservice is `authn-jwt/<service-id>`, the `<service-id>` used in this demo is `gitlab`, this is the URI where the GitLab pipeline will authenticate to.

- Defines the authentication variables: how the JWT Authenticator gets the signing keys

|Variables|Description|
|---|---|
|`jwks-uri`|JSON Web Key Set (JWKS) URI. For GitLab this is `https://<GitLab-URL>/-/jwks/`.|
|`public-keys`|Used to provide a static JWKS to the JWT authenticator if Conjur is unable to reach a remote JWKS URI endpoint|
|`ca-cert`|The CA certificate that signed the GitLab server certificate. **Implemented only beginning from Conjur version 12.5.**|
|`token-app-property`|The JWT claim to be used to identify the application. This demo uses the `project_path` claim from GitLab. |
|`identity-path`|The Conjur policy path where the app ID (`host`) is defined in Conjur policy. The app IDs in `gitlab-hosts.yaml` are created under `jwt-apps/gitlab`, so the `identity-path` is `jwt-apps/gitlab`.|
|`issuer`|URI of the JWT issuer. This is the GitLab URL. This is included in `iss` claim in the JWT token claims.|
|`enforced-claims`|List of claims that are enforced (i.e. must be present in the JWT token claims). Not used in this demo.|
|`claim-aliases`|Map claims to aliases. Not used in this demo.|
|`audience`|This is also the GitLab URL. Not used in this demo (since this is idential to `issuer` for GitLab).|

- Defines `consumers` group - applications that are authorized to authenticate using this JWT authenticator are added to this group
- Defines `operators` group - users who are authorized to check the status of this JWT authenticator are added to this group

#### 3.1.2. Host identity policy

The policy `gitlab-hosts.yaml` performs the following:
- `jwt-apps/gitlab` - policy name, this is also the `identity-path` of the app IDs
- applications `cybr/aws-access-key-demo` and `cybr/mysql-demo` are configured
  - the `id` of the `host` corresponds to the `token-app-property`
  - annotations of the `host` are optional and corresponds to claims in the JWT token claims - the more specific the annotations/claims configured, the more precise and secure the application authentication
- the host layer is granted as a member of the `consumers` group defined in `authn-jwt.yaml` to authorize them to authenticate to the JWT authenticator
- `cybr/aws-access-key-demo` and `cybr/mysql-demo` are granted access to secrets in `aws_api` and `db_cicd` by granting them as members of the respective `consumers` group defined in `app-vars.yaml`

> [!Note]
> 
> `gitlab-hosts.yaml` builds on top of `app-vars.yaml` in https://github.com/joetanx/setup/blob/main/conjur.md
> 
> Loading `authn-jwt-hosts.yaml` without having `app-vars.yaml` loaded previously will not work

### 3.2. Load the Conjur policies and prepare Conjur for GitLab JWT

Login to Conjur

```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```

Download and load the Conjur policies

```console
curl -sLO https://github.com/joetanx/conjur-gitlab/raw/main/policies/authn-jwt-gitlab.yaml
curl -sLO https://github.com/joetanx/conjur-gitlab/raw/main/policies/gitlab-hosts.yaml
conjur policy load -b root -f authn-jwt-gitlab.yaml && rm -f authn-jwt-gitlab.yaml
conjur policy load -b root -f gitlab-hosts.yaml && rm -f gitlab-hosts.yaml
```

Enable the JWT Authenticator

> [!Note]
> 
> This step requires that the `authenticators` section in `/etc/conjur/config/conjur.yml` to be configured
> 
> Ref: [2.5. Allowlist the Conjur default authenticator](https://github.com/joetanx/setup/blob/main/conjur.md#25-allowlist-the-conjur-default-authenticator)

```console
podman exec conjur sed -i -e '/authenticators:/a\  - authn-jwt/gitlab' /etc/conjur/config/conjur.yml
podman exec conjur evoke configuration apply
```

Inject the CA certificate into a environment variable to be set into Conjur variable
- The GitLab server certificate in this demo is signed by a personal CA (`central.pem`), you should use your own certificate chain in your own environment

```console
CA_CERT="$(curl https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/central.pem)"
```

Populate the variables

> [!Note]
> 
> This step requires that the `app-var.yaml` to be already loaded in [3.0. Staging secret variables](https://github.com/joetanx/setup/blob/main/conjur.md#30-staging-secret-variables)

```console
conjur variable set -i conjur/authn-jwt/gitlab/jwks-uri -v https://gitlab.vx/-/jwks/
conjur variable set -i conjur/authn-jwt/gitlab/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-jwt/gitlab/token-app-property -v project_path
conjur variable set -i conjur/authn-jwt/gitlab/identity-path -v jwt-apps/gitlab
conjur variable set -i conjur/authn-jwt/gitlab/issuer -v https://gitlab.vx
```

## 4. GitLab Projects

### 4.1. AWS Connection Test

This project tests retrieval of the AWS secret access key from Conjur

#### 4.1.1. Create a new project

GitLab project name: `AWS Connection Test`

☝️ Project name is important! The `project path` must match the `host` identity configured in the Conjur policy

![aws-connection-test-1](https://github.com/joetanx/conjur-gitlab/assets/90442032/b0fbbb78-f3c5-4164-b239-48ed946d39f2)

> [!Note]
> 
> Adding Conjur certificate to project
> 
> Place the Conjur certificate or the CA certificate which signed the Conjur certificate is required, edit the certificate path variable or attribute to point to this file
> 
> The `CONJUR_CERT_FILE` variable must point to this file (`central.pem` in this example)

#### 4.1.2. Create the [main.tf](/aws-cli-demo/main.tf) file

![aws-connection-test-2](https://github.com/joetanx/conjur-gitlab/assets/90442032/eb848703-c640-49ad-bd9c-bc022fa6126a)

#### 4.1.3. Edit the GitLab CI/CD file

There are 2 stages in the pipeline code below:
1. Fetch variables from Conjur (using CyberArk GitLab runner image)
  - Authenticate to Conjur `authn-jwt/jtan-gitlab` using `CI_JOB_JWT_V2`
  - Retrive AWS credentials
  - Pass the credentials to the next stage using `artifacts:`, `reports:`, `dotenv:`
2. Test the AWS credentials
  - Run Terraform using `docker.io/hashicorp/terraform:latest` image
  - Run AWS CLI using `docker.io/amazon/aws-cli:latest` image

https://github.com/joetanx/conjur-gitlab/blob/c122b728a15a1ab5397d4e54029d16b3b94e5c7f/aws-connection-test/.gitlab-ci.yml#L1-L33

![aws-connection-test-3](https://github.com/joetanx/conjur-gitlab/assets/90442032/ba07a2a6-a7a5-46f9-b65d-e9d819ba9c91)

#### 4.1.4. Pipeline run results

All jobs passed in the pipeline:

![aws-connection-test-4](https://github.com/joetanx/conjur-gitlab/assets/90442032/d413437a-dd54-4108-8860-826c58169e82)

Output for fetch variables job:

![aws-connection-test-5](https://github.com/joetanx/conjur-gitlab/assets/90442032/f40bb510-6648-4df9-aba2-1d83e8c7b241)

Output for AWS CLI job:

![aws-connection-test-6](https://github.com/joetanx/conjur-gitlab/assets/90442032/e1d33e37-b5db-493f-b8d5-4b3293fae64e)

Output for Terraform job:

![aws-connection-test-7](https://github.com/joetanx/conjur-gitlab/assets/90442032/e4f54b9f-69c0-49a2-a0e1-d891e15bd6fe)

### 4.2. AWS Create S3 Bucket

This project demostrates the use of AWS secret access key retrieved from Conjur to create a S3 bucket

#### 4.2.1. Create a new project

GitLab project name: `AWS Create S3 Bucket`

☝️ Project name is important! The `project path` must match the `host` identity configured in the Conjur policy

![aws-create-s3-bucket-1](https://github.com/joetanx/conjur-gitlab/assets/90442032/c7fd5837-3676-45d0-98f3-fcf4bd1baaf4)

> [!Note]
> 
> Adding Conjur certificate to project
> 
> Place the Conjur certificate or the CA certificate which signed the Conjur certificate is required, edit the certificate path variable or attribute to point to this file
> 
> The `CONJUR_CERT_FILE` variable must point to this file (`central.pem` in this example)

#### 4.2.2. Create the [demo.txt](/aws-create-s3-bucket/demo.txt), [main.tf](/aws-create-s3-bucket/main.tf) and [provider.tf](/aws-create-s3-bucket/provider.tf) files

![aws-create-s3-bucket-2](https://github.com/joetanx/conjur-gitlab/assets/90442032/1c6efa4b-d772-4957-980f-de4bf92b55b4)

#### 4.2.3. Edit the GitLab CI/CD file

There are 2 stages in the pipeline code below:
1. Fetch variables from Conjur (using CyberArk GitLab runner image)
  - Authenticate to Conjur `authn-jwt/jtan-gitlab` using `CI_JOB_JWT_V2`
  - Retrive AWS credentials
  - Pass the credentials to the next stage using `artifacts:`, `reports:`, `dotenv:`
2. Run Terraform to create S3 bucket according to `main.tf` using credentials from Conjur

https://github.com/joetanx/conjur-gitlab/blob/c122b728a15a1ab5397d4e54029d16b3b94e5c7f/aws-create-s3-bucket/.gitlab-ci.yml#L1-L26

![aws-create-s3-bucket-3](https://github.com/joetanx/conjur-gitlab/assets/90442032/9164bbe2-3ec6-44ed-9879-b9eedc9fdbb9)

#### 4.2.4. Pipeline run results

Both jobs passed in the pipeline:

![aws-create-s3-bucket-4](https://github.com/joetanx/conjur-gitlab/assets/90442032/05b78ba7-2632-4045-91d7-09d3d7b7fbb3)

Output for fetch variables job:

![aws-create-s3-bucket-5](https://github.com/joetanx/conjur-gitlab/assets/90442032/7302ee4b-40b9-49a5-8664-e1936ad59fcb)

Output for Terraform job:

![aws-create-s3-bucket-6](https://github.com/joetanx/conjur-gitlab/assets/90442032/ea7e8751-9a71-4c28-a055-d3dbf97352f9)

### 4.3. AWS Verify and Cleanup S3 Bucket

This project is used to verify the bucket created from the demo job above

#### 4.3.1. Create a new project

GitLab project name: `AWS Verify and Cleanup S3 Bucket`

☝️ Project name is important! The `project path` must match the `host` identity configured in the Conjur policy

![aws-verify-and-cleanup-s3-bucket-1](https://github.com/joetanx/conjur-gitlab/assets/90442032/de540371-cb23-4242-bb09-1c91e13f0b5e)

> [!Note]
> 
> Adding Conjur certificate to project
> 
> Place the Conjur certificate or the CA certificate which signed the Conjur certificate is required, edit the certificate path variable or attribute to point to this file
> 
> The `CONJUR_CERT_FILE` variable must point to this file (`central.pem` in this example)

#### 4.3.2. Edit the GitLab CI/CD file

There are 3 stages in the pipeline code below:
1. Fetch variables from Conjur (using CyberArk GitLab runner image)
  - Authenticate to Conjur `authn-jwt/jtan-gitlab` using `CI_JOB_JWT_V2`
  - Retrive AWS credentials
  - Pass the credentials to the next stage using `artifacts:`, `reports:`, `dotenv:`
2. Run AWS CLI to get the demo file from the S3 bucket created above using credentials from Conjur
3. Manual job to delete the bucket

https://github.com/joetanx/conjur-gitlab/blob/c122b728a15a1ab5397d4e54029d16b3b94e5c7f/aws-verify-and-cleanup-s3-bucket/.gitlab-ci.yml#L1-L35

![aws-verify-and-cleanup-s3-bucket-2](https://github.com/joetanx/conjur-gitlab/assets/90442032/94119da1-92ce-4c74-b3fd-b0e7b8ab691f)

#### 4.2.4. Pipeline run results

Both jobs passed in the pipeline (manual job is pending manual activation):

![aws-verify-and-cleanup-s3-bucket-3](https://github.com/joetanx/conjur-gitlab/assets/90442032/906753c6-b4f3-49a2-b629-da7ccee6913b)

Output for fetch variables job:

![aws-verify-and-cleanup-s3-bucket-4](https://github.com/joetanx/conjur-gitlab/assets/90442032/a9f22c63-65be-4bbd-818f-92d6cab7e745)

Output for verify bucket job:

![aws-verify-and-cleanup-s3-bucket-5](https://github.com/joetanx/conjur-gitlab/assets/90442032/cb554b64-0533-47d0-8a85-41aff8b7c661)

Proceed to run the last job to delete bucket:

![aws-verify-and-cleanup-s3-bucket-6](https://github.com/joetanx/conjur-gitlab/assets/90442032/aaae993c-6391-4d1a-96da-460c2ca1093c)

Output for delete bucket job:

![aws-verify-and-cleanup-s3-bucket-7](https://github.com/joetanx/conjur-gitlab/assets/90442032/e7651f74-0931-404f-b67d-9013e73a3527)

## Archived - Trusting CA certificate in Conjur container

- For Conjur versions before 12.5, the `authn-jwt/<service-id>/ca-cert` variable was not yet implemented.
- If you are using a self-signed or custom certificate chain in your GitLab like I did in this demo, you will encounter the following error in Conjur, because the GitLab certificate chain is not trusted by Conjur applicance.

```console
USERNAME_MISSING failed to authenticate with authenticator authn-jwt service cyberark:webservice:conjur/authn-jwt/gitlab:
**CONJ00087E** Failed to fetch JWKS from 'https://gitlab.vx-/jwks/'.
Reason: '#<OpenSSL::SSL::SSLError: SSL_connect returned=1 errno=0 state=error: certificate verify failed (self signed certificate in certificate chain)>'
```

- Import your GitLab certificate or the root CA certificate to Conjur appliance
- **Note**: The hash of my CA certificate is **a3280000**, hence I need to create a link **a3280000.0** to my CA certificate. You will need to get the hash of your own CA certificate from the openssl command, and link the certificate to `/etc/ssl/certs/<your-ca-hash>.0`
- This procedure is documented in: <https://cyberark-customers.force.com/s/article/Conjur-CONJ0087E-Failed-to-fetch-JWKS-from-GitLab-certificate-verify-failed>

```console
curl -O https://raw.githubusercontent.com/joetanx/conjur-gitlab/main/central.pem
podman cp central.pem conjur:/etc/ssl/certs/central.pem
podman exec conjur openssl x509 -noout -hash -in /etc/ssl/certs/central.pem
podman exec conjur ln -s /etc/ssl/certs/central.pem /etc/ssl/certs/a3280000.0
```
