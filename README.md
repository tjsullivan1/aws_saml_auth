# AWS SAML Auth Python Script
> This will connect to an ADFS IDP to generate a SAML credential for AWS CLI usage.

This script will connect to an ADFS Identity Provider and will allow you to select which role you want to assume using SAML. It will list all accounts and roles that you have access to through your identity provider. For more information on how this was built, see [my blog](https://tjsullivan1.github.io/blog/2017/05/04/saml-for-aws-2) and the [AWS Security Blog](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/).

## Installation

Run a command line/shell as administrator that has pip in the path.
```
pip install boto3 bs4 awscli requests configparser lxml plac
```

Download the script and invoke by running `py aws_saml_auth.py`.

## Usage example

### Base Usage
Run `py aws_saml_auth.py`.

### Advanced Usage To Convert to Friendly Names
Create a file that contains a comma separated list with 'AWS Account ID','Name You Remember' (e.g., '012345678901','Prod')
Run `py aws_saml_auth.py -f account_ids.txt`

## Development setup

N/A for now.

## Release History

* 1.0.0
    * Initial GitHub relase. Works with several parameters.
* 1.1.0
    * Added function to ingest an id file and convert the mapping into friendly names.
* 1.2.0
    * Added session duration to the SAML token request to be able to take advantage of longer maximum session durations.
* 1.2.1
    * Demoing git

## Meta

Tim Sullivan – [@SullivanTim](https://twitter.com/SullivanTim) – timothyj.sullivan1@gmail.com

[https://github.com/tjsullivan1/aws_saml_auth](https://github.com/tjsullivan1/aws_saml_auth)

## Contributing

1. Fork it (<https://github.com/tjsullivan1/aws_saml_auth/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
