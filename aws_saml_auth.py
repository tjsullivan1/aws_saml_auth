#!/usr/bin/python

import sys
import os
import boto3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import urllib.parse
import plac
from bs4 import BeautifulSoup
from os.path import expanduser

##########################################################################
# Variables

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://adfs.stthomas.edu/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

# Uncomment to enable low level debugging
# logging.basicConfig(filename='aws_saml_auth.log', level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')

##########################################################################


def make_friendly_name(saml_role_response, account_name, account_id):
    """Replace the AWS friendly format with user friendly format
    Example:
    Convert arn:aws:iam::012345678901:role/Admin to Prod/Admin
    make_friendly_name('arn:aws:iam::012345678901:role/Admin', 'Prod', '012345678901')

    Keyword arguments:
    saml_role_response -- This is an AWS friendly role name, e.g. arn:aws:iam::012345678901:role/Admin
    account_name       -- This is the user friendly name for the account, e.g. "Prod"
    account_id         -- The AWS account id 012345678901
    """
    saml_role_response = re.sub(account_id, account_name, saml_role_response).replace(
        'arn:aws:iam::', '').replace(':role', '')
    return saml_role_response


def return_friendly_name_from_file(saml_role_response, filename):
    """Replace the AWS friendly format with user friendly format, using file map
    Example:
    Convert arn:aws:iam::012345678901:role/Admin to Prod/Admin
    return_friendly_name_from_file('arn:aws:iam::012345678901:role/Admin', 'account_ids.txt')

    Keyword arguments:
    saml_role_response -- This is an AWS friendly role name, e.g. arn:aws:iam::012345678901:role/Admin
    filename           -- This is the name of a file that contains comma separated values, e.g. account_ids.txt
    """
    tmp_account_id = re.sub(
        r'\/.*', '', saml_role_response).replace('arn:aws:iam::', '').replace(':role', '')
    if os.path.exists(filename):
        with open(filename, 'r') as account_file:
            found = False
            for line in account_file:
                if re.search(tmp_account_id, line):
                    good_line = line
                    found = True
            if found:
                account_id, account_name = good_line.rstrip().split(',')
                if account_id in saml_role_response:
                    return make_friendly_name(saml_role_response, account_name, account_id)
            else:
                return saml_role_response
    else:
        return saml_role_response


def login(username: ("Your user-principal-name", 'option', 'u'),
          profile: ("The name of the profile we want to put it the credential file", 'option', 'p')='default',
          region: ("The AWS region", 'option', 'r')='us-east-2',
          filename: ("The filename that contains a comma separated mapping of account ids to friendly names",
                     'option', 'f')='account_ids.txt'):
    """login function"""
    # Get the federated credentials from the user
    # If username was not passed as a parameter, we know to ask for it...
    if not username:
        print("Username:", end=""),
        username = input()
    password = getpass.getpass()
    print("")
    logging.debug('Captured user credentials.')

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idpentryurl, verify=sslverification)
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, "lxml")
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "user" in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    # Debug the parameter payload if needed
    # Use with caution since this will print sensitive output to the log file
    # logging.debug(payload)

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the
    # idpauthformsubmiturl above
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        loginid = inputtag.get('id')
        if (action and loginid == "loginForm"):
            parsedurl = urllib.parse.urlsplit(idpentryurl)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

    # Performs the submission of the IdP login form with the above post data
    response = session.post(
        idpauthformsubmiturl, data=payload, verify=sslverification)

    # Debug the response if needed
    #print (response.text)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, "lxml")
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            # print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if (assertion == ''):
        # TODO: Insert valid error checking/handling
        print("Response did not contain a valid SAML assertion")
        sys.exit(0)

    # Debug only
    logging.debug(base64.b64decode(assertion))

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    logging.debug(awsroles)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")
    if len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            current_role = return_friendly_name_from_file(
                awsrole.split(',')[0], filename)
            print('[', i, ']: ', current_role)
            i += 1
        print("Selection: ", end="")
        selectedroleindex = input()

        # Basic sanity check of input
        if int(selectedroleindex) > (len(awsroles) - 1):
            print('You selected an invalid role index, please try again')
            sys.exit(0)

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    conn = boto3.client('sts')
    token = conn.assume_role_with_saml(
        RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion)

    # Write the AWS STS token into the AWS credential file
    os_home = '~'
    home = expanduser(os_home)
    filepath = os.path.join(home, awsconfigfile)
    credential_filename = os.path.normpath(filepath)

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(credential_filename)

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)

    # boto3 outputs a dict that doesn't work with the AWS original script
    saml_access_key = token[u'Credentials'][u'AccessKeyId']
    saml_secret_key = token[u'Credentials'][u'SecretAccessKey']
    saml_session_token = token[u'Credentials'][u'SessionToken']
    saml_expiration = token[u'Credentials'][u'Expiration']

    config.set(profile, 'output', outputformat)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', saml_access_key)
    config.set(profile, 'aws_secret_access_key', saml_secret_key)
    config.set(profile, 'aws_session_token', saml_session_token)

    # Write the updated config file, but create it if it doesn't exist!
    if not os.path.isdir(os.path.dirname(credential_filename)):
        os.makedirs(os.path.dirname(credential_filename))

    mode = 'w+' if os.path.exists(credential_filename) else 'w'
    with open(credential_filename, mode) as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    print('\n\n----------------------------------------------------------------')
    print('Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'.format(credential_filename, profile))
    print('Note that it will expire at {0}.'.format(saml_expiration))
    print('After this time, you may safely rerun this script to refresh your access key pair.')
    print('If you specified a credential other than default, to use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(profile))
    print('----------------------------------------------------------------\n\n')


plac.call(login)
