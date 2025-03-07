# IMPORTANT: EXPERIMENTAL USE ONLY

The code in this package is still in development. **IT IS NOT SUITABLE FOR PRODUCTION USE** at this time, is subject
to backwards-incompatible changes, and will be moved to a different repository when released.

# About

An Apache Cassandra authenticator plugin which enables clients to use their AWS Identity and Access Management (IAM)
credentials -- including credentials for IAM users, roles and EC2 instance roles -- to authenticate to an appropriately
configured Cassandra node. The plugin in this module is for use with the (DataStax) Cassandra Java driver. A matching
plugin for Cassandra nodes is available in a separate repo:
https://github.com/jcshepherd/aws-sts-auth-cassandra-authenticator-plugin . The two requirements for using these
plugins are:
1. The client must be able to provide valid AWS IAM credentials that can be used to sign a request with AWS SigV4. If
   successfully authenticated, the client's identity will be represented by the ARN of the AWS IAM principal associated
   with the signing credentials.
2. The node must be able to reach (i.e. connect over the Internet) the
   [AWS Security Token Service](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html) endpoint specified by
   the client in its authentication response.

Neither the node nor client need to run on AWS infrastructure, and the node itself does not need to be associated with
any AWS account. No particular IAM permissions need to be associated with the AWS account used by the client in order
to use this authenticator.

# Using the Plugin

The node plugin in its current state builds for Cassandra 5 only. Builds for other Cassandra versions are coming.

## Building

Build the project with:
```mvn clean install```

## Configuration

To use this authenticator plugin, you need to add it to the classpath of the application that will use Cassandra's
Java driver, and configure the driver to use the plugin for authentication.

### Classpath

Configuring your application's classpath is highly situation-specific and is left as an exercise for the reader.

### Configuration

Add/modify the following configuration in your driver's configuration file (refer to `core/src/main/resources/reference.conf`
in the driver project).

```
advanced.auth-provider {
  class = software.aws.cassandra.sts.auth.STSAuthProvider
```

You will need to restart your application for these changes to take effect. Note that currently Cassandra can
support a single authenticator: a node enabled for IAM-based authentication won't be able to authenticate by other
mechanisms.

# How it Works

Please see the README for the associated node-side authenticator plugin: https://github.com/jcshepherd/aws-sts-auth-cassandra-authenticator-plugin

# Notes

## Use region-specific AWS STS endpoints

Client-side users of this authenticator are STRONGLY recommended not to use the "global" sts.amazonaws.com endpoint
of the AWS Security Token Service (STS). That endpoint is located in single AWS region (us-east-1) and while it
maintains high availability, it is subject to region-impacting events and does not support automated fail-over to STS
endpoints in other regions. Please use the region-specific endpoint "nearest" the Cassandra cluster you wish to
connect to, as documented here: https://docs.aws.amazon.com/general/latest/gr/sts.html .

## Auth Challenge structure

The structure of the auth challenge sent from the node to the client is likely to change before release. In particular,
the revised challenge will include the length of the nonce in bytes, which will be used on the client side to more
safely extract the nonce.
