#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { SecureAwsEnvStack } from '../lib/secure-aws-env-stack';
require('dotenv').config();


const app = new cdk.App();
new SecureAwsEnvStack(app, 'SecureAwsEnvStack', {
  env: { account: process.env.CDK_ACCOUNT, region: process.env.CDK_REGION },
});