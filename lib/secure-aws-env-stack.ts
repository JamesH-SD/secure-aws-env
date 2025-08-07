import * as cdk from 'aws-cdk-lib';
import { Stack, StackProps, Tags } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as configservice from 'aws-cdk-lib/aws-config';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as dotenv from 'dotenv';
import { AwsCustomResource, AwsCustomResourcePolicy, PhysicalResourceId } from 'aws-cdk-lib/custom-resources';
dotenv.config();

export class SecureAwsEnvStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const stackTag = { key: 'Project', value: 'SecureAwsEnv' };

    const subscriptionEmail = process.env.SNS_SUBSCRIPTION_EMAIL;
    if (!subscriptionEmail) {
      throw new Error('SNS_SUBSCRIPTION_EMAIL environment variable is not defined');
    }

    // 🪣 S3 Bucket (SSE-S3)
    const secureBucket = new s3.Bucket(this, 'SecureClientData', {
      bucketName: 'secure-aws-env-bucket', // must be globally unique
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });
    Tags.of(secureBucket).add(stackTag.key, stackTag.value);

    // Allow CloudTrail to write to bucket
    secureBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSCloudTrailBucketAcl',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
      actions: ['s3:GetBucketAcl'],
      resources: [secureBucket.bucketArn],
    }));

    secureBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSCloudTrailWrite',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [secureBucket.arnForObjects(`AWSLogs/${this.account}/*`)],
      conditions: { StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' } },
    }));

    // Allow AWS Config to write to bucket (prefix: config/)
    secureBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSConfigWrite',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('config.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [secureBucket.arnForObjects('config/*')],
      conditions: { StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' } },
    }));
    secureBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSConfigGetBucketAcl',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('config.amazonaws.com')],
      actions: ['s3:GetBucketAcl'],
      resources: [secureBucket.bucketArn],
    }));

    // 📘 CloudWatch Log Group for CloudTrail
    const cloudTrailLogGroup = new logs.LogGroup(this, 'CloudTrailLogGroup', {
      logGroupName: '/aws/cloudtrail/secure-aws-env-stack',
      retention: logs.RetentionDays.ONE_YEAR,
    });
    Tags.of(cloudTrailLogGroup).add(stackTag.key, stackTag.value);

    // Role for CloudTrail to write to CW Logs
    const cloudTrailCWLogsRole = new iam.Role(this, 'CloudTrailCWLogsRole', {
      assumedBy: new iam.ServicePrincipal('cloudtrail.amazonaws.com'),
      inlinePolicies: {
        LogPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['logs:PutLogEvents', 'logs:CreateLogStream', 'logs:DescribeLogStreams'],
              resources: [cloudTrailLogGroup.logGroupArn],
            }),
          ],
        }),
      },
    });

    // 👣 CloudTrail
    const cloudTrail = new cloudtrail.CfnTrail(this, 'SecureTrail', {
      s3BucketName: secureBucket.bucketName,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      cloudWatchLogsLogGroupArn: cloudTrailLogGroup.logGroupArn,
      cloudWatchLogsRoleArn: cloudTrailCWLogsRole.roleArn,
      isLogging: true,
      insightSelectors: [
        { insightType: 'ApiCallRateInsight' },
        { insightType: 'ApiErrorRateInsight' },
      ],
      eventSelectors: [
        {
          readWriteType: 'All',
          includeManagementEvents: true,
          dataResources: [
            {
              type: 'AWS::S3::Object',
              values: [secureBucket.arnForObjects(`AWSLogs/${this.account}/*`)],
            },
          ],
        },
      ],
    });
    Tags.of(cloudTrail).add(stackTag.key, stackTag.value);

    // 🛡️ IAM Role for AWS Config (use ReadOnlyAccess + minimal writes)
    const configRole = new iam.Role(this, 'ConfigRecorderRole', {
      assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
    });
    Tags.of(configRole).add(stackTag.key, stackTag.value);

    configRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')
    );
    configRole.addToPolicy(new iam.PolicyStatement({
      actions: ['config:*', 's3:PutObject', 's3:GetBucketAcl', 'sns:Publish', 'logs:*'],
      resources: ['*'],
    }));

    // 📘 CloudWatch Log Group for AWS Config (optional)
    const configLogGroup = new logs.LogGroup(this, 'AwsConfigLogGroup', {
      logGroupName: '/aws/config/secure-aws-env-stack',
      retention: logs.RetentionDays.ONE_YEAR,
    });
    Tags.of(configLogGroup).add(stackTag.key, stackTag.value);

    // === AWS Config: Create & Start via Custom Resources ===
    const recorderName = 'default';

    // 1) PutConfigurationRecorder (create/update the recorder)
    const putRecorder = new AwsCustomResource(this, 'PutConfigRecorder', {
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['iam:PassRole'],
          resources: [configRole.roleArn],
        }),
        new iam.PolicyStatement({
          actions: [
            'config:PutConfigurationRecorder',
            'config:DescribeConfigurationRecorders',
          ],
          resources: ['*'],
        }),
      ]),
      onCreate: {
        service: 'ConfigService',
        action: 'putConfigurationRecorder',
        parameters: {
          ConfigurationRecorder: {
            name: recorderName,
            roleARN: configRole.roleArn,
            recordingGroup: {
              allSupported: true,
              includeGlobalResourceTypes: true,
            },
          },
        },
        physicalResourceId: PhysicalResourceId.of('PutConfigRecorderOnce'),
      },
      onUpdate: {
        service: 'ConfigService',
        action: 'putConfigurationRecorder',
        parameters: {
          ConfigurationRecorder: {
            name: recorderName,
            roleARN: configRole.roleArn,
            recordingGroup: {
              allSupported: true,
              includeGlobalResourceTypes: true,
            },
          },
        },
        physicalResourceId: PhysicalResourceId.of('PutConfigRecorderOnce'),
      },
    });
    putRecorder.node.addDependency(configRole);
    

    // 📣 SNS Topic
    const snsTopic = new sns.Topic(this, 'SecureSnsTopic', {
      displayName: 'Secure AWS Notifications',
    });
    Tags.of(snsTopic).add(stackTag.key, stackTag.value);
    snsTopic.addSubscription(new snsSubscriptions.EmailSubscription(subscriptionEmail));

    // 2) Delivery Channel (must exist before starting the recorder)
    const deliveryChannel = new configservice.CfnDeliveryChannel(this, 'SecureDeliveryChannel', {
      name: 'SecureDeliveryChannel',
      s3BucketName: secureBucket.bucketName,
      s3KeyPrefix: 'config',
      snsTopicArn: snsTopic.topicArn,
    });
    Tags.of(deliveryChannel).add(stackTag.key, stackTag.value);

    // DC after recorder is defined
    deliveryChannel.node.addDependency(putRecorder);

    // 3) StartConfigurationRecorder
    const startRecording = new AwsCustomResource(this, 'StartConfigRecording', {
      policy: AwsCustomResourcePolicy.fromStatements([
        // Start/stop don't strictly need PassRole, but safe to include for retries
        new iam.PolicyStatement({
          actions: ['iam:PassRole'],
          resources: [configRole.roleArn],
        }),
        new iam.PolicyStatement({
          actions: [
            'config:StartConfigurationRecorder',
            'config:StopConfigurationRecorder',
            'config:DescribeConfigurationRecorderStatus',
          ],
          resources: ['*'],
        }),
      ]),
      onCreate: {
        service: 'ConfigService',
        action: 'startConfigurationRecorder',
        parameters: { ConfigurationRecorderName: recorderName },
        physicalResourceId: PhysicalResourceId.of('StartConfigRecordingOnce'),
      },
      onUpdate: {
        service: 'ConfigService',
        action: 'startConfigurationRecorder',
        parameters: { ConfigurationRecorderName: recorderName },
        physicalResourceId: PhysicalResourceId.of('StartConfigRecordingOnce'),
      },
      onDelete: {
        service: 'ConfigService',
        action: 'stopConfigurationRecorder',
        parameters: { ConfigurationRecorderName: recorderName },
      },
    });
    startRecording.node.addDependency(deliveryChannel);
    startRecording.node.addDependency(putRecorder);

    // ✅ Config Rules depend on recorder being started
    const defaultSGRule = new configservice.CfnConfigRule(this, 'DefaultSecurityGroupClosedRule', {
      configRuleName: 'default-security-group-closed',
      source: { owner: 'AWS', sourceIdentifier: 'VPC_DEFAULT_SECURITY_GROUP_CLOSED' },
      scope: { complianceResourceTypes: ['AWS::EC2::SecurityGroup'] },
    });
    defaultSGRule.node.addDependency(startRecording);

    const incomingSSH = new configservice.CfnConfigRule(this, 'IncomingSSHDisabledRule', {
      configRuleName: 'incoming-ssh-disabled',
      source: { owner: 'AWS', sourceIdentifier: 'INCOMING_SSH_DISABLED' },
      scope: { complianceResourceTypes: ['AWS::EC2::SecurityGroup'] },
    });
    incomingSSH.node.addDependency(startRecording);

    const s3PublicRead = new configservice.CfnConfigRule(this, 'S3BucketPublicReadProhibited', {
      configRuleName: 's3-bucket-public-read-prohibited',
      source: { owner: 'AWS', sourceIdentifier: 'S3_BUCKET_PUBLIC_READ_PROHIBITED' },
      scope: { complianceResourceTypes: ['AWS::S3::Bucket'] },
    });
    s3PublicRead.node.addDependency(startRecording);

    const s3SSLOnly = new configservice.CfnConfigRule(this, 'S3BucketSSLRequestsOnly', {
      configRuleName: 's3-bucket-ssl-requests-only',
      source: { owner: 'AWS', sourceIdentifier: 'S3_BUCKET_SSL_REQUESTS_ONLY' },
      scope: { complianceResourceTypes: ['AWS::S3::Bucket'] },
    });
    s3SSLOnly.node.addDependency(startRecording);

    const ctEnabled = new configservice.CfnConfigRule(this, 'CloudTrailEnabled', {
      configRuleName: 'cloudtrail-enabled',
      source: { owner: 'AWS', sourceIdentifier: 'CLOUD_TRAIL_ENABLED' },
    });
    ctEnabled.node.addDependency(startRecording);

    const iamPwd = new configservice.CfnConfigRule(this, 'IAMPasswordPolicy', {
      configRuleName: 'iam-password-policy',
      source: { owner: 'AWS', sourceIdentifier: 'IAM_PASSWORD_POLICY' },
    });
    iamPwd.node.addDependency(startRecording);

    // 🛡️ GuardDuty
    const detector = new guardduty.CfnDetector(this, 'GuardDutyDetector', { enable: true });

    const gdEventRule = new events.Rule(this, 'GuardDutyFindingsRule', {
      eventPattern: { source: ['aws.guardduty'], detailType: ['GuardDuty Finding'] },
    });
    gdEventRule.addTarget(new targets.SnsTopic(snsTopic));

    // Optional S3 Access Logging group
    const s3LogGroup = new logs.LogGroup(this, 'S3LogGroup', {
      logGroupName: '/aws/s3/secure-aws-env-stack',
      retention: logs.RetentionDays.ONE_YEAR,
    });
    Tags.of(s3LogGroup).add(stackTag.key, stackTag.value);

    new cdk.CfnOutput(this, 'ConfigRecorderRoleArn', { value: configRole.roleArn });
  }
}
