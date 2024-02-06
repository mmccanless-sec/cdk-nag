import { CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import { NagPack, NagPackProps } from '../nag-pack';
import { NagMessageLevel } from '../nag-rules';
import { EC2InstanceNoPublicIp, EC2RestrictedInbound } from '../rules/ec2';
// import {
//     S3BucketLevelPublicAccessProhibited,
//     S3DefaultEncryptionKMS,
//   } from '../rules/s3';
// import {
//     VPCFlowLogsEnabled,
//   } from '../rules/vpc';

export class MattChecks extends NagPack {
  constructor(props?: NagPackProps) {
    super(props);
    this.packName = 'MattChecks';
  }
  public visit(node: IConstruct): void {
    if (node instanceof CfnResource) {
      this.checkCompute(node);
      // this.checkStorage(node);
      // this.checkVPC(node);
    }
  }

  /**
   * Check Compute Services
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkCompute(node: CfnResource): void {
    this.applyRule({
      ruleSuffixOverride: 'EC2NoPub',
      info: 'The EC2 instance is associated with a public IP address - (Control IDs: 164.308(a)(3)(i), 164.308(a)(4)(ii)(A), 164.308(a)(4)(ii)(C), 164.312(a)(1), 164.312(e)(1)).',
      explanation:
        'Amazon EC2 instances can contain sensitive information and access control is required for such resources.',
      level: NagMessageLevel.ERROR,
      rule: EC2InstanceNoPublicIp,
      node: node,
    });
    this.applyRule({
      ruleSuffixOverride: 'EC2Inbound',
      info: 'The Security Group allows for 0.0.0.0/0 or ::/0 inbound access.',
      explanation:
        'Large port ranges, when open, expose instances to unwanted attacks. More than that, they make traceability of vulnerabilities very difficult. For instance, your web servers may only require 80 and 443 ports to be open, but not all. One of the most common mistakes observed is when  all ports for 0.0.0.0/0 range are open in a rush to access the instance. EC2 instances must expose only to those ports enabled on the corresponding security group level.',
      level: NagMessageLevel.WARN,
      rule: EC2RestrictedInbound,
      node: node,
    });
  }

  // /**
  //  * Check Storage Services
  //  * @param node the CfnResource to check
  //  * @param ignores list of ignores for the resource
  //  */
  // private checkStorage(node: CfnResource): void {
  //   this.applyRule({
  //     ruleSuffixOverride: 'S2',
  //     info: 'The S3 Bucket does not have public access restricted and blocked.',
  //     explanation:
  //       'The bucket should have public access restricted and blocked to prevent unauthorized access.',
  //     level: NagMessageLevel.ERROR,
  //     rule: S3BucketLevelPublicAccessProhibited,
  //     node: node,
  //   });
  // }

  // /**
  //  * Check VPC Resources
  //  * @param node the CfnResource to check
  //  * @param ignores list of ignores for the resource
  //  */
  // private checkVPC(node: CfnResource): void {
  //   this.applyRule({
  //     info: "The VPC's default security group allows inbound or outbound traffic - (Control ID: 164.312(e)(1)).",
  //     explanation:
  //       'When creating a VPC through CloudFormation, the default security group will always be open. Therefore it is important to always close the default security group after stack creation whenever a VPC is created. Restricting all the traffic on the default security group helps in restricting remote access to your AWS resources.',
  //     level: NagMessageLevel.WARN,
  //     rule: VPCDefaultSecurityGroupClosed,
  //     node: node,
  //   });
  // }
}
