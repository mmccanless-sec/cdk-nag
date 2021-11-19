/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnFunction } from '@aws-cdk/aws-lambda';
import { CfnResource, Stack } from '@aws-cdk/core';

/**
 * Lambda functions are configured with a dead-letter configuration
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): boolean => {
    if (node instanceof CfnFunction) {
      const deadLetterConfig = Stack.of(node).resolve(node.deadLetterConfig);
      if (
        deadLetterConfig == undefined ||
        deadLetterConfig.targetArn == undefined
      ) {
        return false;
      }
    }
    return true;
  },
  'name',
  { value: parse(__filename).name }
);