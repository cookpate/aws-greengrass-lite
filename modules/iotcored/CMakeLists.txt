# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ggl_init_module(
  iotcored
  LIBS ggl-sdk
       ggl-common
       core-bus
       core-bus-gg-config
       core_mqtt
       ggl-backoff
       ggl-uri
       PkgConfig::openssl)
