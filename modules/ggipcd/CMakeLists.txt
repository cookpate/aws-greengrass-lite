# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ggl_init_module(
  ggipcd
  LIBS ggl-sdk
       ggl-constants
       core-bus
       core-bus-gg-config
       core-bus-aws-iot-mqtt
       ggipc-auth
       ggl-rand)
