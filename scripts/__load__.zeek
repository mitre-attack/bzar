#
# File: __load__.bro
# Created: 20180701
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

@load ./bzar_config_options

@load ./main
@load ./bzar_dce-rpc_consts
@load ./bzar_dce-rpc_report
@load ./bzar_dce-rpc_detect
@load ./bzar_smb_consts
@load ./bzar_smb_report
@load ./bzar_smb1_detect
@load ./bzar_smb2_detect
@load ./bzar_files

@load-sigs ./dpd.sig

#end __load__.bro
