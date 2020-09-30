#
# File: bzar_config_options.bro
# Created: 20191121
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

export
{
	# BZAR Configuration Options

	#
	# BZAR Actions - ATT&CK Indicators to Detect and Report
	#
	# Description:
	#	These config options should be tuned for your specific environment.
	#	Use the Zeek Configuration Framework to change the default values 
	#	during runtime.
	#
	# xxx_detect_option:
	#	Option to control whether or not to detect this ATT&CK indicator.
	#	If set to False, then it effectively disables _report_option, too.
	#
	# xxx_report_option:
	#	Option to control whether or not to write to the Notice Log.
	#	If _detect_option is False, then this option has no effect.
	#

	# ATTACK::Credential_Access
	option t1003_detect_option = T;
	option t1003_report_option = T;

	# ATTACK::Defense_Evasion
	option t1070_detect_option = T;
	option t1070_report_option = T;

	# ATTACK::Execution
	option t1035_detect_option = T;
	option t1035_report_option = T;

	option t1047_detect_option = T;
	option t1047_report_option = T;

	option t1053_detect_option = T;
	option t1053_report_option = T;

	# ATTACK::Lateral_Movement
	# Options to control whether or not to detect/report
	# 'Remote File Copy to Windows Admin File Share'.

	option t1077_t1105_detect_option = T;
	option t1077_t1105_report_option = T;

	# Options to control whether or not to detect/report
	# 'Windows Admin File Share' by itself.
	# Recommendation: Do not report this ATT&CK indicator without
	# additional context.

	option t1077_detect_option = T;
	option t1077_report_option = F;

	# Option to control whether or not to detect/report
	# 'Remote File Copy' to any other network share, not related to T1077.
	# Recommendation: Do not report this ATT&CK indicator without
	# additional context.

	option t1105_detect_option = T;
	option t1105_report_option = F;

	# ATTACK::Lateral_Movement_Multiple_Attempts
	# Aggregate SumStats Indicator
	# Option to control whether or not to write this SumStats indicator to Notice Log.
	# It relies on t1077_detect_option.  If t1077_detect_option is False, this option has no effect.

	option t1077_multiple_attempts_report_option = T;

	# ATTACK::Lateral_Movement_and_Execution
	# Aggregate SumStats Indicator
	# Option to control whether or not to write this SumStats indicator to the Notice Log.

	option attack_lm_ex_report_option = T;

	# ATTACK::Lateral_Movement_Extracted_File
	# Options to control whether or not to extract files associated with Lateral Movement
	# and whether or not to write to Notice Log. If _extract is False, _report has no effect.
	option attack_lm_file_extract_option = T;		
	option attack_lm_extracted_file_report_option = T;	

	# ATTACK::Persistence
	option t1004_detect_option = T;
	option t1004_report_option = T;

	option t1013_detect_option = T;
	option t1013_report_option = T;

	# ATTACK::Discovery
	option t1016_detect_option = T;
	option t1018_detect_option = T;
	option t1033_detect_option = T;
	option t1049_detect_option = T;
	option t1069_detect_option = T;
	option t1082_detect_option = T;
	option t1083_detect_option = T;
	option t1087_detect_option = T;
	option t1124_detect_option = T;
	option t1135_detect_option = T;

	# Recommendation: Do not report these Discovery indicators individually.
	option t1016_report_option = F;
	option t1018_report_option = F;
	option t1033_report_option = F;
	option t1049_report_option = F;
	option t1069_report_option = F;
	option t1082_report_option = F;
	option t1083_report_option = F;
	option t1087_report_option = F;
	option t1124_report_option = F;
	option t1135_report_option = F;

	# Aggregate SumStats Reporting of Discovery Indicators
	# Dependent on individual Discovery indicators above.

	option attack_discovery_report_option = T; 


	#
	# BZAR Whitelist - Ignore ATT&CK Indicators Involving these Endpoints
	#
	# Description:
	#	Whitelists can be specified by IP address, IP subnet, or host
	#	name for each ATT&CK indicator.  Furthermore, the whitelists can
	#	be specified by originating address, subnet, or hostname; and by
	#	responding address, subnet, or hostname.
	#
	# xxxx_whitelist_orig_addrs : set[addr]
	#	Add originating IP addresses to ignore for an ATT&CK indicator.
	#	The value of 'c$id$orig_h' is checked against this list before 
	#	writing to Notice Log and/or SumStats Observation.
	#
	# xxxx_whitelist_resp_addrs : set[addr]
	#	Add responding IP addresses to ignore for an ATT&CK indicator.
	#	The value of 'c$id$resp_h' is checked against this list before 
	#	writing to Notice Log and/or SumStats Observation.
	#
	# xxxx_whitelist_orig_subnets : set[subnet]
	#	Add originating IP subnets to ignore for an ATT&CK indicator.
	#	The value of 'c$id$orig_h' is checked against this list before 
	#	writing to Notice Log and/or SumStats Observation.
	#
	# xxxx_whitelist_resp_subnets : set[subnet]
	#	Add responding IP subnets to ignore for an ATT&CK indicator.
	#	The value of 'c$id$resp_h' is checked against this list before 
	#	writing to Notice Log and/or SumStats Observation.
	#
	# xxxx_whitelist_orig_names : set[string]
	#	Add originating IP addresses to ignore for an ATT&CK indicator.
	#	CAUTION: A DNS reverse-lookup of the value of 'c$id$orig_h' is
	#	performed and the result is checked against this list before
	#	writing to Notice Log and/or SumStats Observation.  The DNS
	#	reverse-lookup could adversely affect system performance.
	#
	# xxxx_whitelist_resp_names : set[string]
	#	Add responding IP addresses to ignore for an ATT&CK indicator.
	#	CAUTION: A DNS reverse-lookup of the value of 'c$id$resp_h' is
	#	performed and the result is checked against this list before
	#	writing to Notice Log and/or SumStats Observation.  The DNS
	#	reverse-lookup could adversely affect system performance.
	#

	option whitelist_dns_timeout = 1sec;

	# ATTACK::Credential_Access

	# ATTACK::Credential_Access
	option t1003_whitelist_orig_addrs   : set[addr] = {};
	option t1003_whitelist_resp_addrs   : set[addr] = {};
	option t1003_whitelist_orig_subnets : set[subnet] = {};
	option t1003_whitelist_resp_subnets : set[subnet] = {};
	option t1003_whitelist_orig_names   : set[string] = {};
	option t1003_whitelist_resp_names   : set[string] = {};

	# ATTACK::Defense_Evasion
	option t1070_whitelist_orig_addrs   : set[addr] = {};
	option t1070_whitelist_resp_addrs   : set[addr] = {};
	option t1070_whitelist_orig_subnets : set[subnet] = {};
	option t1070_whitelist_resp_subnets : set[subnet] = {};
	option t1070_whitelist_orig_names   : set[string] = {};
	option t1070_whitelist_resp_names   : set[string] = {};

	# ATTACK::Execution
	option t1035_whitelist_orig_addrs   : set[addr] = {};
	option t1035_whitelist_resp_addrs   : set[addr] = {};
	option t1035_whitelist_orig_subnets : set[subnet] = {};
	option t1035_whitelist_resp_subnets : set[subnet] = {};
	option t1035_whitelist_orig_names   : set[string] = {};
	option t1035_whitelist_resp_names   : set[string] = {};

	option t1047_whitelist_orig_addrs   : set[addr] = {};
	option t1047_whitelist_resp_addrs   : set[addr] = {};
	option t1047_whitelist_orig_subnets : set[subnet] = {};
	option t1047_whitelist_resp_subnets : set[subnet] = {};
	option t1047_whitelist_orig_names   : set[string] = {};
	option t1047_whitelist_resp_names   : set[string] = {};

	option t1053_whitelist_orig_addrs   : set[addr] = {};
	option t1053_whitelist_resp_addrs   : set[addr] = {};
	option t1053_whitelist_orig_subnets : set[subnet] = {};
	option t1053_whitelist_resp_subnets : set[subnet] = {};
	option t1053_whitelist_orig_names   : set[string] = {};
	option t1053_whitelist_resp_names   : set[string] = {};

	# ATTACK::Lateral_Movement
	option t1077_t1105_whitelist_orig_addrs   : set[addr] = {};
	option t1077_t1105_whitelist_resp_addrs   : set[addr] = {};
	option t1077_t1105_whitelist_orig_subnets : set[subnet] = {};
	option t1077_t1105_whitelist_resp_subnets : set[subnet] = {};
	option t1077_t1105_whitelist_orig_names   : set[string] = {};
	option t1077_t1105_whitelist_resp_names   : set[string] = {};

	option t1077_whitelist_orig_addrs   : set[addr] = {};
	option t1077_whitelist_resp_addrs   : set[addr] = {};
	option t1077_whitelist_orig_subnets : set[subnet] = {};
	option t1077_whitelist_resp_subnets : set[subnet] = {};
	option t1077_whitelist_orig_names   : set[string] = {};
	option t1077_whitelist_resp_names   : set[string] = {};

	option t1105_whitelist_orig_addrs   : set[addr] = {};
	option t1105_whitelist_resp_addrs   : set[addr] = {};
	option t1105_whitelist_orig_subnets : set[subnet] = {};
	option t1105_whitelist_resp_subnets : set[subnet] = {};
	option t1105_whitelist_orig_names   : set[string] = {};
	option t1105_whitelist_resp_names   : set[string] = {};

	# ATTACK::Lateral_Movement_Multiple_Attempts
	option t1077_multiple_attempts_whitelist_orig_addrs   : set[addr] = {};
	option t1077_multiple_attempts_whitelist_resp_addrs   : set[addr] = {};
	option t1077_multiple_attempts_whitelist_orig_subnets : set[subnet] = {};
	option t1077_multiple_attempts_whitelist_resp_subnets : set[subnet] = {};
	option t1077_multiple_attempts_whitelist_orig_names   : set[string] = {};
	option t1077_multiple_attempts_whitelist_resp_names   : set[string] = {};

	# ATTACK::Lateral_Movement_and_Execution
	option attack_lm_ex_whitelist_orig_addrs   : set[addr] = {};
	option attack_lm_ex_whitelist_resp_addrs   : set[addr] = {};
	option attack_lm_ex_whitelist_orig_subnets : set[subnet] = {};
	option attack_lm_ex_whitelist_resp_subnets : set[subnet] = {};
	option attack_lm_ex_whitelist_orig_names   : set[string] = {};
	option attack_lm_ex_whitelist_resp_names   : set[string] = {};

	# ATTACK::Lateral_Movement_Extracted_File
	option attack_lm_extracted_file_whitelist_orig_addrs   : set[addr] = {};
	option attack_lm_extracted_file_whitelist_resp_addrs   : set[addr] = {};
	option attack_lm_extracted_file_whitelist_orig_subnets : set[subnet] = {};
	option attack_lm_extracted_file_whitelist_resp_subnets : set[subnet] = {};
	option attack_lm_extracted_file_whitelist_orig_names   : set[string] = {};
	option attack_lm_extracted_file_whitelist_resp_names   : set[string] = {};

	# ATTACK::Persistence
	option t1004_whitelist_orig_addrs   : set[addr] = {};
	option t1004_whitelist_resp_addrs   : set[addr] = {};
	option t1004_whitelist_orig_subnets : set[subnet] = {};
	option t1004_whitelist_resp_subnets : set[subnet] = {};
	option t1004_whitelist_orig_names   : set[string] = {};
	option t1004_whitelist_resp_names   : set[string] = {};

	option t1013_whitelist_orig_addrs   : set[addr] = {};
	option t1013_whitelist_resp_addrs   : set[addr] = {};
	option t1013_whitelist_orig_subnets : set[subnet] = {};
	option t1013_whitelist_resp_subnets : set[subnet] = {};
	option t1013_whitelist_orig_names   : set[string] = {};
	option t1013_whitelist_resp_names   : set[string] = {};

	# ATTACK::Discovery
	option attack_discovery_whitelist_orig_addrs   : set[addr] = {};
	option attack_discovery_whitelist_resp_addrs   : set[addr] = {};
	option attack_discovery_whitelist_orig_subnets : set[subnet] = {};
	option attack_discovery_whitelist_resp_subnets : set[subnet] = {};
	option attack_discovery_whitelist_orig_names   : set[string] = {};
	option attack_discovery_whitelist_resp_names   : set[string] = {};

	# If needed, use whitelists for the individual Discovery indicators
	option t1016_whitelist_orig_addrs   : set[addr] = {};
	option t1016_whitelist_resp_addrs   : set[addr] = {};
	option t1016_whitelist_orig_subnets : set[subnet] = {};
	option t1016_whitelist_resp_subnets : set[subnet] = {};
	option t1016_whitelist_orig_names   : set[string] = {};
	option t1016_whitelist_resp_names   : set[string] = {};

	option t1018_whitelist_orig_addrs   : set[addr] = {};
	option t1018_whitelist_resp_addrs   : set[addr] = {};
	option t1018_whitelist_orig_subnets : set[subnet] = {};
	option t1018_whitelist_resp_subnets : set[subnet] = {};
	option t1018_whitelist_orig_names   : set[string] = {};
	option t1018_whitelist_resp_names   : set[string] = {};

	option t1033_whitelist_orig_addrs   : set[addr] = {};
	option t1033_whitelist_resp_addrs   : set[addr] = {};
	option t1033_whitelist_orig_subnets : set[subnet] = {};
	option t1033_whitelist_resp_subnets : set[subnet] = {};
	option t1033_whitelist_orig_names   : set[string] = {};
	option t1033_whitelist_resp_names   : set[string] = {};

	option t1049_whitelist_orig_addrs   : set[addr] = {};
	option t1049_whitelist_resp_addrs   : set[addr] = {};
	option t1049_whitelist_orig_subnets : set[subnet] = {};
	option t1049_whitelist_resp_subnets : set[subnet] = {};
	option t1049_whitelist_orig_names   : set[string] = {};
	option t1049_whitelist_resp_names   : set[string] = {};

	option t1069_whitelist_orig_addrs   : set[addr] = {};
	option t1069_whitelist_resp_addrs   : set[addr] = {};
	option t1069_whitelist_orig_subnets : set[subnet] = {};
	option t1069_whitelist_resp_subnets : set[subnet] = {};
	option t1069_whitelist_orig_names   : set[string] = {};
	option t1069_whitelist_resp_names   : set[string] = {};

	option t1082_whitelist_orig_addrs   : set[addr] = {};
	option t1082_whitelist_resp_addrs   : set[addr] = {};
	option t1082_whitelist_orig_subnets : set[subnet] = {};
	option t1082_whitelist_resp_subnets : set[subnet] = {};
	option t1082_whitelist_orig_names   : set[string] = {};
	option t1082_whitelist_resp_names   : set[string] = {};

	option t1083_whitelist_orig_addrs   : set[addr] = {};
	option t1083_whitelist_resp_addrs   : set[addr] = {};
	option t1083_whitelist_orig_subnets : set[subnet] = {};
	option t1083_whitelist_resp_subnets : set[subnet] = {};
	option t1083_whitelist_orig_names   : set[string] = {};
	option t1083_whitelist_resp_names   : set[string] = {};

	option t1087_whitelist_orig_addrs   : set[addr] = {};
	option t1087_whitelist_resp_addrs   : set[addr] = {};
	option t1087_whitelist_orig_subnets : set[subnet] = {};
	option t1087_whitelist_resp_subnets : set[subnet] = {};
	option t1087_whitelist_orig_names   : set[string] = {};
	option t1087_whitelist_resp_names   : set[string] = {};

	option t1124_whitelist_orig_addrs   : set[addr] = {};
	option t1124_whitelist_resp_addrs   : set[addr] = {};
	option t1124_whitelist_orig_subnets : set[subnet] = {};
	option t1124_whitelist_resp_subnets : set[subnet] = {};
	option t1124_whitelist_orig_names   : set[string] = {};
	option t1124_whitelist_resp_names   : set[string] = {};

	option t1135_whitelist_orig_addrs   : set[addr] = {};
	option t1135_whitelist_resp_addrs   : set[addr] = {};
	option t1135_whitelist_orig_subnets : set[subnet] = {};
	option t1135_whitelist_resp_subnets : set[subnet] = {};
	option t1135_whitelist_orig_names   : set[string] = {};
	option t1135_whitelist_resp_names   : set[string] = {};


	#
	# BZAR Analytics - Use SumStats to Correlate ATT&CK Indicators
	#

	# 1- SumStats Analytics for ATTACK::Lateral_Movement_and_Execution

	option bzar1_epoch = 10min;
	option bzar1_limit = 1001.0; # SMB_WRITE == 1; RPC_EXEC == 1000;

	# 2- SumStats Analytics for ATTACK::Lateral_Movement_Multiple_Attempts
	#    Use threshold vector for greater fidelity and to assist in tuning
	#    the threshold for each unique environment.

	option bzar2_epoch = 5min;
	option bzar2_limit = vector(5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 100.0);

	# 3- SumStats Analytics for ATTACK::Discovery
	#    Use threshold vector for greater fidelity and to assist in tuning
	#    the threshold for each unique environment.

	option bzar3_epoch = 5min;
	option bzar3_limit = vector(5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 100.0);
}
#end export

#end bzar_config_options.bro
