#
# File: bzar_dce-rpc_report.bro
# Created: 20180701
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

#
# Helper Functions
#

function rpc_t1003_log ( c : connection, rpc : string ) : bool
{
	# T1003 Credential Dumping

	#
	# Raise Notice
	#

	if ( t1003_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1003_whitelist_orig_addrs;
		w1$resp_addrs   = t1003_whitelist_resp_addrs;

		w1$orig_subnets = t1003_whitelist_orig_subnets;
		w1$resp_subnets = t1003_whitelist_resp_subnets;

		w1$orig_names   = t1003_whitelist_orig_names;
		w1$resp_names   = t1003_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Credential_Access,
				$msg=rpc,
				$sub=BZAR::attack_info["t1003"],
				$conn=c]
			);
		}
	}

	return T;
}


function rpc_t1070_log ( c : connection, rpc : string ) : bool
{
	# T1070 Indicator Removal on Host

	#
	# Raise Notice
	#

	if ( t1070_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1070_whitelist_orig_addrs;
		w1$resp_addrs   = t1070_whitelist_resp_addrs;

		w1$orig_subnets = t1070_whitelist_orig_subnets;
		w1$resp_subnets = t1070_whitelist_resp_subnets;

		w1$orig_names   = t1070_whitelist_orig_names;
		w1$resp_names   = t1070_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Defense_Evasion,
				$msg=rpc,
				$sub=BZAR::attack_info["t1070"],
				$conn=c]
			);
		}
	}

	return T;
}


function rpc_t1035_log ( c : connection, rpc : string ) : bool
{
	# T1035 Service Execution

	#
	# Raise Notice
	#

	if ( t1035_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1035_whitelist_orig_addrs;
		w1$resp_addrs   = t1035_whitelist_resp_addrs;

		w1$orig_subnets = t1035_whitelist_orig_subnets;
		w1$resp_subnets = t1035_whitelist_resp_subnets;

		w1$orig_names   = t1035_whitelist_orig_names;
		w1$resp_names   = t1035_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Execution,
				$msg=rpc,
				$sub=BZAR::attack_info["t1035"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_lm_ex_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_lm_ex_whitelist_orig_addrs;
		w2$resp_addrs   = attack_lm_ex_whitelist_resp_addrs;

		w2$orig_subnets = attack_lm_ex_whitelist_orig_subnets;
		w2$resp_subnets = attack_lm_ex_whitelist_resp_subnets;

		w2$orig_names   = attack_lm_ex_whitelist_orig_names;
		w2$resp_names   = attack_lm_ex_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			# Score == 1000 for RPC_EXEC

			SumStats::observe("attack_lm_ex",
				  SumStats::Key($host=c$id$resp_h),
				  SumStats::Observation($num=1000)
			);
		}
	}

	return T;
}


function rpc_t1047_log ( c : connection, rpc : string ) : bool
{
	# T1047 Windows Management Instrumentation (WMI)

	#
	# Raise Notice
	#

	if ( t1047_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1047_whitelist_orig_addrs;
		w1$resp_addrs   = t1047_whitelist_resp_addrs;

		w1$orig_subnets = t1047_whitelist_orig_subnets;
		w1$resp_subnets = t1047_whitelist_resp_subnets;

		w1$orig_names   = t1047_whitelist_orig_names;
		w1$resp_names   = t1047_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Execution,
				$msg=rpc,
				$sub=BZAR::attack_info["t1047"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_lm_ex_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_lm_ex_whitelist_orig_addrs;
		w2$resp_addrs   = attack_lm_ex_whitelist_resp_addrs;

		w2$orig_subnets = attack_lm_ex_whitelist_orig_subnets;
		w2$resp_subnets = attack_lm_ex_whitelist_resp_subnets;

		w2$orig_names   = attack_lm_ex_whitelist_orig_names;
		w2$resp_names   = attack_lm_ex_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			# Score == 1000 for RPC_EXEC

			SumStats::observe("attack_lm_ex",
				  SumStats::Key($host=c$id$resp_h),
				  SumStats::Observation($num=1000)
			);
		}
	}

	return T;
}


function rpc_t1053_log ( c : connection, rpc : string ) : bool
{
	# T1053 Scheduled Task

	#
	# Raise Notice
	#

	if ( t1053_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1053_whitelist_orig_addrs;
		w1$resp_addrs   = t1053_whitelist_resp_addrs;

		w1$orig_subnets = t1053_whitelist_orig_subnets;
		w1$resp_subnets = t1053_whitelist_resp_subnets;

		w1$orig_names   = t1053_whitelist_orig_names;
		w1$resp_names   = t1053_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Execution,
				$msg=rpc,
				$sub=BZAR::attack_info["t1053"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_lm_ex_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_lm_ex_whitelist_orig_addrs;
		w2$resp_addrs   = attack_lm_ex_whitelist_resp_addrs;

		w2$orig_subnets = attack_lm_ex_whitelist_orig_subnets;
		w2$resp_subnets = attack_lm_ex_whitelist_resp_subnets;

		w2$orig_names   = attack_lm_ex_whitelist_orig_names;
		w2$resp_names   = attack_lm_ex_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			# Score == 1000 for RPC_EXEC

			SumStats::observe("attack_lm_ex",
				  SumStats::Key($host=c$id$resp_h),
				  SumStats::Observation($num=1000)
			);
		}
	}

	return T;
}


function rpc_t1004_log ( c : connection, rpc : string ) : bool
{
	# T1004 Winlogon Helper DLL

	#
	# Raise Notice
	#

	if ( t1004_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1004_whitelist_orig_addrs;
		w1$resp_addrs   = t1004_whitelist_resp_addrs;

		w1$orig_subnets = t1004_whitelist_orig_subnets;
		w1$resp_subnets = t1004_whitelist_resp_subnets;

		w1$orig_names   = t1004_whitelist_orig_names;
		w1$resp_names   = t1004_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Persistence,
				$msg=rpc,
				$sub=BZAR::attack_info["t1004"],
				$conn=c]
			);
		}
	}

	return T;
}


function rpc_t1013_log ( c : connection, rpc : string ) : bool
{
	# T1013 Port Monitors

	#
	# Raise Notice
	#

	if ( t1013_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1013_whitelist_orig_addrs;
		w1$resp_addrs   = t1013_whitelist_resp_addrs;

		w1$orig_subnets = t1013_whitelist_orig_subnets;
		w1$resp_subnets = t1013_whitelist_resp_subnets;

		w1$orig_names   = t1013_whitelist_orig_names;
		w1$resp_names   = t1013_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Persistence,
				$msg=rpc,
				$sub=BZAR::attack_info["t1013"],
				$conn=c]
			);
		}
	}

	return T;
}


function rpc_t1016_log ( c : connection, rpc : string ) : bool
{
	# T1016 System Network Configuration Discovery

	#
	# Raise Notice
	#

	if ( t1016_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1016_whitelist_orig_addrs;
		w1$resp_addrs   = t1016_whitelist_resp_addrs;

		w1$orig_subnets = t1016_whitelist_orig_subnets;
		w1$resp_subnets = t1016_whitelist_resp_subnets;

		w1$orig_names   = t1016_whitelist_orig_names;
		w1$resp_names   = t1016_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1016"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1018_log ( c : connection, rpc : string ) : bool
{
	# 

	#
	# Raise Notice
	#

	if ( t1018_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1018_whitelist_orig_addrs;
		w1$resp_addrs   = t1018_whitelist_resp_addrs;

		w1$orig_subnets = t1018_whitelist_orig_subnets;
		w1$resp_subnets = t1018_whitelist_resp_subnets;

		w1$orig_names   = t1018_whitelist_orig_names;
		w1$resp_names   = t1018_whitelist_resp_names;

		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			# Raise Notice
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1018"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1033_log ( c : connection, rpc : string ) : bool
{
	# T1033 System Owner/User Discovery

	#
	# Raise Notice
	#

	if ( t1033_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1033_whitelist_orig_addrs;
		w1$resp_addrs   = t1033_whitelist_resp_addrs;

		w1$orig_subnets = t1033_whitelist_orig_subnets;
		w1$resp_subnets = t1033_whitelist_resp_subnets;

		w1$orig_names   = t1033_whitelist_orig_names;
		w1$resp_names   = t1033_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1033"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1049_log ( c : connection, rpc : string ) : bool
{
	# T1049 System Network Connections Discovery

	#
	# Raise Notice
	#

	if ( t1049_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1049_whitelist_orig_addrs;
		w1$resp_addrs   = t1049_whitelist_resp_addrs;

		w1$orig_subnets = t1049_whitelist_orig_subnets;
		w1$resp_subnets = t1049_whitelist_resp_subnets;

		w1$orig_names   = t1049_whitelist_orig_names;
		w1$resp_names   = t1049_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1049"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1069_log ( c : connection, rpc : string ) : bool
{
	# T1069 Permission Groups Discovery

	#
	# Raise Notice
	#

	if ( t1069_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1069_whitelist_orig_addrs;
		w1$resp_addrs   = t1069_whitelist_resp_addrs;

		w1$orig_subnets = t1069_whitelist_orig_subnets;
		w1$resp_subnets = t1069_whitelist_resp_subnets;

		w1$orig_names   = t1069_whitelist_orig_names;
		w1$resp_names   = t1069_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1069"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1082_log ( c : connection, rpc : string ) : bool
{
	# T1082 System Information Discovery

	#
	# Raise Notice
	#

	if ( t1082_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1082_whitelist_orig_addrs;
		w1$resp_addrs   = t1082_whitelist_resp_addrs;

		w1$orig_subnets = t1082_whitelist_orig_subnets;
		w1$resp_subnets = t1082_whitelist_resp_subnets;

		w1$orig_names   = t1082_whitelist_orig_names;
		w1$resp_names   = t1082_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1082"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1083_log ( c : connection, rpc : string ) : bool
{
	# T1083 File & Directory Discovery

	#
	# Raise Notice
	#

	if ( t1083_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1083_whitelist_orig_addrs;
		w1$resp_addrs   = t1083_whitelist_resp_addrs;

		w1$orig_subnets = t1083_whitelist_orig_subnets;
		w1$resp_subnets = t1083_whitelist_resp_subnets;

		w1$orig_names   = t1083_whitelist_orig_names;
		w1$resp_names   = t1083_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1083"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1087_log ( c : connection, rpc : string ) : bool
{
	# T1087 Account Discovery

	#
	# Raise Notice
	#

	if ( t1087_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1087_whitelist_orig_addrs;
		w1$resp_addrs   = t1087_whitelist_resp_addrs;

		w1$orig_subnets = t1087_whitelist_orig_subnets;
		w1$resp_subnets = t1087_whitelist_resp_subnets;

		w1$orig_names   = t1087_whitelist_orig_names;
		w1$resp_names   = t1087_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1087"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1124_log ( c : connection, rpc : string ) : bool
{
	# T1124 System Time Discovery

	#
	# Raise Notice
	#

	if ( t1124_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1124_whitelist_orig_addrs;
		w1$resp_addrs   = t1124_whitelist_resp_addrs;

		w1$orig_subnets = t1124_whitelist_orig_subnets;
		w1$resp_subnets = t1124_whitelist_resp_subnets;

		w1$orig_names   = t1124_whitelist_orig_names;
		w1$resp_names   = t1124_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1124"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function rpc_t1135_log ( c : connection, rpc : string ) : bool
{
	# T1135 Network Share Discovery

	#
	# Raise Notice
	#

	if ( t1135_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1135_whitelist_orig_addrs;
		w1$resp_addrs   = t1135_whitelist_resp_addrs;

		w1$orig_subnets = t1135_whitelist_orig_subnets;
		w1$resp_subnets = t1135_whitelist_resp_subnets;

		w1$orig_names   = t1135_whitelist_orig_names;
		w1$resp_names   = t1135_whitelist_resp_names;

 		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			NOTICE([$note=ATTACK::Discovery,
				$msg=rpc,
				$sub=BZAR::attack_info["t1135"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( attack_discovery_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = attack_discovery_whitelist_orig_addrs;
		w2$resp_addrs   = attack_discovery_whitelist_resp_addrs;

		w2$orig_subnets = attack_discovery_whitelist_orig_subnets;
		w2$resp_subnets = attack_discovery_whitelist_resp_subnets;

		w2$orig_names   = attack_discovery_whitelist_orig_names;
		w2$resp_names   = attack_discovery_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_discovery",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}

#end bzar_dce-rpc_report.bro
