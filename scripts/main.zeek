#
# File: main.bro
# Created: 20180701
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

@if ((Version::info$major == 2) && (Version::info$minor <= 5))

# Use this syntax for Bro v2.5.x and below
@load policy/protocols/smb

@else

# Use this syntax for Bro v2.6.x and above
@load base/protocols/smb

@endif

@load base/protocols/dce-rpc
@load base/frameworks/files
@load base/frameworks/notice
@load base/frameworks/sumstats

module BZAR;

export
{
	# NOTICE - Raise Notices for these ATT&CK Tactic Categories

	redef enum Notice::Type +=
	{
		ATTACK::Credential_Access,
		ATTACK::Defense_Evasion,
		ATTACK::Discovery,
		ATTACK::Execution,
		ATTACK::Lateral_Movement,
		ATTACK::Lateral_Movement_and_Execution,
		ATTACK::Lateral_Movement_Extracted_File,
		ATTACK::Lateral_Movement_Multiple_Attempts,
		ATTACK::Persistence,
	};

	# Full descriptive name of each ATT&CK Technique
	# Used in BZAR Reporting

	const attack_info : table[string] of string = 
	{
		["t1003"] = "T1003 Credential Dumping",
		["t1004"] = "T1004 Winlogon Helper DLL",
		["t1013"] = "T1013 Port Monitors",
		["t1016"] = "T1016 System Network Configuration Discovery",
		["t1018"] = "T1018 Remote System Discovery",
		["t1033"] = "T1033 System Owner/User Discovery",
		["t1035"] = "T1035 Service Execution",
		["t1047"] = "T1047 WMI",
		["t1049"] = "T1049 System Network Connections Discovery",
		["t1053"] = "T1053 Scheduled Task",
		["t1069"] = "T1069 Permission Groups Discovery",
		["t1070"] = "T1070 Indicator Removal on Host",
		["t1077"] = "T1077 Windows Admin Shares",
		["t1082"] = "T1082 System Information Discovery",
		["t1083"] = "T1083 File and Directory Discovery",
		["t1087"] = "T1087 Account Discovery",
		["t1105"] = "T1105 Remote File Copy",
		["t1124"] = "T1124 System Time Discovery",
		["t1135"] = "T1135 Network Share Discovery",
	} &redef;

	type EndpointWhitelist : record
	{
		# Specify IP Addresses to ignore
		orig_addrs : set[addr] &optional;
		resp_addrs : set[addr] &optional;

		# Specify IP Subnets to ignore
		orig_subnets : set[subnet] &optional;
		resp_subnets : set[subnet] &optional;

		# Specify Host Names to ignore
		orig_names : set[string] &optional;
		resp_names : set[string] &optional;
	} &redef;
}
#end export


#
# Helper Functions
#

function whitelist_test( orig_h : addr, resp_h : addr, w : BZAR::EndpointWhitelist ) : bool
{
	local match : bool = F;

	#
	# Check if Endpoint IP Addrs are Associated with Whitelist
	#

	if ( w?$orig_addrs && (orig_h in w$orig_addrs) )
	{
		match = T;
	}
	else if ( w?$resp_addrs && (resp_h in w$resp_addrs) )
	{
		match = T;
	}
	else if ( w?$orig_subnets && (orig_h in w$orig_subnets) )
	{
		match = T;
	}
	else if ( w?$resp_subnets && (resp_h in w$resp_subnets) )
	{
		match = T;
	}
	else if ( w?$orig_names )
	{
		when ( (local n1 = lookup_addr(orig_h)) && (n1 in w$orig_names) )
		{
			match = T;
		}
		timeout BZAR::whitelist_dns_timeout
		{
			match = F;
		}
	}
	else if ( w?$resp_names )
	{
		when ( (local n2 = lookup_addr(resp_h)) && (n2 in w$resp_names) )
		{
			match = T;
		}
		timeout BZAR::whitelist_dns_timeout
		{
			match = F;
		}
	}

	return match;
}


function sort_func( a : double, b : double ) : int
{
	if ( a < b)
		return -1;
	else
		return 1;
}


#
# BZAR Initialization
#

@if ( Version::info$major >= 3 )

# Use this syntax for Zeek v3.x.x and above
event zeek_init()
{

@else

# Use this syntax for Bro v2.x.x and below
event bro_init()
{

@endif

	# 1- SumStats Analytics for ATT&CK Lateral Movement and Execution
	#
	# Description:
	#    Use SumStats to raise a Bro/Zeek Notice event if an SMB Lateral Movement 
	#    indicator (e.g., SMB File Write to a Windows Admin File Share: ADMIN$ or 
	#    C$ only) is observed together with a DCE-RPC Execution indicator against 
	#    the same (targeted) host, within a specified period of time.
	#
	# Relevant ATT&CK Technique(s):
	#    T1077 Windows Admin Shares (file shares only, not named pipes) &&
	#    T1105 Remote File Copy && (T1035 Service Execution || T1047 WMI || T1053 Scheduled Task)
	#
	# Relevant Indicator(s) Detected by Bro/Zeek:
	#    (a) smb1_write_andx_response::c$smb_state$path contains ADMIN$ or C$
	#    (b) smb2_write_request::c$smb_state$path contains ADMIN$ or C$ *
	#    (c) dce_rpc_response::c$dce_rpc$endpoint + c$dce_rpc$operation contains 
	#        any of the following: (see BZAR::t1035_rpc_strings, BZAR::t1047_rpc_strings,
	#        and BZAR::t1053_rpc-strings sets).
	# 
	# NOTE: Preference would be to detect 'smb2_write_response' 
	#       event (instead of 'smb2_write_request'), because it 
	#       would confirm the file was actually written to the 
	#       remote destination.  Unfortuantely, Bro/Zeek does 
	#       not have an event for that SMB message-type yet.
	#
	# Globals (defined in main.bro above):
	#    bzar1_epoch
	#    bzar1_limit

	local bzar1 = SumStats::Reducer(
		$stream="attack_lm_ex",
		$apply=set(SumStats::SUM, SumStats::MAX, SumStats::MIN)
	);

	SumStats::create([
		$name = "attack_lm_ex_notice",
		$reducers  = set(bzar1),
		$epoch     = bzar1_epoch,
		$threshold = bzar1_limit,
		$threshold_val (key:SumStats::Key, result:SumStats::Result) =
		{
			return result["attack_lm_ex"]$sum;
		},
		$threshold_crossed(key:SumStats::Key, result:SumStats::Result) = 
		{
			local r = result["attack_lm_ex"];

			# Ensure at least one RPC_EXEC was observed and
			# at least one SMB_WRITE was observed

			if ( r$max == 1000 && r$min == 1 )
			{ 
				local s = fmt("Detected activity against host %s, total score %.0f within timeframe %s", key$host, r$sum, bzar1_epoch);

				# Raise Notice
				NOTICE([$note=ATTACK::Lateral_Movement_and_Execution,
					$msg=s]
				);
			}
		}
	]);


	# 2- SumStats Analytics for ATTACK Lateral Movement (Multiple Attempts)
	#
	# Description:
	#    Use SumStats to raise a Bro/Zeek Notice event if multiple SMB Lateral 
	#    Movement indicators (e.g., multiple attempts to connect to a Windows Admin
	#    File Share: ADMIN$ or C$ only) are observed originating from the same host, 
	#    regardless of write-attempts and regardless of whether or not any connection
	#    is successful --just connection attempts-- within a specified period of time.
	#
	# Relevant ATT&CK Technique(s):
	#    T1077 Windows Admin Shares (file shares only, not named pipes)
	#
	# Relevant Indicator(s) Detected by Bro/Zeek:
	#    (a) smb1_tree_connect_andx_request::c$smb_state$path contains ADMIN$ or C$
	#    (b) smb2_tree_connect_request::c$smb_state$path contains ADMIN$ or C$
	#
	# Globals (defined in main.bro above):
	#    bzar2_epoch
	#    bzar2_limit

	local bzar2 = SumStats::Reducer(
		$stream="attack_lm_multiple_t1077",
		$apply=set(SumStats::SUM)
	);

	SumStats::create([
		$name = "attack_t1077_notice",
		$reducers  = set(bzar2),
		$epoch     = bzar2_epoch,
		$threshold_series = sort(bzar2_limit, sort_func),
		$threshold_val (key:SumStats::Key, result:SumStats::Result) =
		{
			return result["attack_lm_multiple_t1077"]$sum;
		},
		$threshold_crossed(key:SumStats::Key, result:SumStats::Result) = 
		{
			local s = fmt("Detected T1077 Admin File Share activity from host %s, total attempts %.0f within timeframe %s", key$host, result["attack_lm_multiple_t1077"]$sum, bzar2_epoch);

			# Raise Notice
			NOTICE([$note=ATTACK::Lateral_Movement_Multiple_Attempts,
				$msg=s]
			);
		}
	]);


	# 3- SumStats Analytics for ATTACK Discovery
	#
	# Description:
	#    Use SumStats to raise a Bro/Zeek Notice event if multiple instances of 
	#    DCE-RPC Discovery indicators are observed originating from the same host, 
	#    within a specified period of time.
	#
	# Relevant ATT&CK Technique(s):
	#    T1016 System Network Configuration Discovery
	#    T1018 Remote System Discovery 
	#    T1033 System Owner/User Discovery 
	#    T1069 Permission Groups Discovery 
	#    T1082 System Information Discovery
	#    T1083 File & Directory Discovery
	#    T1087 Account Discovery
	#    T1124 System Time Discovery
	#    T1135 Network Share Discovery
	#
	# Relevant Indicator(s) Detected by Bro/Zeek:
	#    (a) dce_rpc_response::c$dce_rpc$endpoint + c$dce_rpc$operation contains 
	#        any of the following: (see BZAR::txxxx_rpc_strings set for each relevant
	#        ATT&CK Technique lsited above).
	# 
	# Globals (defined in main.bro above):
	#    bzar3_epoch
	#    bzar3_limit

	local bzar3 = SumStats::Reducer(
		$stream="attack_discovery",
		$apply=set(SumStats::SUM)
	);

	SumStats::create([
		$name = "attack_discovery_notice",
		$reducers  = set(bzar3),
		$epoch     = bzar3_epoch,
		$threshold_series = sort(bzar3_limit, sort_func),
		$threshold_val (key:SumStats::Key, result:SumStats::Result) =
		{
			return result["attack_discovery"]$sum;
		},
		$threshold_crossed(key:SumStats::Key, result:SumStats::Result) = 
		{
			local s = fmt("Detected activity from host %s, total attempts %.0f within timeframe %s", key$host, result["attack_discovery"]$sum, bzar3_epoch);

			# Raise Notice
			NOTICE([$note=ATTACK::Discovery,
				$msg=s]
			);
		}
	]);
}

#end main.bro
