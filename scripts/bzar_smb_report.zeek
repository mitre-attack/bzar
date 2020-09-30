#
# File: bzar_smb_report.bro
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

function smb_full_path_and_file_name ( s : SMB::State ) : string
{
	local tree_name = "";
	local file_name = "";

	if ( s$current_file?$path )
		tree_name = s$current_file$path;

	if ( s$current_file?$name )
		file_name = s$current_file$name;

	return fmt("%s%s", tree_name, file_name);
}


function smb_tree_name ( s : SMB::State ) : string
{
	local tree_name : string;

	if ( s?$current_file && s$current_file?$path )
	{
		tree_name = s$current_file$path;
	}
	else if ( s$current_cmd?$referenced_file && s$current_cmd$referenced_file?$path )
	{
		tree_name = s$current_cmd$referenced_file$path;
	}
	else if ( s?$current_tree && s$current_tree?$path )
	{
		tree_name = s$current_tree$path;
	}
	else if ( s$current_cmd?$referenced_tree && s$current_cmd$referenced_tree?$path )
	{
		tree_name = s$current_cmd$referenced_tree$path;
	}
	else {
		tree_name = "";
	}	

	return tree_name;
}


function smb_admin_file_share_test ( s : SMB::State ) : bool
{
	local tree_name : string;

	if ( s?$current_file && s$current_file?$path )
	{
		tree_name = s$current_file$path;
	}
	else if ( s$current_cmd?$referenced_file && s$current_cmd$referenced_file?$path )
	{
		tree_name = s$current_cmd$referenced_file$path;
	}
	else if ( s?$current_tree && s$current_tree?$path )
	{
		tree_name = s$current_tree$path;
	}
	else if ( s$current_cmd?$referenced_tree && s$current_cmd$referenced_tree?$path )
	{
		tree_name = s$current_cmd$referenced_tree$path;
	}
	else {
		tree_name = "";
	}	

	local a = 0;
	local b = |BZAR::smb_admin_file_shares|;

	while ( a < b )
	{
		if ( BZAR::smb_admin_file_shares[a] in tree_name ) { return T; }
		++a;
	}

	return F;
}


function smb_t1077_log ( c : connection, action : string ) : bool
{
	# T1077 Windows Admin Share (ADMIN$ or C$ only)
	#
	# Indicators
	# 01:	SMB1-Tree-Connect-Request to ADMIN$ or C$
	#	SMB2-Tree-Connect-Request to ADMIN$ or C$
	#
	# Analytics
	# 01:	Detect single instance of SMB-Write to ADMIN$ or C$
	#
	# Reporting
	# 01:	Write to notice.log:
	#	"ATTACK::Lateral_Movement"<tab>
	#	"Detected SMB::TREE_CONNECT to admin file share '<smb_tree_name>'"<tab>
	#	"T1077 Windows Admin Share + T1105 Remote File Copy"
	#
	# 02:	Set Observation for SumStats

	#
	# Raise Notice
	#

	if ( t1077_report_option ) 
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1077_whitelist_orig_addrs;
		w1$resp_addrs   = t1077_whitelist_resp_addrs;

		w1$orig_subnets = t1077_whitelist_orig_subnets;
		w1$resp_subnets = t1077_whitelist_resp_subnets;

		w1$orig_names   = t1077_whitelist_orig_names;
		w1$resp_names   = t1077_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			local notice_msg = "Detected %s admin file share \'%s\'";
			local tree_name  = BZAR::smb_tree_name(c$smb_state);

			NOTICE([$note=ATTACK::Lateral_Movement,
				$msg=fmt(notice_msg, action, tree_name),
				$sub=BZAR::attack_info["t1077"],
				$conn=c]
			);
		}
	}

	#
	# Set Observation
	#

	if ( t1077_multiple_attempts_report_option )
	{
		# Get whitelist from config options
		local w2 : BZAR::EndpointWhitelist;

		w2$orig_addrs   = t1077_multiple_attempts_whitelist_orig_addrs;
		w2$resp_addrs   = t1077_multiple_attempts_whitelist_resp_addrs;

		w2$orig_subnets = t1077_multiple_attempts_whitelist_orig_subnets;
		w2$resp_subnets = t1077_multiple_attempts_whitelist_resp_subnets;

		w2$orig_names   = t1077_multiple_attempts_whitelist_orig_names;
		w2$resp_names   = t1077_multiple_attempts_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w2) )
		{
			SumStats::observe("attack_lm_multiple_t1077",
				  SumStats::Key($host=c$id$orig_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}


function smb_t1077_t1105_log ( c : connection, action : string ) : bool
{
	# T1077 Windows Admin Share (ADMIN$ or C$ only)
	#
	# Indicators
	# 01:	SMB1-Tree-Connect-Request to ADMIN$ or C$
	#	SMB2-Tree-Connect-Request to ADMIN$ or C$
	#
	# 02:	SMB1-Write-Response
	#	SMB2-Write-Request*
	#
	#	* NOTE: Bro/Zeek event for SMB2-Write-Response was introduced
	#	  in Zeek v3.0.0.  Therefore, for Bro v2.6 (and earlier), need
	#	  to use SMB2-Write-Request event instead.
	#
	# Analytics
	# 01:	Detect single instance of SMB-Write to ADMIN$ or C$
	#
	# Reporting
	# 01:	Write to notice.log:
	#	"ATTACK::Lateral_Movement"<tab>
	#	"Detected SMB::FILE_WRITE to admin file share '<smb_file_name>'"<tab>
	#	"T1077 Windows Admin Share + T1105 Remote File Copy"
	#
	# 02:	Set Observation for SumStats

	#
	# Raise Notice
	#

	if ( t1077_t1105_report_option )
	{
		# Get whitelist from config options
		local w1 : BZAR::EndpointWhitelist;

		w1$orig_addrs   = t1077_t1105_whitelist_orig_addrs;
		w1$resp_addrs   = t1077_t1105_whitelist_resp_addrs;

		w1$orig_subnets = t1077_t1105_whitelist_orig_subnets;
		w1$resp_subnets = t1077_t1105_whitelist_resp_subnets;

		w1$orig_names   = t1077_t1105_whitelist_orig_names;
		w1$resp_names   = t1077_t1105_whitelist_resp_names;

		# Check whitelist
		if ( !BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1) )
		{
			local t1 = BZAR::attack_info["t1077"];
			local t2 = BZAR::attack_info["t1105"];

			local notice_msg = "Detected %s admin file share \'%s\'";
			local file_name  = BZAR::smb_full_path_and_file_name(c$smb_state);

			NOTICE([$note=ATTACK::Lateral_Movement,
				$msg=fmt(notice_msg, action, file_name),
				$sub=fmt("%s + %s", t1, t2),
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
			# Score == 1 for SMB::FILE_WRITE

			SumStats::observe("attack_lm_ex",
				  SumStats::Key($host=c$id$resp_h),
				  SumStats::Observation($num=1)
			);
		}
	}

	return T;
}

#end bzar_smb_report.bro
