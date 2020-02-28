#
# File: bzar_files.bro
# Created: 20180701
# Updated: 20200228
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

function file_extract_whitelist_test ( c : connection ) : bool
{
	# Get whitelist from config options
	local w1 : BZAR::EndpointWhitelist;

	w1$orig_addrs   = attack_lm_extracted_file_whitelist_orig_addrs;
	w1$resp_addrs   = attack_lm_extracted_file_whitelist_resp_addrs;

	w1$orig_subnets = attack_lm_extracted_file_whitelist_orig_subnets;
	w1$resp_subnets = attack_lm_extracted_file_whitelist_resp_subnets;

	w1$orig_names   = attack_lm_extracted_file_whitelist_orig_names;
	w1$resp_names   = attack_lm_extracted_file_whitelist_resp_names;

	# Check whitelist
	return BZAR::whitelist_test(c$id$orig_h, c$id$resp_h, w1);
}


event file_over_new_connection(f:fa_file, c:connection, is_orig:bool)
{
	# Check Option
	if ( !attack_lm_file_extract_option ) { return; }

	# Check if SMB Tree Path is an Admin File Share
	if ( f?$source && f$source == "SMB" && c?$smb_state &&
	     BZAR::smb_admin_file_share_test(c$smb_state)
	   )
	{
		# Check if SMB Write to an Admin File Share
		if ( c$smb_state?$current_file &&
		     c$smb_state$current_file?$action &&
		     c$smb_state$current_file$action == SMB::FILE_WRITE )
		{
	 		# Check whitelist
			if ( !BZAR::file_extract_whitelist_test(c) )
			{
				local smb_name = BZAR::smb_full_path_and_file_name(c$smb_state);
				local fname = fmt("%s_%s%s", c$uid, f$id, subst_string(smb_name, "\\", "_"));

				Files::add_analyzer(f, Files::ANALYZER_EXTRACT, Files::AnalyzerArgs($extract_filename=fname));
				Files::add_analyzer(f, Files::ANALYZER_MD5);
				Files::add_analyzer(f, Files::ANALYZER_SHA1);
				Files::add_analyzer(f, Files::ANALYZER_SHA256);
			}
		}
	}
}


event file_state_remove(f:fa_file)
{
	# Check Options
	if ( !attack_lm_file_extract_option ) { return; }
	else if ( !attack_lm_extracted_file_report_option ) { return; }

	local fname = "";

	if ( f?$source && f$source == "SMB" && f?$conns && f$info?$extracted )
	{
		fname = f$info$extracted;

		for ( x in f$conns )
		{
			local c = f$conns[x];

			# Check if SMB Tree Path is an Admin File Share
			if ( c?$smb_state && BZAR::smb_admin_file_share_test(c$smb_state) )
			{
		 		# Check whitelist
				if ( !BZAR::file_extract_whitelist_test(c) )
				{
					# Raise Notice
					NOTICE([$note=ATTACK::Lateral_Movement_Extracted_File,
						$msg="Saved a copy of the file written to SMB admin file share",
						$sub=fname,
						$f=f,
						$conn=c]
					);
				}
			}
		}
	}
}

#end bzar_files.bro
