#
# File: bzar_smb1_detect.bro
# Created: 20180701
# Updated: 20200217
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

#
# SMB1 Event Handlers
#

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, svc: string) &priority=3
{
	local smb_action = "SMB::TREE_CONNECT to";

	# Check if detect_option is True &&
	# Check if SMB Tree Path is an Admin File Share

	if ( BZAR::t1077_detect_option &&
	     BZAR::smb_admin_file_share_test(c$smb_state) )
	{
		# Looks like:
		# T1077 Windows Admin Share (File Shares Only)

		# Raise Notice and/or Set Observation
		BZAR::smb_t1077_log(c, smb_action);
	}
}


event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=3
{
	# Copied this snippet from Bro default handler:
	# policy/protocols/smb/smb1-main.bro#smb1_write_andx_request.
	# It is important to know the full file path at SMB::FILE_OPEN time,
	# so the smb_files.log is consistent with smb_cmd.log.
	# Let's do this now, during smb1_nt_create_andx_request.

	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path ) 
		c$smb_state$current_file$path = c$smb_state$current_tree$path; 
}


event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=3
{ 
	# Keep track of the number of bytes in the Write Request.
	# priority==3 ... We want to execute before writing to smb_files.log

	c$smb_state$current_file$data_offset_req = offset;
	c$smb_state$current_file$data_len_req    = data_len;
}


event smb1_write_andx_response(c: connection, hdr: SMB1::Header, written_bytes: count) &priority=3
{
	local smb_action = "SMB::FILE_WRITE to";

	# Copied this snippet from Bro default handler:
	# policy/protocols/smb/smb1-main.bro#smb1_write_andx_request.
	# Can't hurt to double-check this.

	# Skip if the request was not seen and we don't know what the current file is
	if ( !c?$smb_state || !c$smb_state?$current_file )
		return;

	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path ) 
		c$smb_state$current_file$path = c$smb_state$current_tree$path; 

	# Keep track of the number of bytes in the Write Response. 
	# priority==3 ... We want to execute before writing to smb_files.log

	c$smb_state$current_file$data_len_rsp = written_bytes;


	# Check if detect_option is True &&
	# Check if SMB Tree Path is an Admin File Share

	if ( BZAR::t1077_t1105_detect_option &&
	     BZAR::smb_admin_file_share_test(c$smb_state) )
	{
		# Looks like:
		# T1105 Remote File Copy &&
		# T1077 Windows Admin Share (File Shares Only)

		# Raise Notice and/or Set Observation
		BZAR::smb_t1077_t1105_log(c, smb_action);
	}
}


event smb1_write_andx_response(c: connection, hdr: SMB1::Header, written_bytes: count) &priority=-5
{
	# Write to smb_files.log
	SMB::write_file_log(c$smb_state);
}

#end bzar_smb1_detect.bro
