#
# File: bzar_smb2_detect.bro
# Created: 20180701
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

#
# SMB2 Event Handlers
#

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=3
{
	# Copied this snippet from Bro default handler:
	# policy/protocols/smb/smb1-main.bro#smb1_message.
	# The smb_cmd.log was inconsistent with the .$tree field
	# for SMB1 (populated) and SMB2 (was not populated).

	if ( c$smb_state$current_tree?$path )
	     c$smb_state$current_cmd$tree = c$smb_state$current_tree$path; 
}


event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=3
{
	local smb_action = "SMB::TREE_CONNECT to";

	# Copied this snippet from Bro default handler:
	# policy/protocols/smb/smb1-main.bro#smb1_tree_connect_andx_request.
	# The smb_cmd.log was inconsistent with certain fields
	# for SMB1 (populated) and SMB2 (was not populated).

	local tmp_tree = SMB::TreeInfo($ts=network_time(), $uid=c$uid, $id=c$id, $path=path); 

	c$smb_state$current_cmd$referenced_tree = tmp_tree; 
	c$smb_state$current_cmd$argument = path;


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


@if ((Version::info$major == 2) && (Version::info$minor <= 5))

# Use this syntax for Bro v2.5.x and below
event smb2_create_request(c: connection, hdr: SMB2::Header, name: string) &priority=3
{

@else

# Use this syntax for Bro v2.6.x and above
event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest) &priority=3
{

@endif
	# Copied this snippet from Bro default handler:
	# policy/protocols/smb/smb1-main.bro#smb1_write_andx_request.
	# It is important to know the full file path at SMB::FILE_OPEN time,
	# so the smb_files.log is consistent with smb_cmd.log.
	# Let's do this now, during smb2_create_request.

	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path ) 
	     c$smb_state$current_file$path = c$smb_state$current_tree$path; 
}


event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, data_len: count) &priority=3 
{ 
	# Keep track of the number of bytes in the Write Response. 
	# priority==3 ... We want to execute before writing to smb_files.log

	c$smb_state$current_file$data_offset_req = offset;
	c$smb_state$current_file$data_len_req    = data_len;
} 


event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, data_len: count) &priority=2 
{
	# NOTE: Preference would be to detect 'smb2_write_response' 
	#       event (instead of 'smb2_write_request'), because it 
	#       would confirm the file was actually written to the 
	#       remote destination.  Unfortuantely, Bro/Zeek does 
	#       not have an event for that SMB message-type yet.

	local smb_action = "SMB::FILE_WRITE to";

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


# #
# # WARNING: No event generated for SMB2_WRITE_RESPONSE
# #
#event smb2_write_response(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, written_bytes: count) &priority=3
#{
#	# Keep track of the number of bytes in the Write Response. 
#	# priority==3 ... We want to execute before writing to smb_files.log
#	c$smb_state$current_file$data_len_rsp = written_bytes;
#}

#event smb2_write_response(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, written_bytes: count) &priority=-5
#{
#	SMB::write_file_log(c$smb_state); 
#}

#end bzar_smb2_detect.bro
