#
# File: bzar_smb_consts.bro
# Created: 20180701
# Updated: 20191121
#
# Copyright 2018 The MITRE Corporation.  All Rights Reserved.
# Approved for public release.  Distribution unlimited.  Case number 18-3868.
#

module BZAR;

export
{
	# ATT&CK - Lateral Movement Techniques
	#
	# Windows Admin File Shares (eg, ADMIN$ or C$) used for
	# Lateral Movement onto the remote system
	#
	# Relevant ATT&CK Technique(s):
	#    T1077 Windows Admin Shares [File Shares Only]
	#    T1105 Remote File Copy

	const smb_admin_file_shares = vector
	(
		/\\c\$/i,
		/\\admin\$/i

	) &redef;

	# Add these details about SMB::FILE_WRITE actions to smb_files.log
	# in case an existing file is overwritten, rather than a new file
	# being created.  These details would show if the existing file is
	# overwritten in its entirety, or just a smaller sub-section is
	# overwritten, which would be an interesting diagnostic to detect.

@if ((Version::info$major == 2) && (Version::info$minor <= 5))
	# Use this syntax for Bro v2.5.x and below
	redef SMB::write_cmd_log	=  T &redef;
@endif
	redef SMB::logged_file_actions	+= { SMB::FILE_WRITE, } &redef;

	redef record SMB::FileInfo	+= 
	{
		# Keep track of how many bytes written for
		# SMB:FILE_WRITE request and response.
		#
		# This could be an interesting diagnostic for 
		# SMB::FILE_READ too, but not implemented yet.

		data_offset_req	: count &optional &log; # File offset to first byte to write/read
		data_len_req	: count &optional &log; # How many bytes to write/read
		data_len_rsp	: count &optional &log; # How many bytes written/read
	};
}
#end export

#end bzar_smb_consts.bro
