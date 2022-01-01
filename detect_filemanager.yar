rule FileManager_FilesMan {
			meta:
						description = "Web Shell - FilesMan file manager"
						author = "Farhan Faisal"
						date = "2019/07/11"
						score = 70
						hash = "451addf319a55d21bd4f2d4d30a07d07"
			strings:
						$s0 = "FilesMan" nocase
						$s1 = "auth_pass"
						$x1 = "$_SERVER['"
						$x2 = "$_REQUEST["
			condition:
						all of ($s*) and 1 of ($x*)
}
