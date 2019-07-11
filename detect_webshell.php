import "magic"

rule webshell_wp_custm {
	meta:
		description = "Web Shell - wp-custm.php - Heavily obfuscated webshell"
		author = "Farhan Faisal"
		date = "2018/07/17"
		score = 70
		hash = "f85b0e08afa5d328b42d73c8f9b99c9b"
	strings:
		$s0 = "fputs"
		$s1 = "include"
		$s2 = "fclose"
		$s3 = "str_replace"
		$s4 = "fopen"
		$s5 = "<?php"
		$s6 = "\",\"w\")"
		$s7 = "str_replace("
		$s8 = "$$$$$$$"
	condition:
		all of them
}

rule webshell_FilesMan {
	meta:
		description = "Web Shell - FilesMan file manager"
		author = "Farhan Faisal"
		date = "2019/07/11"
		score = 70
		hash = "451addf319a55d21bd4f2d4d30a07d07"
	strings:
		$s0 = "FilesMan"
		$s1 = "auth_pass"
		$s2 = "$_REQUEST"
		$s3 = "default_charset"
		
	condition:
		all of them and (filesize < 27KB)
}


rule SH_uploader_cleartext {
        meta:
             	description = "Web Shell - SH file uploader (cleartext)"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 70
                hash = "1dcc711d35772234413f54c0540efb9a"
        strings:
                $s0 = "<title>SH</title>"
                $s1 = "0x00.ath.cx"
                $s2 = "is_callable(\"posix_getuid"
                $s3 = "is_callable(\"php_uname"
                $s4 = "posix_getpwuid"
        condition:
                all of them
}


rule Exploiter_jposeirt_downloader_cleartext {
	meta:
		description = "Redirector - jposeirt downloader (cleartext)"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 70
                hash = "94f8cf252a854c864e78b95480c87846"
	strings:
		$s0 = "$_REQUEST[\"test_url"
                $s1 = "base64_decode"
                $s2 = "file_put_contents"
                $s3 = ".zip"
                $s4 = "PCLZIP_ERR_USER_ABORTED"
		$s5 = "PCLZIP_ERR_INVALID_PARAMETER"
		$s6 = "PclZip::errorCode"
		$s7 = "PCLZIP_OPT_BY_INDEX"
	condition:
		$s0 and $s1 and $s2 and $s3 and $s4 and $s5 and $s6 and ( #s7 > 8 )
}

rule Exploiter_wordpress_WP_load_update_core {
	meta:
		description = "Wordpress exploiter - replace wp-load.php and update-core.php"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 70
                hash = "f15ab6224eb386bf6efbdf323536b306"
	strings:
		$s1 = "ini_set"
		$s2 = "set_time_limit"
		$s3 = "error_reporting"
		$s4 = "file_put_contents"
		$s5 = "wp-load.php"
		$s6 = "gzuncompress"
		$s7 = "base64_decode"
		$s8 = "str_replace"
		$s9 = "unlink"
		$s10 = "strlen"
		$s11 = "htaccess"
	condition:
		all of them
}

rule Exploiter_wordpress_injected_createUser {
	meta:
		description = "Wordpress exploiter - replace wp-load.php and update-core.php"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 70
                hash = "0c1ef85adf6cad873ee5413ab2e1baa5"
	strings:
		$s1 = "set_time_limit"
		$s2 = "SHELL_PASSWORD"
		$s3 = "MAX_UP_LEVELS"
		$s4 = "create_user"
		$s5 = "wp_insert_user"
		$s6 = "wp_login_url"
		$s7 = "wp_insert_post"
		$aa = "hashed_password"
	condition:
		(#aa > 7) and (all of ($s*))
}



rule Exploiter_wordpress_joomla {
	meta:
		description = "Wordpress & joomla exploiter - uploader.php"
                author = "Farhan Faisal"
                date = "2019/07/11"
                score = 70
                hash = "1337cd85defe6b1c00a8a598acd99bef"
	strings:
		$s1 = "function filter_dirs"
		$s2 = "function get_all_dirs"
		$s3 = "jm_file_names"
		$s4 = "wp_file_names"
		$s5 = "MAX_EXEC_TIME"
		$s6 = "MAX_LEVELS_UP"
		$s7 = "base64_decode"
		$s8 = "eval("
		$s9 = "WORDPRESS"
		$s10 = "JOOMLA"
		$s11 = "PLATFORM"

	condition:
		(all of ($s*))
}

rule Exploiter_wordpress_2 {
	meta:
		description = "Wordpress exploiter - wp_code.php"
                author = "Farhan Faisal"
                date = "2019/07/11"
                score = 70
                hash = "0a28c9bee45b7f7dad1b2c57d69652ed"
	strings:
		$s1 = "set_time_limit"
		$s2 = "PASSWORD_FILE"
		$s3 = "rawurlencode"
		$s4 = "SHELL_PASSWORD"
		$s5 = "MAX_UP_LEVELS"
		$s6 = "wp-load.php"
		$s7 = "file_found"
		$s8 = "get_blogs_list"
		$s9 = "get_users"
		$s10 = "file2clean"
		$s11 = "post_url2search"

	condition:
		(all of ($s*))
}


rule Exploiter_joomla_1 {
	meta:
		description = "Wordpress exploiter - jm_code.php"
        author = "Farhan Faisal"
        date = "2019/07/11"
        score = 70
        hash = "863e2a44ba896d456731998cd084288c"
	strings:
		$s1 = "set_time_limit"
		$s2 = "PASSWORD_FILE"
		$s3 = "SHELL_PASSWORD"
		$s4 = "MAX_UP_LEVELS"
		$s5 = "administrator"
		$s6 = "file_found"
		$s7 = "JPATH_BASE"
		$s8 = "JPATH_COMPONENT_ADMINISTRATOR"
		$s9 = "id2delete"
		$s10 = "JTable"
		$s11 = "raiseWarning"

	condition:
		(all of ($s*))
}






rule Webshell_simple_dama_php_cleartext {
        meta:
             	description = "Webshell - simple dama.php cleartext"
                author = "Farhan Faisal"
                date = "2018/07/17"
                score = 60
                hash = "7b19a553a5f2a61c0f9f1122c54c907c"
        strings:
                $s1 = "set_time_limit"
                $s2 = "error_reporting"
                $s3 = "get_magic_quotes_gpc"
                $s4 = "404-server"
                $s5 = "multipart/form-data"
                $s6 = "php_uname"
                $s7 = "is_readable"
        condition:
                all of them
}

rule Webshell_chinese_filebox_php_cleartext {
	meta:
		description = "Webshell - PHP Chinese webshell (cleartext)"
                author = "Farhan Faisal"
                date = "2018/07/21"
                score = 60
                hash = "67447a35d2bf604a7bb087a983553164"
	strings:
		$s1 = "Microsoft Yahei"
		$s2 = "setcookie"
		$s3 = "SHELL"
		$s4 = "宇宙无敌的"
		$s5 = "login"
		$s6 = "payload_selfshell_filename"
	condition:
		all of them and ( filesize > 38KB and filesize < 45KB )
}


/* 
to do 
generic_small_uploader
	filesize < 1k
*/
