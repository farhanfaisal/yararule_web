
rule Uploader_small_uploader_1 {
			meta:
					description = "Uploader - Clear form,obfuscated handler"
					author = "Farhan Faisal"
					date = "2018/07/17"
					score = 60
					hash = "ecf1130eb57297296953f36970657994"
			strings:
					$s1 = "error_reporting(0)"
					$s2 = "<form"
					$s3 = "multipart/form-data"
					$s4 = "$_REQUEST"

			condition:
					all of them and (filesize < 1KB)
}



rule Uploader_small_uploader_2_clear {
			meta:
					description = "Uploader - simple, clear"
					author = "Farhan Faisal"
					date = "2019/07/11"
					score = 60
					hash = "a5398e7617983b1a85dd203b46055449"
			strings:
					$s1 = "<form"
					$s2 = "multipart/form-data"
					$s3 = "is_uploaded_file"
					$s4 = "move_uploaded_file"
			condition:
					all of them and (filesize < 1KB)
}


rule Uploader_GENERIC_smallPHP_upload_capable {
			meta:
					description = "Uploader - simple"
					author = "Farhan Faisal"
					date = "2021/06/24"
					score = 60
					hash = "ddc8acea01f639a64f1c24399749c9d2"
			strings:
					$s1 = "$_GET"
					$s2 = "$_POST"
					$s3 = "$_REQUEST"
					$xx1 = "file_put_contents("
					$xx2 = "unlink("
					$xx3 = "readfile("
					$xx4 = "basename("
					$xx5 = "file_get_contents("
					$xx6 = "fwrite("
					$xx7 = "base64_decode("
			condition:
					(filesize < 50KB) and (1 of ($s*)) and (3 of ($xx*))
}


rule Exploiter_GENERIC_file_dumping_capable {
			meta:
					description = "Generic PHP exploiter - dumping .zip file."
					author = "Farhan Faisal"
					date = "2021/06/24"
					score = 70
					hash = ""
			strings:
					$b1 = /[0-9a-zA-Z]{100,}/
					$b2 = "<?php"
					$b3 = "base64_decode"
					$b4 = "file_put_contents"
			condition:
					(4 of ($b*))
}
