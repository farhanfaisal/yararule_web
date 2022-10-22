rule Redirector_small_html_redirector {
	meta:
		description = "Small HTML redirector"
        author = "Farhan Faisal"
        date = "2021/06/26"
        score = 80
	strings:
		$s1 = "http-equiv"
		$s2 = "refresh"
		$s3 = "content"
		$s4 = "javascript"
	condition:
		filesize < 1KB and (all of ($s*))
}

rule Small_Redirector_HTML {
	meta:
		description = "Redirector - small HTML redirector"
        author = "Farhan Faisal"
        date = "2018/07/19"
        score = 80
	strings:
		$s1 = "<head>"
		$s2 = "<meta"
		$s3 = "http-equiv=\"refresh\""
		$s4 = "content=\"0"
	condition:
		all of them and filesize < 200
}