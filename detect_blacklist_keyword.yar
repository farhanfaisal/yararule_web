rule Blacklisted_keywords {
			meta:
						description = "Blacklisted keywords."
						author = "Farhan Faisal"
						date = "2021/06/24"
						score = 60
						hash = ""
			strings:
						$s1 = "RunPorn"
						$s2 = "drugstore"
						$s3 = "tvarm.ru"
						$s4 = "pornstars"
						$s5 = "viagra"
						$s6 = "47MedPortal"
						$s7 = "1BdmQcoa12YJE9RyEEGPc2JZViNeBHEyvXs-qYsNVc4"
						$s8 = ".xhcdn.com"
						$s9 = "tvarm.ru"
						$s10 = "pornsite"
						$s11 = "porn21"

			condition:
						(any of ($s*))
}
