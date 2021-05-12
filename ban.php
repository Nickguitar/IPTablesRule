#!/usr/bin/php
<?php
set_time_limit(0);

// required: inotify
// $ sudo apt install php8.0-inotify -y

// # ./ban.php &
// [1] 600
// run as root or put nginx as sudoer to iptables

function tail($file,&$pos) { // literally  $ tail -F
	if(!$pos) $pos = filesize($file);
	$fd = inotify_init();
	$watch_descriptor = inotify_add_watch($fd, $file, IN_ALL_EVENTS);
	while (true) {
		$events = inotify_read($fd);
		foreach ($events as $event=>$evdetails) {
			switch (true) {
				case ($evdetails['mask'] & IN_MODIFY):
					inotify_rm_watch($fd, $watch_descriptor);
					fclose($fd);
					$fp = fopen($file,'r');
					if (!$fp) return false;
					fseek($fp,$pos);
					$buf = '';
					while (!feof($fp)) {
						$buf .= fread($fp,8192);
					}
					$pos = ftell($fp); fclose($fp);
					return $buf;
				break;

				case ($evdetails['mask'] & IN_MOVE):
				case ($evdetails['mask'] & IN_MOVE_SELF):
				case ($evdetails['mask'] & IN_DELETE):
				case ($evdetails['mask'] & IN_DELETE_SELF):
				inotify_rm_watch($fd, $watch_descriptor);
				fclose($fd);
				return false;
				break;
			}
		}
	}
}

$file = "/var/log/nginx/access.log";

while(true) {

	$tail = tail($file, 0);
if(preg_match("/SSTP_DUPLEX|Analyze|\/\.env|\/GponForm\/diag_Form\?images\/|Hello| World|boaform|\.exe|\.cgi|certutil|urlcache|python|wget|drupal_ajax|Nimbostratus|\/admin\/formLogin|wordpress|wp-login.php|wp-admin.php|127\.0\.0\.1|sitemap\.xml|well-known\/security\.txt|zgrab|clear|x00|Palo Alto Networks company|NetSystemsResearch|\/hudson|\/clientaccesspolicy\.xml|\/owa\/auth\/logon\.aspx|bot\.html|\/ZOQc|\/GponForm\/diag_Form\?images\/|\/tmp|AhrefsBot|nikto|masscan|nmap|buster|wpscan|nimb/i", $tail)){
		$ip = explode(" -",explode("] ",$tail)[1])[0];
		shell_exec("sudo iptables -I INPUT -j DROP -s ".escapeshellarg($ip)); // hopefully it won't get shell injection from spoofed IP address  :pray:
		shell_exec("echo 'Blocked: ".escapeshellarg($ip)."' >> blocked");
	}
}
