#!/usr/bin/php
<?php
set_time_limit(0);

// required: inotify
// $ sudo apt install php8.0-inotify -y

// # ./ban.php &
// [1] 600
// run as root or put your user as sudoer to iptables

function tail($file,&$pos) { // literally  $ tail -F
			     // I prefer not using shell_exec('tail -F $file') to prevent shell injection attempts
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
	if(preg_match("/SSTP_DUPLEX|baidu|GponForm|ruthmori|Go-http-client|VLC\/|clients_live|system|shell|Analyze|\/\.env|\/GponForm\/diag_Form\?images\/|Hello| World|boaform|\.exe|\.cgi|certutil|urlcache|python|wget|drupal_ajax|Nimbostratus|\/admin\/formLogin|wordpress|wp-login.php|wp-admin.php|wp-includes|pma20..|PMA20..|mysqlmanager|db-admin|mysql-admin|phpmanager|phpmyadmin|mstshash=Admin|Mozi.m|phpMyAdmin|127\.0\.0\.1|execute-solution|CensysInspect|censys|well-known\/security\.txt|vicidial|is_the_shittiest_lang|boaform|formLogin|admin.php|zgrab|\\x[0-9a-fA-F]{2}|Palo Alto Networks company|NetSystemsResearch|\/hudson|\/clientaccesspolicy\.xml|\/owa\/auth\/logon\.aspx|bot\.html|\/ZOQc|\/GponForm\/diag_Form\?images\/|\/tmp|AhrefsBot|nikto|masscan|nmap|buster|wpscan|nimb/i", $tail)){
		$ip = explode(" -",explode("] ",$tail)[1])[0];
		if(preg_match("/^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/", $ip) && $ip !== "0.0.0.0"){
			shell_exec("sudo iptables -I INPUT -j DROP -s ".$ip);
			shell_exec("echo 'Blocked: ".$ip).' >> blocked");
		}
	}
}
