CREATE TABLE `api_users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user` varchar(250) NOT NULL DEFAULT '',
  `password` varchar(250) NOT NULL DEFAULT '',
  `api_key` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `api_users` (`id`, `user`, `password`) VALUES
('0', 'hernan98_v@hotmail.com', 'pbkdf2_sha256$180000$PiTBENEFhDD8$p/ONz+pyXenUA+ar5ur5drSGCWqrBMRertnMYMtwr3w='),
('1', 'alfred@hotmail.com', '893ejrf20jdc13851f940f8df710c4c7');
