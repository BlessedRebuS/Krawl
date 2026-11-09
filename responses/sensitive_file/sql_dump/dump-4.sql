-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: shop
-- ------------------------------------------------------

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `email` varchar(128) NOT NULL,
  `password` varchar(128) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `users` VALUES
(1, 'jmorrison', 'jmorrison@example.com', '$2y$10$EHaInPNt9nQyuzQUGt3I2.sEWJIlI0fp70cVcwSS4Rvi071xywxIC'),
(2, 'mrossi', 'mrossi@example.com', '$2y$10$c9GPG4pct3bym9SA1tsz.UGQhTDbWy7N3iFIDVJqAari/6j.HqS4v'),
(3, 'deploy', 'deploy@example.com', '$2y$10$2ZGwKN/bDOt.g7hfAqDJG/GlTMnl2Wmm1yr4JtvXA7pcK2S1gjxqU'),
(4, 'akhan', 'akhan@example.com', '$2y$10$ZKbpZsqGz2EL1Q75uE4vSfja1zdDCYJjRSwT1WBy9GDeYH.EciV2e');
