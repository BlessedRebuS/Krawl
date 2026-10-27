-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: crm
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
(1, 'tchen', 'tchen@example.com', '$2y$10$XBo89PK3CkxhDeDQxM.pGQxtHVxY2yAMA1olT6vcX6BH4Qh/xzKyu'),
(2, 'pgarcia', 'pgarcia@example.com', '$2y$10$okv1tuo55WufF9fjvSWkmz.rP5bZMgWGTKSX23J8R4hHQWS.uSnzk'),
(3, 'admin', 'admin@example.com', '$2y$10$ME/zDTucszMXpYZfgAPgxi4cMuQq2/YOm8TF5esOModhCe6CeVgHn'),
(4, 'ops', 'ops@example.com', '$2y$10$MQL5GFhiFxP2bi3OicWA/LDEAo0E89hU8VSbQUCiu5AfreeeRGe56'),
(5, 'jmorrison', 'jmorrison@example.com', '$2y$10$B1yMm/fQ.tcAZy3uiMaCm1RYFFCe3lZc4ebu.0E52IpDbpwchmuo.');
