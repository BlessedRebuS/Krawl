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
(1, 'pgarcia', 'pgarcia@example.com', '$2y$10$wvnV5WI5.m3CYq.McseD6TYyIaWkdvlNJ7FjfFbkqF/5lmdK8GOB2'),
(2, 'svc_app', 'svc_app@example.com', '$2y$10$XuZiI6cQnmUMLaXHo3w1Ns09mmO8mICEJvS7RWCkBSOr8KrGD3e/w'),
(3, 'lnovak', 'lnovak@example.com', '$2y$10$n46MREF4wzkuAqzWYyDtoQLNerzXQw141N.UYC46O/d9FzRcnlWHj'),
(4, 'ops', 'ops@example.com', '$2y$10$9QObR8RIr4Hw25xxM4J1QcqCGFEt7XyiBy8ejwh6M0eovQTK5seU3');
