-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: app
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
(1, 'akhan', 'akhan@example.com', '$2y$10$Ll0LfvQpizbdht05zV0.oS5Vc1XMcfaJMg1AiLqnnYgpiQRBjb7Md'),
(2, 'tchen', 'tchen@example.com', '$2y$10$O1n8kCB9EVUsDDvmk/7k/vWDEBcHq6Os1LOVUn3VWVo.U6st4/Sjs'),
(3, 'mrossi', 'mrossi@example.com', '$2y$10$IavK7S5n3nqQpaSeOgG5An56EVpboMYjjtqwVxVP6L.xImnw25Dwu'),
(4, 'deploy', 'deploy@example.com', '$2y$10$KD/SxKD9lZszcquqOhtIILlqX/kf4/z9M5cb1DgXamVVGNMqwNoY6'),
(5, 'admin', 'admin@example.com', '$2y$10$OksLCzbyxh/X9pRTpMULIqquGAnd/w45kloaoNSlHPURWfiUCTUXT'),
(6, 'svc_app', 'svc_app@example.com', '$2y$10$B5QE0vwM.msgPEEwxLkEjGFAuZpH9xARFX4pGEDOmrpBut8NugOMK');
