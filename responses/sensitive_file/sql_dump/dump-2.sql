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
(1, 'pgarcia', 'pgarcia@example.com', '$2y$10$UHSzUfJ3abhz8l5VdJShvYK32zfQ3UI05DyValLgbaSqNQZEtWe/7'),
(2, 'svc_app', 'svc_app@example.com', '$2y$10$Pg6E9BSl9GQNFDA2gd2SU54hwaYQRPowTfaNEFKX.0Cq7aLsxHt/4'),
(3, 'tchen', 'tchen@example.com', '$2y$10$U5GY64Z/bqH0l0vDVJ062kGB3wisPqIew1ufTYvGZTxpwkgfSt0qw'),
(4, 'deploy', 'deploy@example.com', '$2y$10$Itm53Q88hfjCpbZTQ7GXcFBd9fLpc3YRMWq4KCmd8zdYtThJWKRlZ'),
(5, 'ops', 'ops@example.com', '$2y$10$rBhA4TrYLUjhSx2PcBnpLtScDQ9VMen9ryvEz13VKOZMbAr11I5aC'),
(6, 'mrossi', 'mrossi@example.com', '$2y$10$pVy.juzqVybM2svCnNzbwxh03HMRoHzV4hN0Oo/yOy5SgC1/.0IKG');
