create database db_tarefa4;
use db_tarefa4;
--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(100) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `mfa_secret` varchar(255) DEFAULT NULL,
  `mfa_enabled` tinyint DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=36 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (11,'mig_per@hotmail.com','$2y$12$I0fMt7E5nWjskbDShWs7be3NiVi7zJESZhb8vXDD8eq.h9qtKwjwu','Z4UANZE4ZHREXWYTHMJMAEF42FQX6SO5',1),(33,'migarper@gmail.com','$2y$12$KDr5/gAECT8sEJbo0QYhSulSMZnU.goVMlGZeQHC9QhLraiKlQla6','PPADY5XFQ6UMA7AKQK25ZD5P6IGIJYOW',1),(35,'migalexper@gmail.com','$2y$12$S6EZsc2TY9SdrP8VE1.eVujCZIWF5H.A97CxH7LdqeTTSaShGupHK','H3UGKSKF4TLD4RTAUVYOYMOXVV5XDBV2',0);

UNLOCK TABLES;



