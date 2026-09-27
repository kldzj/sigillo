CREATE TABLE `secret_read` (
	`id` text PRIMARY KEY,
	`environment_id` text NOT NULL,
	`actor` text NOT NULL,
	`kind` text NOT NULL,
	`names` text NOT NULL,
	`ip_address` text,
	`created_at` integer NOT NULL,
	`seq` integer NOT NULL,
	`hash` text NOT NULL,
	`signature` text NOT NULL,
	CONSTRAINT `fk_secret_read_environment_id_environment_id_fk` FOREIGN KEY (`environment_id`) REFERENCES `environment`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
ALTER TABLE `environment` ADD `protected` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `secret_event` ADD `actor` text;--> statement-breakpoint
ALTER TABLE `secret_event` ADD `seq` integer;--> statement-breakpoint
ALTER TABLE `secret_event` ADD `hash` text;--> statement-breakpoint
ALTER TABLE `secret_event` ADD `signature` text;--> statement-breakpoint
CREATE UNIQUE INDEX `secret_event_env_seq_unique` ON `secret_event` (`environment_id`,`seq`);--> statement-breakpoint
CREATE UNIQUE INDEX `secret_read_env_seq_unique` ON `secret_read` (`environment_id`,`seq`);