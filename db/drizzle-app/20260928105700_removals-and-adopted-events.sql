CREATE TABLE `org_removal` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`user_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_org_removal_org_id_org_id_fk` FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_org_removal_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_removal_org_id_user_id_unique` ON `org_removal` (`org_id`,`user_id`);--> statement-breakpoint
ALTER TABLE `secret_event` ADD `adopted` integer DEFAULT false NOT NULL;
