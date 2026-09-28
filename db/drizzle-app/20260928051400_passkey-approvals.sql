PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_step_up_grant` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`session_id` text NOT NULL,
	`purpose` text NOT NULL,
	`environment_ids` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `fk_step_up_grant_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_step_up_grant_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
INSERT INTO `__new_step_up_grant`(`id`, `user_id`, `session_id`, `purpose`, `environment_ids`, `created_at`, `expires_at`) SELECT `id`, `user_id`, `session_id`, `purpose`, `environment_ids`, `created_at`, `expires_at` FROM `step_up_grant`;--> statement-breakpoint
DROP TABLE `step_up_grant`;--> statement-breakpoint
ALTER TABLE `__new_step_up_grant` RENAME TO `step_up_grant`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_step_up_request` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`session_id` text NOT NULL,
	`purpose` text NOT NULL,
	`environment_ids` text NOT NULL,
	`user_code` text,
	`challenge` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`ip_address` text,
	`country` text,
	`user_agent` text,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `fk_step_up_request_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_step_up_request_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
INSERT INTO `__new_step_up_request`(`id`, `user_id`, `session_id`, `purpose`, `environment_ids`, `user_code`, `challenge`, `status`, `ip_address`, `country`, `user_agent`, `created_at`, `expires_at`) SELECT `id`, `user_id`, `session_id`, `purpose`, `environment_ids`, `user_code`, `challenge`, `status`, `ip_address`, `country`, `user_agent`, `created_at`, `expires_at` FROM `step_up_request`;--> statement-breakpoint
DROP TABLE `step_up_request`;--> statement-breakpoint
ALTER TABLE `__new_step_up_request` RENAME TO `step_up_request`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `step_up_grant_session_id_idx` ON `step_up_grant` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `step_up_request_user_code_unique` ON `step_up_request` (`user_code`);--> statement-breakpoint
CREATE INDEX `step_up_request_user_id_idx` ON `step_up_request` (`user_id`);--> statement-breakpoint
UPDATE `step_up_grant` SET `purpose` = CASE `purpose` WHEN 'read' THEN 'access' WHEN 'passkeys' THEN 'admin' ELSE `purpose` END;--> statement-breakpoint
UPDATE `step_up_request` SET `purpose` = CASE `purpose` WHEN 'read' THEN 'access' WHEN 'passkeys' THEN 'admin' ELSE `purpose` END;--> statement-breakpoint
ALTER TABLE `session` ADD `signed_in` integer DEFAULT false NOT NULL;
