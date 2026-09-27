-- secret_event.user_id / api_token_id were ON DELETE CASCADE, so deleting a
-- token or user deleted every secret event it authored and reverted values
-- to older versions. Rebuild with SET NULL. Nothing references secret_event,
-- so dropping it cannot cascade anywhere. No PRAGMA foreign_keys=OFF: D1
-- ignores it.
CREATE TABLE `__new_secret_event` (
	`id` text PRIMARY KEY,
	`environment_id` text NOT NULL,
	`name` text NOT NULL,
	`operation` text NOT NULL,
	`value_encrypted` text,
	`iv` text,
	`user_id` text,
	`api_token_id` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_secret_event_environment_id_environment_id_fk` FOREIGN KEY (`environment_id`) REFERENCES `environment`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_secret_event_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE SET NULL,
	CONSTRAINT `fk_secret_event_api_token_id_api_token_id_fk` FOREIGN KEY (`api_token_id`) REFERENCES `api_token`(`id`) ON DELETE SET NULL
);
--> statement-breakpoint
INSERT INTO `__new_secret_event`(`id`, `environment_id`, `name`, `operation`, `value_encrypted`, `iv`, `user_id`, `api_token_id`, `created_at`) SELECT `id`, `environment_id`, `name`, `operation`, `value_encrypted`, `iv`, `user_id`, `api_token_id`, `created_at` FROM `secret_event`;--> statement-breakpoint
DROP TABLE `secret_event`;--> statement-breakpoint
ALTER TABLE `__new_secret_event` RENAME TO `secret_event`;--> statement-breakpoint
CREATE INDEX `secret_event_env_name_idx` ON `secret_event` (`environment_id`,`name`,`created_at`);
