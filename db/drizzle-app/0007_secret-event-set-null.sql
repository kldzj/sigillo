-- Recreate secret_event so deleting a user or API token keeps the secrets
-- they wrote (SET NULL) instead of cascading into the event log, which
-- deleted or silently reverted those secrets.
PRAGMA foreign_keys=OFF;--> statement-breakpoint
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
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `secret_event_env_name_idx` ON `secret_event` (`environment_id`,`name`,`created_at`);