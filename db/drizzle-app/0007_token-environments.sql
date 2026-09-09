-- Allowlist of environments per API token. Zero rows = all envs (same as
-- memberAccess).
--
-- D1 keeps foreign_keys ON and may ignore PRAGMA foreign_keys=OFF across
-- split statements. secret_event.api_token_id is ON DELETE CASCADE, so
-- DROP TABLE api_token would delete token-authored audit rows. Park
-- secret_event first. Create the junction WITHOUT FKs so DROP api_token
-- cannot wipe the backfill either.
CREATE TABLE `api_token_environment` (
	`id` text PRIMARY KEY NOT NULL,
	`token_id` text NOT NULL,
	`environment_id` text NOT NULL
);--> statement-breakpoint
INSERT INTO `api_token_environment` (`id`, `token_id`, `environment_id`)
SELECT `id`, `id`, `environment_id`
FROM `api_token`
WHERE `environment_id` IS NOT NULL;--> statement-breakpoint
CREATE TABLE `__secret_event_copy` (
	`id` text PRIMARY KEY,
	`environment_id` text NOT NULL,
	`name` text NOT NULL,
	`operation` text NOT NULL,
	`value_encrypted` text,
	`iv` text,
	`user_id` text,
	`api_token_id` text,
	`created_at` integer NOT NULL
);--> statement-breakpoint
INSERT INTO `__secret_event_copy` SELECT `id`, `environment_id`, `name`, `operation`, `value_encrypted`, `iv`, `user_id`, `api_token_id`, `created_at` FROM `secret_event`;--> statement-breakpoint
DROP TABLE `secret_event`;--> statement-breakpoint
CREATE TABLE `__new_api_token` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`project_id` text NOT NULL,
	`prefix` text NOT NULL,
	`hashed_key` text NOT NULL,
	`created_by` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_api_token_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_api_token_created_by_user_id_fk` FOREIGN KEY (`created_by`) REFERENCES `user`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
INSERT INTO `__new_api_token`(`id`, `name`, `project_id`, `prefix`, `hashed_key`, `created_by`, `created_at`) SELECT `id`, `name`, `project_id`, `prefix`, `hashed_key`, `created_by`, `created_at` FROM `api_token`;--> statement-breakpoint
DROP TABLE `api_token`;--> statement-breakpoint
ALTER TABLE `__new_api_token` RENAME TO `api_token`;--> statement-breakpoint
CREATE INDEX `api_token_project_id_idx` ON `api_token` (`project_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `api_token_hashed_key_idx` ON `api_token` (`hashed_key`);--> statement-breakpoint
CREATE TABLE `secret_event` (
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
	CONSTRAINT `fk_secret_event_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_secret_event_api_token_id_api_token_id_fk` FOREIGN KEY (`api_token_id`) REFERENCES `api_token`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
INSERT INTO `secret_event` SELECT `id`, `environment_id`, `name`, `operation`, `value_encrypted`, `iv`, `user_id`, `api_token_id`, `created_at` FROM `__secret_event_copy`;--> statement-breakpoint
DROP TABLE `__secret_event_copy`;--> statement-breakpoint
CREATE INDEX `secret_event_env_name_idx` ON `secret_event` (`environment_id`,`name`,`created_at`);--> statement-breakpoint
CREATE TABLE `__new_api_token_environment` (
	`id` text PRIMARY KEY NOT NULL,
	`token_id` text NOT NULL REFERENCES `api_token`(`id`) ON DELETE CASCADE,
	`environment_id` text NOT NULL REFERENCES `environment`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
INSERT INTO `__new_api_token_environment` (`id`, `token_id`, `environment_id`)
SELECT `id`, `token_id`, `environment_id` FROM `api_token_environment`;--> statement-breakpoint
DROP TABLE `api_token_environment`;--> statement-breakpoint
ALTER TABLE `__new_api_token_environment` RENAME TO `api_token_environment`;--> statement-breakpoint
CREATE UNIQUE INDEX `api_token_environment_token_env_unique` ON `api_token_environment` (`token_id`, `environment_id`);--> statement-breakpoint
CREATE INDEX `api_token_environment_token_id_idx` ON `api_token_environment` (`token_id`);--> statement-breakpoint
CREATE INDEX `api_token_environment_environment_id_idx` ON `api_token_environment` (`environment_id`);--> statement-breakpoint
-- If cascade deletes the last allowlist row, revoke the token instead of
-- treating 0 rows as "all environments" (which would grant prod).
CREATE TRIGGER `api_token_environment_revoke_empty`
AFTER DELETE ON `api_token_environment`
WHEN NOT EXISTS (SELECT 1 FROM `api_token_environment` WHERE `token_id` = OLD.`token_id`)
 AND EXISTS (SELECT 1 FROM `api_token` WHERE `id` = OLD.`token_id`)
BEGIN
	DELETE FROM `api_token` WHERE `id` = OLD.`token_id`;
END;
