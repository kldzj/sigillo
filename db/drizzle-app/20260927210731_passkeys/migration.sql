CREATE TABLE `passkey` (
	`id` text PRIMARY KEY,
	`name` text,
	`public_key` text NOT NULL,
	`user_id` text NOT NULL,
	`credential_id` text NOT NULL,
	`counter` integer NOT NULL,
	`device_type` text NOT NULL,
	`backed_up` integer NOT NULL,
	`transports` text,
	`created_at` integer,
	`aaguid` text,
	CONSTRAINT `fk_passkey_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX `passkey_user_id_idx` ON `passkey` (`user_id`);--> statement-breakpoint
CREATE INDEX `passkey_credential_id_idx` ON `passkey` (`credential_id`);--> statement-breakpoint
CREATE TABLE `passkey_event` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`passkey_name` text,
	`ip_address` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `step_up_grant` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`session_id` text NOT NULL,
	`purpose` text DEFAULT 'read' NOT NULL,
	`environment_ids` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `fk_step_up_grant_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_step_up_grant_session_id_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `step_up_request` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`session_id` text NOT NULL,
	`purpose` text DEFAULT 'read' NOT NULL,
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
ALTER TABLE `api_token` ADD `last_used_ip` text;--> statement-breakpoint
ALTER TABLE `api_token` ADD `protected_access` integer DEFAULT false NOT NULL;--> statement-breakpoint
CREATE INDEX `passkey_event_user_id_idx` ON `passkey_event` (`user_id`);--> statement-breakpoint
CREATE INDEX `step_up_grant_session_id_idx` ON `step_up_grant` (`session_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `step_up_request_user_code_unique` ON `step_up_request` (`user_code`);--> statement-breakpoint
CREATE INDEX `step_up_request_user_id_idx` ON `step_up_request` (`user_id`);
