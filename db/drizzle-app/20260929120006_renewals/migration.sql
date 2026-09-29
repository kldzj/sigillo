CREATE TABLE IF NOT EXISTS `security_event` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`project_id` text,
	`project_name` text,
	`kind` text NOT NULL,
	`subject_id` text NOT NULL,
	`subject_name` text NOT NULL,
	`actor` text NOT NULL,
	`actor_name` text,
	`ip_address` text,
	`details` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `api_token` ADD `previous_hashed_key` text;--> statement-breakpoint
ALTER TABLE `api_token` ADD `previous_expires_at` integer;--> statement-breakpoint
ALTER TABLE `api_token` ADD `previous_last_used_at` integer;--> statement-breakpoint
ALTER TABLE `api_token` ADD `previous_last_used_ip` text;--> statement-breakpoint
ALTER TABLE `api_token` ADD `regenerated_at` integer;--> statement-breakpoint
ALTER TABLE `api_token` ADD `regenerated_by` text REFERENCES user(id) ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE `trust_rule` ADD `renewed_at` integer;--> statement-breakpoint
ALTER TABLE `trust_rule` ADD `renewals` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `api_token_previous_hashed_key_unique` ON `api_token` (`previous_hashed_key`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `security_event_org_id_idx` ON `security_event` (`org_id`,`created_at`);