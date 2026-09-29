CREATE TABLE IF NOT EXISTS `trust_rule` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`name` text NOT NULL,
	`issuer` text NOT NULL,
	`jwks_uri` text,
	`jwks` text NOT NULL,
	`jwks_fetched_at` integer,
	`audience` text NOT NULL,
	`subject` text NOT NULL,
	`claims` text NOT NULL,
	`environment_ids` text NOT NULL,
	`protected_access` integer DEFAULT false NOT NULL,
	`created_by` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_used_at` integer,
	CONSTRAINT `fk_trust_rule_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_trust_rule_created_by_user_id_fk` FOREIGN KEY (`created_by`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
ALTER TABLE `api_token` ADD `trust_rule_id` text REFERENCES trust_rule(id) ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE `api_token` ADD `workload` text;--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `api_token_trust_rule_id_idx` ON `api_token` (`trust_rule_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `trust_rule_issuer_idx` ON `trust_rule` (`issuer`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `trust_rule_project_id_idx` ON `trust_rule` (`project_id`);