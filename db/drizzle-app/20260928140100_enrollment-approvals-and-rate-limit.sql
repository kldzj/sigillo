CREATE TABLE `enrollment_approval` (
	`id` text PRIMARY KEY,
	`request_id` text NOT NULL,
	`org_id` text NOT NULL,
	`approver_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_enrollment_approval_request_id_step_up_request_id_fk` FOREIGN KEY (`request_id`) REFERENCES `step_up_request`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_enrollment_approval_org_id_org_id_fk` FOREIGN KEY (`org_id`) REFERENCES `org`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_enrollment_approval_approver_id_user_id_fk` FOREIGN KEY (`approver_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_approval_request_id_org_id_unique` ON `enrollment_approval` (`request_id`,`org_id`);--> statement-breakpoint
CREATE TABLE `rate_limit` (
	`id` text PRIMARY KEY,
	`key` text NOT NULL UNIQUE,
	`count` integer NOT NULL,
	`last_request` integer NOT NULL
);
