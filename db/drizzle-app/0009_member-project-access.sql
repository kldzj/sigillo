ALTER TABLE `org_member` ADD `project_access` text DEFAULT 'all' NOT NULL;--> statement-breakpoint
-- Existing scoped members (any member_access row) keep their restriction.
UPDATE `org_member` SET `project_access` = 'selected' WHERE `id` IN (SELECT `org_member_id` FROM `member_access`);
