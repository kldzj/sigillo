-- One org per auto-join domain, as documented: the first claim wins. Clear
-- later duplicate claims first so the unique index can be built. Org ids
-- are ULIDs, so the smallest id is the oldest org, which keeps its claim.
UPDATE `org` SET `auto_join_domain` = NULL WHERE `auto_join_domain` IS NOT NULL AND `id` NOT IN (SELECT min(`id`) FROM `org` WHERE `auto_join_domain` IS NOT NULL GROUP BY `auto_join_domain`);--> statement-breakpoint
DROP INDEX IF EXISTS `org_auto_join_domain_idx`;--> statement-breakpoint
CREATE UNIQUE INDEX `org_auto_join_domain_unique` ON `org` (`auto_join_domain`);