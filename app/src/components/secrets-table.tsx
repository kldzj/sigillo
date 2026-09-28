// Secrets table with editable keys/values like Doppler.
// The page loads names only. A value is fetched when revealed (eye icon, or
// "Show all secrets"), which protected environments record in the read log.
// Editing a key or value, filling a missing key, or drafting a new secret
// marks the table dirty. A single "Save N secrets" flow handles all of it.
// Import from .env via a dialog with a textarea, and export current secrets
// back to .env via download or copy.

"use client";

import { EyeIcon, EyeOffIcon, TrashIcon, UploadIcon, PlusIcon, KeyIcon, CheckIcon, DownloadIcon, CopyIcon, ArrowDownToLineIcon } from "lucide-react";
import { EmptyState } from "sigillo-app/src/components/ui/empty-state";
import { Spinner } from "sigillo-app/src/components/ui/spinner";
import { useState, useCallback, useEffect, useRef } from "react";
import { z } from "zod";
import { parseFormData } from "spiceflow";
import { cn, renderEnvFile } from "sigillo-app/src/lib/utils";
import { Button } from "sigillo-app/src/components/ui/button";
import { Frame } from "sigillo-app/src/components/ui/frame";
import { Input, Textarea } from "sigillo-app/src/components/ui/input";
import { NativeSelect } from "sigillo-app/src/components/ui/native-select";
import {
  Dialog,
  DialogPopup,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "sigillo-app/src/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "sigillo-app/src/components/ui/table";
import { parseEnv } from "sigillo-app/src/lib/parse-env";
import { TimeAgo } from "sigillo-app/src/components/ui/time-ago";
import {
  deleteSecretAction,
  revealSecretsAction,
  saveSecretsAction,
  syncMissingSecretsAction,
} from "../actions.ts";
import { withStepUp } from "./step-up.ts";
import { useLoaderData } from "spiceflow/react";


// A copy whose passkey approval wasn't given
class NotApproved extends Error {}

// Secret values use the .text-security-disc CSS class from globals.css
// instead of inline style objects (eliminates duplication with event-log-table).

function SecretValueCell({
  value,
  editedValue,
  onValueChange,
  visible,
  loading,
  onToggle,
  isDirty,
}: {
  // Undefined until fetched
  value: string | undefined;
  editedValue: string | undefined;
  onValueChange: (value: string) => void;
  visible: boolean;
  loading: boolean;
  onToggle: () => void;
  isDirty?: boolean;
}) {
  const displayValue = editedValue ?? value;
  // Shown once fetched; a read that wasn't approved stays masked
  const shown = visible && !loading && displayValue !== undefined;

  return (
    <div className="flex w-full min-w-0 items-center gap-1.5">
      <div className="relative flex min-w-0 flex-1" aria-busy={loading}>
      <Input
        type="text"
        inputSize="sm"
        autoComplete="off"
        data-1p-ignore
        data-lpignore="true"
        value={shown ? displayValue : "••••••••••••"}
        onChange={(e) => {
          if (shown) {
            onValueChange(e.target.value);
          }
        }}
        readOnly={!shown}
        onFocus={(e) => {
          if (!visible) {
            e.target.blur()
            onToggle()
          }
        }}
        className={cn(
          "min-w-0 max-w-full flex-1 mono-sm",
          shown ? "bg-muted/50 value-reveal" : "text-security-disc border-transparent bg-muted/50 cursor-pointer select-none",
          isDirty && "border-amber-400/50 focus:ring-amber-500",
        )}
      />
      {loading && <span aria-hidden className="pointer-events-none absolute inset-0 rounded-md value-loading" />}
      </div>
      <button
        onClick={onToggle}
        disabled={loading}
        className="shrink-0 cursor-pointer text-muted-foreground hover:text-foreground disabled:cursor-default"
        title={loading ? "Loading value" : visible ? "Hide value" : "Reveal value"}
      >
        {loading ? (
          <Spinner className="size-4" />
        ) : visible ? (
          <EyeOffIcon className="size-4" />
        ) : (
          <EyeIcon className="size-4" />
        )}
      </button>
    </div>
  );
}

type Environment = { id: string; name: string; slug: string };

export function SecretsTable({
  allVisible,
}: {
  allVisible: boolean;
}) {
  const { secrets, selectedEnvId: environmentId, environments, allSecretNames } = useLoaderData('/dash/projects/:projectId/envs/:envSlug');
  const [newSecrets, setNewSecrets] = useState<Array<{ id: string; name: string; value: string }>>([]);
  const [saving, setSaving] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);
  const [syncOpen, setSyncOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<{ name: string } | null>(null);

  // Per-row visibility overrides (only used when allVisible is false)
  const [rowVisible, setRowVisible] = useState<Record<string, boolean>>({});
  // Fetched values by secret id: a save gives a secret a new id, so a changed
  // value is fetched again
  const [values, setValues] = useState<Record<string, string>>({});

  // Ids being fetched: the ref so a re-render doesn't fetch (and record) them
  // twice, the state to show them loading
  const fetching = useRef(new Set<string>());
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set());
  // Rows whose passkey approval was declined: "Show all" doesn't ask for them
  // again on its own, only when turned on again or when a row is revealed
  const [declined, setDeclined] = useState<ReadonlySet<string>>(new Set());

  const loadValues = useCallback(async (targets: { id: string; name: string }[]) => {
    const missing = targets.filter((secret) => values[secret.id] === undefined && !fetching.current.has(secret.id));
    if (!environmentId || missing.length === 0) return;
    for (const secret of missing) fetching.current.add(secret.id);
    setPending(new Set(fetching.current));
    try {
      // A protected environment asks for the passkey first
      const result = await withStepUp(() => revealSecretsAction({ environmentId, names: missing.map((secret) => secret.name) }));
      if (result) {
        setValues((prev) => ({ ...prev, ...Object.fromEntries(missing.map((secret) => [secret.id, result.values[secret.name] ?? ""])) }));
      } else {
        setRowVisible((prev) => ({ ...prev, ...Object.fromEntries(missing.map((secret) => [secret.id, false])) }));
        setDeclined((prev) => new Set([...prev, ...missing.map((secret) => secret.id)]));
      }
    } catch (e: any) {
      alert(e?.message || "Failed to load values");
    } finally {
      for (const secret of missing) fetching.current.delete(secret.id);
      setPending(new Set(fetching.current));
    }
  }, [environmentId, values]);

  useEffect(() => {
    if (allVisible) setDeclined(new Set());
  }, [allVisible]);

  // Every action refreshes the page data, so this runs again after each one
  useEffect(() => {
    if (allVisible) void loadValues(secrets.filter((secret) => !declined.has(secret.id)));
  }, [allVisible, secrets, loadValues, declined]);

  // Track edits per secret id
  const [edits, setEdits] = useState<Record<string, { name?: string; value?: string }>>({});
  // Track values typed into missing-key rows (keyed by secret name)
  const [missingEdits, setMissingEdits] = useState<Record<string, string>>({});

  if (!environmentId) return null;

  const setEdit = useCallback((id: string, field: "name" | "value", val: string) => {
    setEdits((prev) => ({
      ...prev,
      [id]: { ...prev[id], [field]: val },
    }));
  }, []);

  // Keys that exist in other envs but not in this one
  // Use edited names so renaming a secret to a missing key hides the red row
  const effectiveNames = new Set(
    [
      ...secrets.map((s) => edits[s.id]?.name ?? s.name),
      ...newSecrets.map((secret) => secret.name),
    ].filter(Boolean)
  );
  const missingKeys = allSecretNames.filter((name) => !effectiveNames.has(name));

  const dirtySecrets = secrets.filter((s) => {
    const e = edits[s.id];
    if (!e) return false;
    if (e.name !== undefined && e.name !== s.name) return true;
    if (e.value !== undefined) return true;
    return false;
  });

  // Missing keys that have a value typed in
  const dirtyMissingKeys = missingKeys.filter((name) => missingEdits[name]?.trim());

  const dirtyNewSecrets = newSecrets.filter((secret) => secret.name.trim() && secret.value.trim());

  const pendingEdits = [
    ...dirtySecrets.map((secret) => {
      const edit = edits[secret.id]!;
      // No value: a rename keeps the current one on the server
      return {
        originalName: secret.name,
        name: edit.name !== undefined ? edit.name : secret.name,
        value: edit.value,
      };
    }),
    ...dirtyMissingKeys.map((name) => ({
      name,
      value: missingEdits[name]!,
    })),
    ...dirtyNewSecrets.map((secret) => ({
      name: secret.name,
      value: secret.value,
    })),
  ];

  const totalDirtyCount = pendingEdits.length;

  // The .env of this environment with unsaved edits applied. Fetches every
  // value, recorded as a download. Null when its passkey approval wasn't given.
  const buildEnvFile = useCallback(async () => {
    const result = await withStepUp(() => revealSecretsAction({ environmentId, names: null, download: true }));
    if (!result) return null;
    const fetched = result.values;
    return renderEnvFile([
      ...secrets.map((secret): [string, string] => [
        edits[secret.id]?.name ?? secret.name,
        edits[secret.id]?.value ?? fetched[secret.name] ?? "",
      ]),
      ...dirtyMissingKeys.map((name): [string, string] => [name, missingEdits[name]!]),
      ...dirtyNewSecrets.map((secret): [string, string] => [secret.name, secret.value]),
    ]);
  }, [environmentId, secrets, edits, dirtyMissingKeys, missingEdits, dirtyNewSecrets]);

  const handleImportText = useCallback(async (text: string) => {
    const parsed = parseEnv(text);
    const edits = Object.entries(parsed).map(([name, value]) => ({ name, value }));
    if (edits.length === 0) return;
    setImporting(true);
    try {
      if (await withStepUp(() => saveSecretsAction({ edits, environmentIds: [environmentId] })) !== null) setImportOpen(false);
    } catch (e: any) {
      alert(e?.message || "Failed to import secrets");
    } finally {
      setImporting(false);
    }
  }, [environmentId]);

  const addNewSecret = useCallback(() => {
    setNewSecrets((prev) => [...prev, { id: crypto.randomUUID(), name: "", value: "" }]);
  }, []);

  const updateNewSecret = useCallback((id: string, field: "name" | "value", value: string) => {
    setNewSecrets((prev) => prev.map((secret) => (
      secret.id === id ? { ...secret, [field]: value } : secret
    )));
  }, []);

  const removeNewSecret = useCallback((id: string) => {
    setNewSecrets((prev) => prev.filter((secret) => secret.id !== id));
  }, []);

  const handleDownloadEnv = useCallback(async () => {
    try {
      const text = await buildEnvFile();
      if (text === null) return;
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `.env.${environments.find((env) => env.id === environmentId)?.slug ?? "env"}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error: any) {
      alert(error?.message || "Failed to download .env");
    }
  }, [buildEnvFile, environmentId, environments]);

  const handleCopyEnv = useCallback(async () => {
    // A declined approval rejects the pending item, and the browser then
    // reports its own error instead of ours
    let notApproved = false;
    try {
      // A pending ClipboardItem keeps the click's permission to write while
      // the values load; writeText after an await would lose it in Safari
      const text = buildEnvFile().then((t) => {
        if (t === null) {
          notApproved = true;
          throw new NotApproved();
        }
        return t;
      });
      if (typeof ClipboardItem !== "undefined") {
        await navigator.clipboard.write([new ClipboardItem({ "text/plain": text.then((t) => new Blob([t], { type: "text/plain" })) })]);
      } else {
        await navigator.clipboard.writeText(await text);
      }
    } catch (error: any) {
      if (notApproved || error instanceof NotApproved) return;
      alert(error?.message || "Failed to copy .env contents");
    }
  }, [buildEnvFile]);

  // Empty state (only show when no secrets AND no missing keys from other envs)
  if (secrets.length === 0 && missingKeys.length === 0 && newSecrets.length === 0) {
    return (
      <>
        <EmptyState
          icon={<KeyIcon className="size-6 text-muted-foreground" />}
          title="No secrets yet"
          description="Add secrets manually or import them from a .env file to get started."
        >
          <div className="flex items-center gap-3">
            <Button size="sm" onClick={addNewSecret}>
              <PlusIcon className="size-4" />
              Add Secret
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setImportOpen(true)}
            >
              <UploadIcon className="size-4" />
              Import .env
            </Button>
          </div>
        </EmptyState>
        <ImportEnvDialog open={importOpen} onOpenChange={setImportOpen} importing={importing} onImport={handleImportText} />
      </>
    );
  }

  return (
    <>
      <Frame className="w-full gap-3">
        <div className="overflow-x-auto">
        <Table>
          <colgroup>
            <col />
            <col />
            <col className="w-32" />
            <col className="w-16" />
          </colgroup>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="whitespace-normal">Key</TableHead>
              <TableHead className="whitespace-normal">Value</TableHead>
              <TableHead>Last Updated</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {secrets.map((secret) => {
              const isDirty = dirtySecrets.includes(secret);
              const isVisible = (allVisible && !declined.has(secret.id)) || (rowVisible[secret.id] ?? false);
              return (
                <TableRow key={secret.id} className={isDirty ? "bg-amber-50/50 dark:bg-amber-950/20" : ""}>
                  <TableCell className="min-w-0 overflow-hidden">
                    <Input
                      type="text"
                      inputSize="sm"
                      value={edits[secret.id]?.name ?? secret.name}
                      onChange={(e) => setEdit(secret.id, "name", e.target.value)}
                      className={cn(
                        "w-full min-w-0 border-transparent bg-transparent px-1.5 mono-sm font-medium focus:border-input hover:border-input",
                        isDirty && "text-amber-700 dark:text-amber-400 border-amber-400/50 focus:ring-amber-500",
                      )}
                    />
                  </TableCell>
                  <TableCell className="min-w-0 overflow-hidden">
                    <SecretValueCell
                      value={values[secret.id]}
                      editedValue={edits[secret.id]?.value}
                      onValueChange={(v) => setEdit(secret.id, "value", v)}
                      visible={isVisible}
                      loading={pending.has(secret.id)}
                      onToggle={() => {
                        if (!isVisible) {
                          setDeclined((prev) => new Set([...prev].filter((id) => id !== secret.id)));
                          void loadValues([secret]);
                        }
                        setRowVisible((prev) => ({ ...prev, [secret.id]: !isVisible }));
                      }}
                      isDirty={isDirty}
                    />
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <TimeAgo
                      ts={secret.updatedAt}
                      className="text-muted-foreground text-xs tabular-nums"
                    />
                  </TableCell>
                  <TableCell className="p-0">
                    <button
                      onClick={() => setDeleteTarget({ name: secret.name })}
                      className="text-muted-foreground hover:text-destructive cursor-pointer"
                      title="Delete secret"
                    >
                      <TrashIcon className="size-3.5" />
                    </button>
                  </TableCell>
                </TableRow>
              );
            })}
            {/* Missing keys: exist in other envs but not this one */}
            {missingKeys.map((name) => {
              const hasValue = missingEdits[name]?.trim();
              return (
                <TableRow key={`missing-${name}`} className="bg-destructive/5 dark:bg-destructive/10">
                  <TableCell className="min-w-0 whitespace-normal">
                    <span className="block break-all px-1.5 mono-sm text-sm font-medium text-destructive">
                      {name}
                    </span>
                  </TableCell>
                  <TableCell className="min-w-0 overflow-hidden">
                    <Input
                      type="text"
                      inputSize="sm"
                      autoComplete="off"
                      data-1p-ignore
                      data-lpignore="true"
                      placeholder="Missing — add a value"
                      value={missingEdits[name] ?? ""}
                      onChange={(e) => setMissingEdits((prev) => ({ ...prev, [name]: e.target.value }))}
                       className={cn(
                         "w-full min-w-0 mono-sm border-destructive/40",
                         hasValue ? "bg-amber-50/50 dark:bg-amber-950/20" : "text-security-disc bg-transparent",
                       )}
                     />
                   </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <span className="text-destructive text-xs">missing</span>
                  </TableCell>
                  <TableCell />
                </TableRow>
              );
            })}
            {newSecrets.map((secret) => {
              const isComplete = secret.name.trim() && secret.value.trim();
              return (
                <TableRow
                  key={secret.id}
                  className={cn(
                    "bg-primary/5 dark:bg-primary/10",
                    isComplete && "bg-amber-50/50 dark:bg-amber-950/20",
                  )}
                >
                  <TableCell className="min-w-0 overflow-hidden">
                    <Input
                      type="text"
                      inputSize="sm"
                      autoFocus={newSecrets.length === 1}
                      value={secret.name}
                      onChange={(e) => updateNewSecret(secret.id, "name", e.target.value)}
                      placeholder="SECRET_KEY"
                      className="w-full min-w-0 border-transparent bg-transparent px-1.5 mono-sm font-medium focus:border-input hover:border-input"
                    />
                  </TableCell>
                  <TableCell className="min-w-0 overflow-hidden">
                    <Input
                      type="text"
                      inputSize="sm"
                      autoComplete="off"
                      data-1p-ignore
                      data-lpignore="true"
                      value={secret.value}
                      onChange={(e) => updateNewSecret(secret.id, "value", e.target.value)}
                      placeholder="secret value"
                      className="w-full min-w-0 border-transparent bg-transparent px-1.5 mono-sm focus:border-input hover:border-input"
                    />
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <span className="text-xs text-muted-foreground">new</span>
                  </TableCell>
                  <TableCell className="p-0">
                    <button
                      onClick={() => removeNewSecret(secret.id)}
                      className="text-muted-foreground hover:text-destructive cursor-pointer"
                      title="Remove draft secret"
                    >
                      <TrashIcon className="size-3.5" />
                    </button>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
        </div>

        {/* Bottom bar: add secret + import */}
        <div className="flex flex-wrap items-center gap-2 px-1 pb-2">
          <Button onClick={addNewSecret} size="xs">
            <PlusIcon className="size-3" />
            Add Secret
          </Button>
          {missingKeys.length > 0 && (
            <Button
              onClick={() => setSyncOpen(true)}
              size="xs"
              variant="ghost"
            >
              <ArrowDownToLineIcon className="size-3" />
              Sync {missingKeys.length} missing
            </Button>
          )}
          <div className="flex-1" />
          <Button
            onClick={() => setImportOpen(true)}
            size="xs"
            variant="ghost"
          >
            <UploadIcon className="size-3" />
            Import .env
          </Button>
          <Button
            onClick={() => void handleDownloadEnv()}
            size="xs"
            variant="ghost"
          >
            <DownloadIcon className="size-3" />
            Download .env
          </Button>
          <Button
            onClick={() => void handleCopyEnv()}
            size="xs"
            variant="ghost"
          >
            <CopyIcon className="size-3" />
            Copy as .env
          </Button>
        </div>
      </Frame>

      <ImportEnvDialog open={importOpen} onOpenChange={setImportOpen} importing={importing} onImport={handleImportText} />

      <SyncMissingDialog
        open={syncOpen}
        onOpenChange={setSyncOpen}
        missingKeys={missingKeys}
        environments={environments}
        currentEnvironmentId={environmentId}
      />

      {deleteTarget && (
        <DeleteFromEnvsDialog
          open
          onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
          secretName={deleteTarget.name}
          environments={environments}
          currentEnvId={environmentId}
        />
      )}

      <SaveToEnvsDialog
        open={saveOpen}
        onOpenChange={setSaveOpen}
        environments={environments}
        currentEnvId={environmentId}
        dirtyCount={totalDirtyCount}
        saving={saving}
        onSave={async (envIds) => {
          setSaving(true);
          try {
            // Copying a kept value out of a protected environment asks for the passkey
            if (pendingEdits.length > 0 && await withStepUp(() => saveSecretsAction({ edits: pendingEdits, environmentIds: envIds })) === null) {
              return;
            }
            setEdits({});
            setMissingEdits({});
            setNewSecrets([]);
            setSaveOpen(false);
          } catch (e: any) {
            alert(e?.message || "Failed to save secrets");
          } finally {
            setSaving(false);
          }
        }}
      />

      {/* Save bar */}
      {totalDirtyCount > 0 && (
        <div className="flex justify-end mt-3">
          <Button onClick={() => setSaveOpen(true)}>
            Save {totalDirtyCount} secret{totalDirtyCount > 1 ? "s" : ""}
          </Button>
        </div>
      )}
    </>
  );
}

const importEnvSchema = z.object({ envText: z.string().min(1, "Paste your .env contents") });
const importEnvFields = importEnvSchema.keyof().enum;

function ImportEnvDialog({
  open,
  onOpenChange,
  importing,
  onImport,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  importing: boolean;
  onImport: (text: string) => Promise<void>;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Import .env</DialogTitle>
          <DialogDescription>
            Paste your .env file contents below. Each line should be in KEY=value format.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2"
          action={async (formData: FormData) => {
            const { envText } = parseFormData(importEnvSchema, formData);
            if (envText.trim()) await onImport(envText);
          }}
        >
          <Textarea
            name={importEnvFields.envText}
            required
            autoFocus
            placeholder={"DATABASE_URL=postgres://...\nAPI_KEY=sk-...\nSECRET_TOKEN=abc123"}
            rows={8}
            className="mono-sm"
          />
          <DialogFooter variant="bare" className="mt-4">
            <DialogClose render={<Button variant="outline" />}>
              Cancel
            </DialogClose>
            <Button type="submit">
              Import
            </Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  );
}

// Shared environment checkbox list used by save and delete dialogs.
// Current env is always checked and disabled, others are toggleable.
function useEnvSelection(environments: Environment[], currentEnvId: string) {
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const toggle = (id: string) => setChecked((prev) => ({ ...prev, [id]: !prev[id] }));
  const selectedIds = [
    currentEnvId,
    ...environments.filter((e) => e.id !== currentEnvId && checked[e.id]).map((e) => e.id),
  ];
  return { checked, toggle, selectedIds };
}

function EnvCheckboxList({
  environments,
  currentEnvId,
  checked,
  onToggle,
}: {
  environments: Environment[];
  currentEnvId: string;
  checked: Record<string, boolean>;
  onToggle: (id: string) => void;
}) {
  return (
    <div className="px-6 pb-2 flex flex-col gap-1.5">
      {environments.map((env) => {
        const isCurrent = env.id === currentEnvId;
        const isChecked = isCurrent || (checked[env.id] ?? false);
        return (
          <label
            key={env.id}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer transition-colors",
              isChecked ? "bg-primary/5" : "hover:bg-muted/50",
              isCurrent && "opacity-80",
            )}
          >
            <span
              className={cn(
                "flex items-center justify-center size-4 rounded border transition-colors",
                isChecked ? "bg-primary border-primary text-primary-foreground" : "border-input",
              )}
              aria-hidden
            >
              {isChecked && <CheckIcon className="size-3" />}
            </span>
            <input
              type="checkbox"
              checked={isChecked}
              disabled={isCurrent}
              onChange={() => onToggle(env.id)}
              className="sr-only"
            />
            <span className="text-sm font-medium">{env.name}</span>
            {isCurrent && <span className="text-xs text-muted-foreground ml-auto">current</span>}
          </label>
        );
      })}
    </div>
  );
}

function DeleteFromEnvsDialog({
  open,
  onOpenChange,
  secretName,
  environments,
  currentEnvId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  secretName: string;
  environments: Environment[];
  currentEnvId: string;
}) {
  const { checked, toggle, selectedIds } = useEnvSelection(environments, currentEnvId);
  const [deleting, setDeleting] = useState(false);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Delete "{secretName}"</DialogTitle>
          <DialogDescription>
            Choose which environments to remove this secret from.
          </DialogDescription>
        </DialogHeader>
        <EnvCheckboxList environments={environments} currentEnvId={currentEnvId} checked={checked} onToggle={toggle} />
        <DialogFooter variant="bare" className="px-6 pb-4 pt-2">
          <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
          <Button
            variant="destructive"
            loading={deleting}
            onClick={async () => {
              setDeleting(true);
              try {
                if (await withStepUp(() => deleteSecretAction({ name: secretName, environmentIds: selectedIds }))) onOpenChange(false);
              } catch (e: any) {
                alert(e?.message || "Failed to delete secret");
              } finally {
                setDeleting(false);
              }
            }}
          >
            Delete from {selectedIds.length} environment{selectedIds.length > 1 ? "s" : ""}
          </Button>
        </DialogFooter>
      </DialogPopup>
    </Dialog>
  );
}

function SaveToEnvsDialog({
  open,
  onOpenChange,
  environments,
  currentEnvId,
  dirtyCount,
  saving,
  onSave,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  environments: Environment[];
  currentEnvId: string;
  dirtyCount: number;
  saving: boolean;
  onSave: (envIds: string[]) => Promise<void>;
}) {
  const { checked, toggle, selectedIds } = useEnvSelection(environments, currentEnvId);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Save {dirtyCount} secret{dirtyCount > 1 ? "s" : ""}</DialogTitle>
          <DialogDescription>
            Choose which environments to apply the changes to.
            Secrets are matched by name — missing keys will be created.
          </DialogDescription>
        </DialogHeader>
        <EnvCheckboxList environments={environments} currentEnvId={currentEnvId} checked={checked} onToggle={toggle} />
        <DialogFooter variant="bare" className="px-6 pb-4 pt-2">
          <DialogClose render={<Button variant="outline" />}>Cancel</DialogClose>
          <Button loading={saving} onClick={() => onSave(selectedIds)}>
            Save to {selectedIds.length} environment{selectedIds.length > 1 ? "s" : ""}
          </Button>
        </DialogFooter>
      </DialogPopup>
    </Dialog>
  );
}

const syncSchema = z.object({ sourceEnvironmentId: z.string().min(1, "Select an environment") });
const syncFields = syncSchema.keyof().enum;

function SyncMissingDialog({
  open,
  onOpenChange,
  missingKeys,
  environments,
  currentEnvironmentId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  missingKeys: string[];
  environments: Environment[];
  currentEnvironmentId: string;
}) {
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function handleOpenChange(open: boolean) {
    if (!open) setError(null);
    onOpenChange(open);
  }

  const otherEnvironments = environments.filter((e) => e.id !== currentEnvironmentId);

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>Sync missing secrets</DialogTitle>
          <DialogDescription>
            Copy {missingKeys.length} missing secret{missingKeys.length > 1 ? "s" : ""} from another environment into this one.
          </DialogDescription>
        </DialogHeader>
        <form
          className="px-6 pb-2"
          action={async (formData: FormData) => {
            const { sourceEnvironmentId } = parseFormData(syncSchema, formData);
            setSyncing(true);
            setError(null);
            try {
              const result = await withStepUp(() => syncMissingSecretsAction({
                sourceEnvironmentId,
                targetEnvironmentId: currentEnvironmentId,
                names: missingKeys,
              }));
              if (!result) return;
              if (result.count === 0) {
                setError("That environment doesn't have any of the missing secrets.");
              } else {
                handleOpenChange(false);
              }
            } catch (e: any) {
              setError(e?.message || "Failed to sync secrets");
            } finally {
              setSyncing(false);
            }
          }}
        >
          {error && <p className="text-sm text-destructive mb-3">{error}</p>}
          <div>
            <label htmlFor="sync-source-env" className="text-sm font-medium mb-1 block">
              Source environment
            </label>
            <NativeSelect id="sync-source-env" name={syncFields.sourceEnvironmentId} required autoFocus>
              <option value="">Select an environment…</option>
              {otherEnvironments.map((env) => (
                <option key={env.id} value={env.id}>{env.name}</option>
              ))}
            </NativeSelect>
            <p className="text-xs text-muted-foreground mt-2">
              Only the {missingKeys.length} missing key{missingKeys.length > 1 ? "s" : ""} will be copied. Existing secrets are not affected.
            </p>
          </div>
          <DialogFooter variant="bare" className="mt-4">
            <DialogClose render={<Button variant="outline" />}>
              Cancel
            </DialogClose>
            <Button type="submit" loading={syncing}>
              Sync from environment
            </Button>
          </DialogFooter>
        </form>
      </DialogPopup>
    </Dialog>
  );
}
