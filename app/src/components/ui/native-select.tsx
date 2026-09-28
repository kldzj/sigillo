// Native select wrapper that matches the shared select trigger styling.

"use client";

import { ChevronsUpDownIcon } from "lucide-react";
import type * as React from "react";
import { cn } from "sigillo-app/src/lib/utils";

export function NativeSelect({
  children,
  className,
  size = "default",
  ...props
}: Omit<React.ComponentProps<"select">, "size"> & {
  size?: "sm" | "default";
}): React.ReactElement {
  return (
    <div
      className={cn(
        "group/native-select relative w-fit max-w-full has-[select:disabled]:opacity-50",
        className,
      )}
      data-slot="native-select-wrapper"
      data-size={size}
    >
      <select
        data-slot="native-select"
        data-size={size}
        className={cn(
          "h-8 w-full min-w-0 appearance-none rounded-lg border border-input bg-background py-0 pr-8 pl-2.5 text-sm text-foreground outline-none transition-colors",
          "focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50",
          "disabled:pointer-events-none disabled:cursor-not-allowed",
          "dark:bg-input/32",
          size === "sm" && "h-7 text-xs",
        )}
        {...props}
      >
        {children}
      </select>
      <ChevronsUpDownIcon className="pointer-events-none absolute top-1/2 right-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
    </div>
  );
}
