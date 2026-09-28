// The field for a login or approval code. It shows the code as XXXX-XXXX
// while you type or paste it, so it reads the same as in your terminal.

"use client";

import type * as React from "react";
import { Input } from "sigillo-app/src/components/ui/input";
import { formatUserCode } from "sigillo-app/src/lib/utils";

export function CodeInput(props: React.ComponentProps<typeof Input>): React.ReactElement {
  return (
    <Input
      autoComplete="off"
      autoCapitalize="characters"
      spellCheck={false}
      maxLength={12}
      className="h-12 text-center text-2xl mono-sm tracking-[0.25em]"
      onInput={(event) => {
        const input = event.currentTarget;
        // Keeps the caret after the same letter it followed
        const caret = formatUserCode(input.value.slice(0, input.selectionStart ?? input.value.length)).length;
        input.value = formatUserCode(input.value);
        input.setSelectionRange(caret, caret);
      }}
      {...props}
    />
  );
}
