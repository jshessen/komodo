import { ICONS } from "@/lib/icons";
import {
  ActionIcon,
  Button,
  Group,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { Types } from "komodo_client";
import { MonacoEditor, languageFromPath } from "mogh_ui";

export default function StackInlineFiles({
  stackId,
  value,
  primary,
  envFile,
  set,
  disabled,
}: {
  stackId: string;
  value: Types.FileContents[] | undefined;
  primary: string;
  envFile: string;
  set: (value: Partial<Types.StackConfig>) => void;
  disabled: boolean;
}) {
  const files = value ?? [];
  return (
    <Stack>
      <Text c="dimmed" fz="sm">
        Supply local include, environment, or auxiliary files here. Companions
        are not additional Compose roots. Paths are relative to the managed
        stack directory; include paths remain relative to their including file.
      </Text>
      {files.map((file, index) => {
        const parts = file.path.split("/");
        const invalid =
          !file.path ||
          /[\0\\:]/.test(file.path) ||
          parts.some((part) => ["", ".", "..", ".git"].includes(part));
        const collision = [
          primary,
          envFile,
          ".komodo-inline-files.json",
          ...files
            .filter((_, other) => other !== index)
            .map((file) => file.path),
        ].some(
          (other) =>
            file.path === other ||
            file.path.startsWith(`${other}/`) ||
            other.startsWith(`${file.path}/`),
        );
        return (
          <Stack key={index} gap="xs">
            <Group align="flex-start">
              <TextInput
                label={`Companion ${index + 1} path`}
                placeholder="modules/compose.yaml"
                value={file.path}
                disabled={disabled}
                error={
                  invalid
                    ? "Use a normalized relative path without traversal."
                    : collision
                      ? "Path collides with another source or managed file."
                      : undefined
                }
                onChange={(event) =>
                  set({
                    inline_files: files.map((file, other) =>
                      other === index
                        ? { ...file, path: event.target.value }
                        : file,
                    ),
                  })
                }
                flex={1}
              />
              {!disabled && (
                <ActionIcon
                  aria-label={`Remove companion ${index + 1}`}
                  color="red"
                  mt={30}
                  onClick={() =>
                    set({
                      inline_files: files.filter((_, other) => other !== index),
                    })
                  }
                >
                  <ICONS.Remove size="1rem" />
                </ActionIcon>
              )}
            </Group>
            <MonacoEditor
              value={file.contents}
              filename={`stack-${stackId}-companion-${index + 1}`}
              language={languageFromPath(file.path)}
              readOnly={disabled}
              onValueChange={(contents) =>
                set({
                  inline_files: files.map((file, other) =>
                    other === index ? { ...file, contents } : file,
                  ),
                })
              }
            />
          </Stack>
        );
      })}
      {!disabled && (
        <Button
          leftSection={<ICONS.Add size="1rem" />}
          disabled={files.length >= 511}
          onClick={() =>
            set({
              inline_files: [...files, { path: "", contents: "" }],
            })
          }
          w="fit-content"
        >
          Add Companion File
        </Button>
      )}
    </Stack>
  );
}
