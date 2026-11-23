import { useEffect, useRef } from "react";
import {
  DiffEditor as UpstreamDiffEditor,
  type DiffEditorProps,
} from "@monaco-editor/react/dist/index";
import type { editor } from "monaco-editor";

export { default } from "@monaco-editor/react/dist/index";
export * from "@monaco-editor/react/dist/index";

export function DiffEditor(props: DiffEditorProps) {
  const instance = useRef<editor.IStandaloneDiffEditor | null>(null);
  const currentProps = useRef(props);
  currentProps.current = props;

  useEffect(
    () => () => {
      const diff = instance.current;
      const models = diff?.getModel();
      if (!diff || !models) return;
      // Detach first: Monaco rejects disposing models still attached to a diff editor.
      diff.setModel(null);
      if (!currentProps.current.keepCurrentOriginalModel) {
        models.original.dispose();
      }
      if (!currentProps.current.keepCurrentModifiedModel) {
        models.modified.dispose();
      }
    },
    [],
  );

  return (
    <UpstreamDiffEditor
      {...props}
      onMount={(diff, monaco) => {
        instance.current = diff;
        props.onMount?.(diff, monaco);
      }}
    />
  );
}
