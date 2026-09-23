<script lang="ts">
  // Bottom sheet over the screen: forms, logs, share.
  import type { Snippet } from "svelte";
  let { title, onclose, children }: { title: string; onclose?: () => void; children: Snippet } = $props();
</script>

<div class="backdrop" role="presentation" onclick={() => onclose?.()}></div>
<div class="sheet" role="dialog" aria-label={title}>
  <header class="row">
    <h1 class="grow">{title}</h1>
    {#if onclose}<button class="close" onclick={onclose} aria-label="Закрыть">✕</button>{/if}
  </header>
  {@render children()}
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, .45); z-index: 10; }
  .sheet {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 11; max-height: 88vh; overflow-y: auto;
    max-width: 560px; margin: 0 auto; background: var(--bg); border-radius: 20px 20px 0 0;
    padding: 18px 16px 24px; display: flex; flex-direction: column; gap: 14px; border-top: 1px solid var(--border);
  }
  h1 { font-size: 19px; }
  .close { color: var(--muted); font-size: 18px; padding: 4px 8px; }
</style>
