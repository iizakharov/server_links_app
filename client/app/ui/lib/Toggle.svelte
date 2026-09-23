<script lang="ts">
  let { checked, disabled = false, label, hint = "", onchange }:
    { checked: boolean; disabled?: boolean; label: string; hint?: string; onchange: (v: boolean) => void } = $props();
</script>

<label class="toggle" class:disabled>
  <span class="grow">
    <span class="label">{label}</span>
    {#if hint}<span class="small muted hint">{hint}</span>{/if}
  </span>
  <input type="checkbox" {checked} {disabled} onchange={(e) => onchange((e.target as HTMLInputElement).checked)} />
  <span class="switch" aria-hidden="true"></span>
</label>

<style>
  .toggle { display: flex; align-items: center; gap: 12px; cursor: pointer; }
  .toggle.disabled { opacity: .5; cursor: default; }
  .label { display: block; font-weight: 560; }
  .hint { display: block; margin-top: 2px; }
  input { position: absolute; opacity: 0; width: 0; height: 0; }
  .switch { flex: none; width: 44px; height: 26px; border-radius: 13px; background: var(--surface-2); border: 1px solid var(--border); position: relative; transition: background .2s; }
  .switch::after { content: ""; position: absolute; top: 2px; left: 2px; width: 20px; height: 20px; border-radius: 50%; background: var(--muted); transition: transform .2s, background .2s; }
  input:checked + .switch { background: var(--accent-grad); border-color: transparent; }
  input:checked + .switch::after { transform: translateX(18px); background: #fff; }
  input:focus-visible + .switch { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>
