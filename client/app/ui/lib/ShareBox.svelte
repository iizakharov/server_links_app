<script lang="ts">
  import Icon from "./Icon.svelte";
  import { errorText, saveFile, writeClipboard, type Share } from "./api";

  let { data }: { data: Share } = $props();
  let mode = $state<"key" | "conf">("key");
  let copied = $state(false);
  let error = $state("");

  const text = $derived(mode === "key" ? data.vpn_key : data.conf);
  async function copy() {
    await writeClipboard(text);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
  async function save() {
    const base = data.name.replace(/[^\p{L}\p{N}_-]+/gu, "_");
    try { await saveFile(mode === "key" ? `${base}.vpn.txt` : `${base}.conf`, text); } catch (e) { error = errorText(e); }
  }
</script>

<div class="segmented">
  <button class:on={mode === "key"} onclick={() => (mode = "key")}>Ключ vpn://</button>
  <button class:on={mode === "conf"} onclick={() => (mode = "conf")}>Файл .conf</button>
</div>
{#if mode === "key"}
  <div class="qr">{@html data.qr_svg}</div>
  <p class="small muted center">Отсканируйте в AmneziaVPN или АМнеЗинуVPN на телефоне</p>
{:else}
  <pre class="card mono conf">{data.conf}</pre>
{/if}
<div class="row">
  <button class="btn grow" onclick={copy}><Icon name={copied ? "check" : "copy"} size={18} /> {copied ? "Скопировано" : "Копировать"}</button>
  <button class="btn grow" onclick={save}><Icon name="download" size={18} /> Сохранить</button>
</div>
<p class="small muted">Ключ даёт доступ к VPN. Отправляйте его только тем, кому доверяете: одним ключом нельзя пользоваться на двух устройствах одновременно.</p>
{#if error}<p class="error">{error}</p>{/if}

<style>
  .qr { background: #fff; border-radius: var(--radius); padding: 12px; align-self: center; width: min(100%, 300px); aspect-ratio: 1; }
  .qr :global(svg) { width: 100%; height: 100%; display: block; }
  .center { text-align: center; }
  .conf { margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto; user-select: text; }
</style>
