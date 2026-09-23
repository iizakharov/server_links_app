<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import { api, errorText, saveFile, writeClipboard, type Share } from "../lib/api";
  import { app } from "../lib/store.svelte";

  let mode = $state<"key" | "conf">("key");
  let data = $state<Share | null>(null);
  let error = $state("");
  let copied = $state(false);

  const id = $derived(app.shareId ?? app.view.selected ?? app.view.profiles[0]?.id ?? null);

  $effect(() => {
    const current = id;
    data = null; error = "";
    if (current) api.share(current).then((d) => (data = d)).catch((e) => (error = errorText(e)));
  });

  const text = $derived(data ? (mode === "key" ? data.vpn_key : data.conf) : "");
  async function copy() {
    await writeClipboard(text);
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
  function fileName() {
    const base = (data?.name ?? "vpn").replace(/[^\p{L}\p{N}_-]+/gu, "_");
    return mode === "key" ? `${base}.vpn.txt` : `${base}.conf`;
  }
  async function save() {
    try { await saveFile(fileName(), text); } catch (e) { error = errorText(e); }
  }
</script>

<section class="screen">
  <h1>Поделиться</h1>

  {#if app.view.profiles.length === 0}
    <p class="muted">Сначала добавьте сервер.</p>
  {:else}
    <label class="col">
      <h2>Сервер</h2>
      <select value={id} onchange={(e) => (app.shareId = (e.target as HTMLSelectElement).value)}>
        {#each app.view.profiles as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
      </select>
    </label>

    <div class="segmented">
      <button class:on={mode === "key"} onclick={() => (mode = "key")}>Ключ vpn://</button>
      <button class:on={mode === "conf"} onclick={() => (mode = "conf")}>Файл .conf</button>
    </div>

    {#if data}
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
    {/if}
    {#if error}<p class="error">{error}</p>{/if}
  {/if}
</section>

<style>
  .col { display: flex; flex-direction: column; }
  select {
    font: inherit; color: var(--text); background: var(--surface-2); border: 1px solid var(--border);
    border-radius: 12px; padding: 11px 12px;
  }
  .qr { background: #fff; border-radius: var(--radius); padding: 12px; align-self: center; width: min(100%, 300px); aspect-ratio: 1; }
  .qr :global(svg) { width: 100%; height: 100%; display: block; }
  .center { text-align: center; }
  .conf { margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 320px; overflow: auto; user-select: text; }
</style>
