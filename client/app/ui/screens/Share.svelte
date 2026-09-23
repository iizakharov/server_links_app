<script lang="ts">
  import ShareBox from "../lib/ShareBox.svelte";
  import { api, errorText, type Share } from "../lib/api";
  import { app } from "../lib/store.svelte";

  let data = $state<Share | null>(null);
  let error = $state("");
  const id = $derived(app.shareId ?? app.view.selected ?? app.view.profiles[0]?.id ?? null);

  $effect(() => {
    const current = id;
    data = null; error = "";
    if (current) api.share(current).then((d) => (data = d)).catch((e) => (error = errorText(e)));
  });
</script>

<section class="screen">
  <h1>Поделиться</h1>
  {#if app.view.profiles.length === 0}
    <p class="muted">Сначала добавьте сервер.</p>
  {:else}
    <label class="col">
      <h2>Сервер</h2>
      <select value={id} onchange={(e) => (app.shareId = (e.target as HTMLSelectElement).value)}>
        {#each app.view.profiles as p (p.id)}<option value={p.id}>{p.title}</option>{/each}
      </select>
    </label>
    {#if data}<ShareBox {data} />{/if}
    {#if error}<p class="error">{error}</p>{/if}
  {/if}
</section>

<style>
  .col { display: flex; flex-direction: column; }
  select {
    font: inherit; color: var(--text); background: var(--surface-2); border: 1px solid var(--border);
    border-radius: 12px; padding: 11px 12px; appearance: none;
  }
</style>
