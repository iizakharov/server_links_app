<script lang="ts">
  import Icon from "../lib/Icon.svelte";
  import { api, errorText } from "../lib/api";
  import { app, refreshView } from "../lib/store.svelte";

  let open = $state<string | null>(null);
  let renaming = $state<string | null>(null);
  let newName = $state("");
  let confirmDelete = $state<string | null>(null);
  let error = $state("");

  async function run(f: () => Promise<unknown>) {
    error = "";
    try { await f(); await refreshView(); } catch (e) { error = errorText(e); }
  }
  const select = (id: string) => run(() => api.select(id));
  const rename = (id: string) => run(async () => { await api.rename(id, newName); renaming = null; });
  const remove = (id: string) => run(async () => { await api.remove(id); confirmDelete = null; open = null; });
  function share(id: string) { app.shareId = id; app.tab = "share"; }
</script>

<section class="screen">
  <header class="row">
    <h1 class="grow">Серверы</h1>
    <button class="btn primary" onclick={() => (app.tab = "add")}><Icon name="plus" size={18} /> Добавить</button>
  </header>

  {#if app.view.profiles.length === 0}
    <div class="card empty">
      <p><b>Пока нет ни одного сервера</b></p>
      <p class="small muted">Добавьте ключ vpn:// из AmneziaVPN или панели каскадов, либо файл .conf.</p>
    </div>
  {/if}

  <ul>
    {#each app.view.profiles as p (p.id)}
      {@const active = app.view.selected === p.id}
      {@const connectedHere = app.status?.connected && app.status.name === p.title}
      <li class="card" class:active>
        <div class="row">
          <button class="radio" class:on={active} onclick={() => select(p.id)} aria-label="Выбрать {p.name}">
            {#if active}<Icon name="check" size={14} />{/if}
          </button>
          <button class="grow info" onclick={() => select(p.id)}>
            <span class="name ellipsis">{p.name}{#if p.exit}<span class="muted"> · {p.exit}</span>{/if}</span>
            <span class="small muted ellipsis">{p.endpoint} · {p.address}</span>
          </button>
          <span class="tag">AWG {p.awg_version}</span>
          <button class="more" onclick={() => (open = open === p.id ? null : p.id)} aria-label="Действия">
            <Icon name="chevron" size={18} />
          </button>
        </div>
        {#if connectedHere}<p class="small live">● подключено сейчас</p>{/if}

        {#if open === p.id}
          <div class="actions">
            {#if renaming === p.id}
              <div class="row">
                <input bind:value={newName} placeholder="Название" />
                <button class="btn primary" onclick={() => rename(p.id)} disabled={!newName.trim()}>OK</button>
              </div>
            {:else if confirmDelete === p.id}
              <p class="small">Удалить «{p.name}» с этого устройства? Доступ на сервере при этом не отзывается.</p>
              <div class="row">
                <button class="btn grow" onclick={() => (confirmDelete = null)}>Отмена</button>
                <button class="btn danger grow" onclick={() => remove(p.id)}>Удалить</button>
              </div>
            {:else}
              <div class="row">
                <button class="btn grow" onclick={() => share(p.id)}><Icon name="share" size={18} /> Поделиться</button>
                <button class="btn" onclick={() => { renaming = p.id; newName = p.name; }} aria-label="Переименовать"><Icon name="edit" size={18} /></button>
                <button class="btn danger" onclick={() => (confirmDelete = p.id)} aria-label="Удалить"
                        disabled={connectedHere}><Icon name="trash" size={18} /></button>
              </div>
            {/if}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
  {#if error}<p class="error">{error}</p>{/if}
</section>

<style>
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  li.active { border-color: var(--accent); }
  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--border); display: grid; place-items: center; flex: none; }
  .radio.on { background: var(--accent-grad); border-color: transparent; color: var(--on-accent); }
  .info { text-align: left; }
  .info .name { display: block; font-weight: 600; }
  .info .small { display: block; }
  .more { color: var(--muted); padding: 6px; }
  .actions { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 10px; }
  .live { color: var(--ok); margin-top: 6px; margin-left: 34px; }
  .empty { display: flex; flex-direction: column; gap: 4px; }
</style>
