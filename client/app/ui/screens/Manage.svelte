<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "../lib/Icon.svelte";
  import Sheet from "../lib/Sheet.svelte";
  import ShareBox from "../lib/ShareBox.svelte";
  import { bytes, errorText, manage, onManageLog, pickFile, secretStore, type ManageView, type MServer, type OpLog, type ServerIn, type Share } from "../lib/api";
  import { app, refreshView } from "../lib/store.svelte";

  let v = $state<ManageView>({ servers: [], cascades: [], external: [], clients: [], busy: false });
  let section = $state<"servers" | "cascades" | "clients">("servers");
  let error = $state("");

  // operation in progress / finished: live log
  let op = $state<{ title: string; lines: string[]; done: boolean; ok: boolean } | null>(null);
  let serverForm = $state<ServerIn | null>(null);
  let cascadeForm = $state<{ proxy_id: string; exit_ids: string[]; instance: string; port: string } | null>(null);
  let clientForm = $state<{ name: string; cascade_ids: string[] } | null>(null);
  let shareData = $state<Share | null>(null);
  let confirm = $state<{ text: string; action: () => void } | null>(null);

  const name = (id: string) => v.servers.find((s) => s.id === id)?.name ?? "?";
  const route = (c: { proxy_id: string; exit_id: string; mode?: string }) =>
    c.mode === "direct" ? `${name(c.exit_id)} (напрямую)` : `${name(c.proxy_id)} → ${name(c.exit_id)}`;
  const cascadeLabel = (id: string) => {
    const c = v.cascades.find((c) => c.id === id);
    return c ? route(c) : "каскад удалён";
  };
  const statusText: Record<string, string> = {
    applied: "работает", missing: "нет правила на прокси", conflict: "конфликт порта", unknown: "прокси не сканирован", external: "существующий", direct: "напрямую",
  };
  const instanceText: Record<string, string> = { main: "основной", legacy: "1.0", v2: "2.0", v3: "3.x" };

  async function load() {
    try { v = await manage.view(); } catch (e) { error = errorText(e); }
  }
  onMount(() => {
    load();
    let off = () => {};
    onManageLog((line) => op?.lines.push(line)).then((f) => (off = f));
    return () => off();
  });

  /** Runs an operation with the live log sheet. */
  async function run(title: string, f: () => Promise<OpLog | string | unknown>) {
    error = "";
    op = { title, lines: [], done: false, ok: false };
    try {
      const r = await f();
      if (r && typeof r === "object" && "log" in r) {
        const res = r as OpLog;
        if (op.lines.length === 0) op.lines.push(...res.log);
        op.ok = res.ok;
      } else {
        if (typeof r === "string") op.lines.push(r);
        op.ok = true;
      }
    } catch (e) {
      op.lines.push("ОШИБКА: " + errorText(e));
      op.ok = false;
    }
    op.done = true;
    await load();
  }

  function editServer(s?: MServer) {
    serverForm = s
      ? { id: s.id, name: s.name, host: s.host, ssh_port: s.ssh_port, user: s.user, password: "", key_path: s.key_path }
      : { id: null, name: "", host: "", ssh_port: 22, user: "root", password: "", key_path: "" };
  }
  async function saveServer() {
    const f = serverForm!;
    try {
      const id = await manage.saveServer(f);
      serverForm = null;
      await load();
      if (!f.id) run(`Сканирование ${f.name || f.host}`, () => manage.scan(id));
    } catch (e) { error = errorText(e); }
  }
  async function createCascade() {
    const f = cascadeForm!;
    cascadeForm = null;
    if (!f.proxy_id) {
      // no proxy: the device connects straight to each exit
      await run("Прямое подключение", async () => {
        const logs: string[] = [];
        for (const id of f.exit_ids) {
          const r = await manage.direct(id, f.instance);
          logs.push(...r.log);
          if (!r.ok) return { ok: false, log: logs };
        }
        return { ok: true, log: logs };
      });
      return;
    }
    await run("Создание каскада", () => manage.createCascades({
      proxy_id: f.proxy_id, exit_ids: f.exit_ids, instance: f.instance, port: f.port ? Number(f.port) : null,
    }));
  }
  async function createClient() {
    const f = clientForm!;
    clientForm = null;
    await run(`Клиент ${f.name}`, async () => {
      const ids = await manage.createClient(f.name, f.cascade_ids);
      return `Создано ключей: ${ids.length}`;
    });
    section = "clients";
  }
  async function toDevice(id: string) {
    try {
      app.view = await manage.toDevice(id);
      await refreshView();
      app.tab = "home";
    } catch (e) { error = errorText(e); }
  }
  async function share(id: string) {
    try { shareData = await manage.share(id); } catch (e) { error = errorText(e); }
  }
  async function importPanel() {
    const path = await pickFile([{ name: "state.json", extensions: ["json"] }]);
    if (path) run("Импорт из панели", async () => `Импортировано серверов: ${await manage.importPanel(path)}`);
  }
  function ago(ts: number | null) {
    if (!ts) return "не подключался";
    const s = Math.floor(Date.now() / 1000) - ts;
    if (s < 180) return "онлайн";
    if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
    if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
    return `${Math.floor(s / 86400)} дн назад`;
  }
  const toggle = (list: string[], id: string) => (list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);
</script>

<section class="screen">
  <header class="row">
    <h1 class="grow">Управление</h1>
    {#if section === "servers"}
      <button class="btn primary" onclick={() => editServer()}><Icon name="plus" size={18} /> Сервер</button>
    {:else if section === "cascades"}
      <button class="btn primary" disabled={v.servers.length < 2}
              onclick={() => (cascadeForm = { proxy_id: v.servers[0]?.id ?? "", exit_ids: [], instance: "auto", port: "" })}>
        <Icon name="plus" size={18} /> Каскад</button>
    {:else}
      <button class="btn primary" disabled={v.cascades.length === 0}
              onclick={() => (clientForm = { name: "", cascade_ids: [] })}><Icon name="plus" size={18} /> Клиент</button>
    {/if}
  </header>

  <div class="segmented">
    <button class:on={section === "servers"} onclick={() => (section = "servers")}>Серверы {v.servers.length}</button>
    <button class:on={section === "cascades"} onclick={() => (section = "cascades")}>Каскады {v.cascades.length}</button>
    <button class:on={section === "clients"} onclick={() => (section = "clients")}>Клиенты {v.clients.length}</button>
  </div>
  {#if error}<p class="error">{error}</p>{/if}

  {#if section === "servers"}
    {#if v.servers.length === 0}
      <div class="card col">
        <p><b>Свои серверы</b></p>
        <p class="small muted">Добавьте серверы по SSH: приложение установит AmneziaWG нужной версии, соберёт каскады и выдаст ключи. Уже пользуетесь панелью каскадов — перенесите её данные.</p>
        <button class="btn" onclick={importPanel}><Icon name="file" size={18} /> Импорт из панели (state.json)</button>
      </div>
    {/if}
    <ul>
      {#each v.servers as s (s.id)}
        <li class="card col">
          <div class="row">
            <div class="grow">
              <p class="name ellipsis">{s.name}</p>
              <p class="small muted ellipsis">{s.user}@{s.host}:{s.ssh_port} · {s.os || "не сканирован"}</p>
            </div>
          </div>
          {#if s.awg.length}
            <p class="tags">{#each s.awg as a}<span class="tag">AWG {a.version} · {instanceText[a.instance]} · UDP {a.port}</span>{/each}</p>
          {/if}
          {#if s.forwards.length}<p class="small muted">Чужие пробросы: {s.forwards.length}</p>{/if}
          <div class="row">
            <button class="btn grow" onclick={() => run(`Сканирование ${s.name}`, () => manage.scan(s.id))}><Icon name="scan" size={18} /> Сканировать</button>
            <button class="btn" onclick={() => editServer(s)} aria-label="Изменить"><Icon name="edit" size={18} /></button>
            <button class="btn danger" aria-label="Удалить"
                    onclick={() => (confirm = { text: `Удалить сервер «${s.name}» из приложения? На самом сервере ничего не изменится.`,
                                                action: () => run(`Удаление ${s.name}`, () => manage.deleteServer(s.id)) })}>
              <Icon name="trash" size={18} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {:else if section === "cascades"}
    {#if v.servers.length < 2}<p class="small muted">Для каскада нужны минимум два сервера: прокси и выход.</p>{/if}
    <ul>
      {#each v.cascades as c (c.id)}
        <li class="card col">
          <p class="name">{route(c)}</p>
          <p class="tags">
            <span class="tag st-{c.status}">{statusText[c.status] ?? c.status}</span>
            <span class="tag">UDP {c.port}</span>
            {#if c.awg_version}<span class="tag">AWG {c.awg_version}</span>{/if}
          </p>
          <div class="row">
            <button class="btn grow" onclick={() => run(`Проверка ${route(c)}`, () => manage.check(c.id))}>Проверить связь</button>
            <button class="btn danger" aria-label="Удалить"
                    onclick={() => (confirm = { text: `Удалить ${route(c)}? Его клиенты перестанут работать.`,
                                                action: () => run("Удаление каскада", () => manage.deleteCascade(c.id)) })}>
              <Icon name="trash" size={18} /></button>
          </div>
        </li>
      {/each}
    </ul>
    {#if v.external.length}
      <h2>Найденные пробросы на прокси</h2>
      {#each v.external as x}
        <div class="card row">
          <div class="grow"><p class="name">{name(x.proxy_id)} → {name(x.exit_id)}</p><p class="small muted">{x.rule}</p></div>
          <button class="btn" onclick={() => run("Подключение существующего каскада", () => manage.adopt(x.proxy_id, x.exit_id, x.port))}>Использовать</button>
        </div>
      {/each}
    {/if}
  {:else}
    {#if v.clients.length}
      <button class="btn" onclick={() => run("Обновление трафика", () => manage.traffic())}><Icon name="refresh" size={18} /> Обновить трафик</button>
    {/if}
    <ul>
      {#each v.clients as c (c.id)}
        <li class="card col">
          <div class="row">
            <div class="grow">
              <p class="name ellipsis">{c.name}</p>
              <p class="small muted ellipsis">{cascadeLabel(c.cascade_id)} · {c.ip}</p>
            </div>
            <span class="tag" class:online={ago(c.handshake) === "онлайн"}>{ago(c.handshake)}</span>
          </div>
          {#if c.traffic}<p class="small muted">↓ {bytes(c.traffic.tx)} · ↑ {bytes(c.traffic.rx)}</p>{/if}
          <div class="row">
            <button class="btn grow" onclick={() => toDevice(c.id)}><Icon name="device" size={18} /> Сюда</button>
            <button class="btn grow" onclick={() => share(c.id)}><Icon name="share" size={18} /> Ключ</button>
            <button class="btn danger" aria-label="Отозвать"
                    onclick={() => (confirm = { text: `Отозвать доступ «${c.name}»? Ключ перестанет работать.`,
                                                action: () => run(`Отзыв ${c.name}`, () => manage.deleteClient(c.id)) })}>
              <Icon name="trash" size={18} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

{#if serverForm}
  <Sheet title={serverForm.id ? "Сервер" : "Новый сервер"} onclose={() => (serverForm = null)}>
    <input bind:value={serverForm.host} placeholder="IP-адрес или домен" />
    <input bind:value={serverForm.name} placeholder="Название (необязательно)" />
    <div class="row">
      <input class="grow" bind:value={serverForm.user} placeholder="Пользователь" />
      <input class="port" type="number" bind:value={serverForm.ssh_port} placeholder="22" />
    </div>
    <input type="password" bind:value={serverForm.password}
           placeholder={serverForm.id ? "Пароль SSH (оставьте пустым, чтобы не менять)" : "Пароль SSH"} />
    <input bind:value={serverForm.key_path} placeholder="…или путь к ключу, например ~/.ssh/id_ed25519" />
    <p class="small muted">Нужен root или пользователь с sudo без пароля. Пароль хранится в {secretStore}. Добавление сервера ничего на нём не меняет — только читает.</p>
    <button class="btn primary wide" disabled={!serverForm.host.trim()} onclick={saveServer}>Сохранить</button>
  </Sheet>
{/if}

{#if cascadeForm}
  <Sheet title="Новый каскад" onclose={() => (cascadeForm = null)}>
    <h2>Прокси (вход)</h2>
    <select bind:value={cascadeForm.proxy_id}>
      <option value="">Без прокси — напрямую</option>
      {#each v.servers as s}<option value={s.id}>{s.name}</option>{/each}
    </select>
    <h2>{cascadeForm.proxy_id ? "Серверы выхода" : "Серверы"}</h2>
    <div class="col">
      {#each v.servers.filter((s) => s.id !== cascadeForm!.proxy_id) as s}
        <label class="check row">
          <input type="checkbox" checked={cascadeForm.exit_ids.includes(s.id)}
                 onchange={() => (cascadeForm!.exit_ids = toggle(cascadeForm!.exit_ids, s.id))} />
          <span class="grow">{s.name}</span>
          <span class="small muted">{s.awg.map((a) => a.version).join(", ") || "AWG нет"}</span>
        </label>
      {/each}
    </div>
    <h2>Версия AmneziaWG</h2>
    <div class="segmented">
      {#each [["auto", "Как есть"], ["legacy", "1.0"], ["v2", "2.0"], ["v3", "3.x"]] as [id, label]}
        <button class:on={cascadeForm.instance === id} onclick={() => (cascadeForm!.instance = id)}>{label}</button>
      {/each}
    </div>
    <p class="small muted">«Как есть» — AmneziaWG, который уже стоит на сервере (или установка). 1.0 — для роутеров. Другие версии ставятся в отдельные контейнеры, не затрагивая существующих клиентов.</p>
    {#if cascadeForm.exit_ids.length === 1 && cascadeForm.proxy_id}
      <input type="number" bind:value={cascadeForm.port} placeholder="Порт на прокси (необязательно, подберётся сам)" />
    {/if}
    <button class="btn primary wide" disabled={!cascadeForm.exit_ids.length} onclick={createCascade}>Создать</button>
  </Sheet>
{/if}

{#if clientForm}
  <Sheet title="Новый клиент" onclose={() => (clientForm = null)}>
    <input bind:value={clientForm.name} placeholder="Имя (телефон мамы, ноутбук…)" />
    <h2>Каскады</h2>
    <div class="col">
      {#each v.cascades as c}
        <label class="check row">
          <input type="checkbox" checked={clientForm.cascade_ids.includes(c.id)}
                 onchange={() => (clientForm!.cascade_ids = toggle(clientForm!.cascade_ids, c.id))} />
          <span class="grow">{route(c)}</span>
          <span class="small muted">AWG {c.awg_version ?? "?"}</span>
        </label>
      {/each}
    </div>
    <p class="small muted">На каждый выбранный каскад — свой ключ: так человек сможет выбирать сервер выхода.</p>
    <button class="btn primary wide" disabled={!clientForm.name.trim() || !clientForm.cascade_ids.length} onclick={createClient}>Создать</button>
  </Sheet>
{/if}

{#if shareData}
  <Sheet title={shareData.name} onclose={() => (shareData = null)}><ShareBox data={shareData} /></Sheet>
{/if}

{#if confirm}
  <Sheet title="Подтвердите" onclose={() => (confirm = null)}>
    <p>{confirm.text}</p>
    <div class="row">
      <button class="btn grow" onclick={() => (confirm = null)}>Отмена</button>
      <button class="btn danger grow" onclick={() => { const a = confirm!.action; confirm = null; a(); }}>Да</button>
    </div>
  </Sheet>
{/if}

{#if op}
  <Sheet title={op.title} onclose={op.done ? () => (op = null) : undefined}>
    <div class="log mono">
      {#each op.lines as l}<p class:err={l.startsWith("ОШИБКА") || l.startsWith("ВНИМАНИЕ")}>{l}</p>{/each}
      {#if !op.done}<p class="muted">выполняется…</p>{/if}
    </div>
    {#if op.done}
      <p class:ok={op.ok} class:error={!op.ok}>{op.ok ? "Готово" : "Не получилось"}</p>
      <button class="btn wide" onclick={() => (op = null)}>Закрыть</button>
    {/if}
  </Sheet>
{/if}

<style>
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .col { display: flex; flex-direction: column; gap: 10px; }
  .name { font-weight: 600; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .tag.st-applied, .tag.online { color: var(--ok); }
  .tag.st-missing, .tag.st-conflict { color: var(--danger); }
  .port { width: 90px; }
  select { font: inherit; color: var(--text); background: var(--surface-2); border: 1px solid var(--border); border-radius: 12px; padding: 11px 12px; appearance: none; }
  .check { padding: 8px 0; cursor: pointer; }
  .check input { width: 18px; height: 18px; accent-color: var(--accent); }
  .log { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 12px; max-height: 50vh; overflow: auto; display: flex; flex-direction: column; gap: 4px; user-select: text; }
  .log .err { color: var(--danger); }
  .ok { color: var(--ok); font-weight: 600; }
</style>
