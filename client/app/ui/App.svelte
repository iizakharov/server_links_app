<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "./lib/Icon.svelte";
  import { api } from "./lib/api";
  import { app, refreshStatus, refreshView, type Tab } from "./lib/store.svelte";
  import Home from "./screens/Home.svelte";
  import Servers from "./screens/Servers.svelte";
  import Add from "./screens/Add.svelte";
  import Share from "./screens/Share.svelte";
  import Settings from "./screens/Settings.svelte";
  import Split from "./screens/Split.svelte";
  import Manage from "./screens/Manage.svelte";

  const tabs: { id: Tab; label: string; icon: string }[] = [
    { id: "home", label: "Главная", icon: "home" },
    { id: "servers", label: "Серверы", icon: "servers" },
    { id: "manage", label: "Управление", icon: "cascade" },
    { id: "share", label: "Поделиться", icon: "share" },
    { id: "settings", label: "Настройки", icon: "settings" },
  ];

  onMount(() => {
    refreshView();
    api.helperState().then((h) => (app.helper = h));
    refreshStatus();
    const t = setInterval(refreshStatus, 1000);
    return () => clearInterval(t);
  });
</script>

<div class="shell">
  <main>
    {#if app.tab === "home"}<Home />
    {:else if app.tab === "servers"}<Servers />
    {:else if app.tab === "add"}<Add />
    {:else if app.tab === "share"}<Share />
    {:else if app.tab === "split"}<Split />
    {:else if app.tab === "manage"}<Manage />
    {:else}<Settings />{/if}
  </main>
  <nav>
    {#each tabs as t}
      <button class:on={app.tab === t.id || (t.id === "servers" && app.tab === "add") || (t.id === "settings" && app.tab === "split")} onclick={() => (app.tab = t.id)}>
        <Icon name={t.icon} />
        <span>{t.label}</span>
      </button>
    {/each}
  </nav>
</div>

<style>
  .shell { height: 100%; display: flex; flex-direction: column; max-width: 560px; margin: 0 auto; }
  main { flex: 1; overflow-y: auto; }
  nav {
    display: flex; border-top: 1px solid var(--border); background: var(--surface);
    padding: 6px 4px calc(6px + env(safe-area-inset-bottom));
  }
  nav button {
    flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px;
    padding: 6px 0; color: var(--muted); font-size: 11px; font-weight: 560; border-radius: 10px;
  }
  nav button.on { color: var(--accent); }
</style>
