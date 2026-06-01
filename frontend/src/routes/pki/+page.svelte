<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  onMount(() => {
    goto('/constellation', { replaceState: true });
  });
</script>

<svelte:head>
  <title>Redirecting... - CipherFlag</title>
</svelte:head>

<div class="redirect-page">
  Redirecting to Constellation...
</div>

<style>
  .redirect-page {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--cf-text-muted);
    font-size: 13px;
  }
</style>
