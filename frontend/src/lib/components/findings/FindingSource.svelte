<!-- Copyright 2026 net4n6-dev

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. -->

<script lang="ts">
	let { sourceUrl }: { sourceUrl?: string } = $props();
</script>

{#if sourceUrl}
	{#if sourceUrl === 'manual'}
		<span class="finding-source-manual" title="Manually curated reference data">manually curated</span>
	{:else}
		<a class="finding-source-link" href={sourceUrl} target="_blank" rel="noopener noreferrer">source</a>
	{/if}
{/if}

<style>
	.finding-source-link,
	.finding-source-manual {
		font-size: 0.7rem;
		color: var(--cf-accent);
		opacity: 0.8;
		margin-top: 0.2rem;
		display: inline-block;
	}
	.finding-source-link { text-decoration: none; }
	.finding-source-link:hover { text-decoration: underline; opacity: 1; }
	.finding-source-manual { font-style: italic; cursor: default; }
</style>
