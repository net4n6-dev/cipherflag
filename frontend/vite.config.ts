/// <reference types="vitest/config" />
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import { svelteTesting } from '@testing-library/svelte/vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit(), svelteTesting()],
	// Never emit source maps into the build; adapter-static output is
	// embedded into the Go binary via //go:embed, so a map would ship
	// readable source in released artifacts. Pin it rather than rely on
	// the bundler default.
	build: {
		sourcemap: false
	},
	server: {
		port: 5174,
		proxy: {
			'/api': {
				target: 'http://localhost:8443',
				changeOrigin: true
			}
		}
	},
	test: {
		environment: 'jsdom',
		globals: true,
		setupFiles: ['./vitest-setup.ts'],
		include: ['src/**/*.{test,spec}.{js,ts}']
	}
});
