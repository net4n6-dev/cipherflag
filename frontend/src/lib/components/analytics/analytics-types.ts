// analytics-types.ts — Shared constants for analytics components

export const GRADE_COLORS: Record<string, string> = {
	'A+': '#22c55e',
	'A': '#22c55e',
	'B': '#84cc16',
	'C': '#eab308',
	'D': '#f97316',
	'F': '#ef4444',
	'?': '#64748b',
};

export function gradeColor(grade: string): string {
	return GRADE_COLORS[grade] ?? '#64748b';
}
