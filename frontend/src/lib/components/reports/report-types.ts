export const GRADE_COLORS: Record<string, string> = {
	'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16',
	'C': '#eab308', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b',
};

export const SEVERITY_COLORS: Record<string, string> = {
	'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#eab308',
	'Low': '#64748b', 'Info': '#94a3b8',
};

export function gradeColor(grade: string): string {
	return GRADE_COLORS[grade] ?? '#64748b';
}

export function severityColor(severity: string): string {
	return SEVERITY_COLORS[severity] ?? '#64748b';
}

export function exportCSV(headers: string[], rows: string[][], filename: string): void {
	const csvContent = [
		headers.join(','),
		...rows.map(row => row.map(cell => `"${String(cell ?? '').replace(/"/g, '""')}"`).join(','))
	].join('\n');

	const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
	const link = document.createElement('a');
	link.href = URL.createObjectURL(blob);
	link.download = filename;
	link.click();
	URL.revokeObjectURL(link.href);
}
