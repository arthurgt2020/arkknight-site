export const fmt = (d: Date) =>
  d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
export const fmtMonth = (d: Date) =>
  d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short' });
export const published = <T extends { data: { draft?: boolean } }>(e: T) =>
  import.meta.env.DEV || !e.data.draft;

// Newest first: by drop number when both have one, otherwise by date.
export const byDropDesc = (a: any, b: any) =>
  (b.data.drop ?? 0) - (a.data.drop ?? 0) || +b.data.date - +a.data.date;
