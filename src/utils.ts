export const fmt = (d: Date) =>
  d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
export const fmtMonth = (d: Date) =>
  d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short' });
export const published = <T extends { data: { draft?: boolean } }>(e: T) =>
  import.meta.env.DEV || !e.data.draft;
