# arkknight.si

Personal site of **Arthur Geo Thomas**: portfolio, threat intelligence, threat hunting, blog and the RedKuppi Series.

Built with [Astro](https://astro.build), hosted on GitHub Pages, DNS on Cloudflare.

## Run locally
```bash
npm install
npm run dev      # http://localhost:4321
npm run build    # output in dist/
```

## Add content
Copy a file from `templates/` into the matching folder under `src/content/`, fill in the front matter, and set `draft: false`.

| Section | Folder | Template |
|---|---|---|
| Intel | `src/content/intel/` | `templates/intel.md` |
| Hunting | `src/content/hunts/` | `templates/hunts.md` |
| Blog | `src/content/posts/` | `templates/posts.md` |
| RedKuppi | `src/content/redkuppi/` | `templates/redkuppi.md` |
| Certifications | `src/content/certifications/` | `templates/certification.yaml` |
| Experience / Projects | `src/content/experience/`, `src/content/projects/` | see existing files |

Drafts show in `npm run dev` but are left out of the production build.

## Deploy
Push to `main`. GitHub Actions builds and deploys to Pages (`.github/workflows/deploy.yml`). Pull requests run a build check (`ci.yml`).
