# Deception Pages Management

Manage and bulk import/export deception pages from the dashboard's **Deception** tab.

## Automatic Startup Import

Place HTML files in `src/templates/deception/` to auto-import at startup. Double underscores map to path separators: `admin__login.html` → `/admin/login`.

Enable via config:
```yaml
deception:
  import_pages: true
```

Or environment variable:
```bash
export KRAWL_DECEPTION_IMPORT_PAGES=true
```

## Single File Operations

**Upload**: Click **Upload**, enter path, select file
**Download**: Click download icon on any page in the table

Supported types: HTML, HTM, XML, JSON, TXT, CSS, JS

## Bulk Operations

### Download (Bulk Export)
Export multiple pages as ZIP:
- **By selection**: Check boxes → click **Download**
- **By date**: Use date picker → click **Download** (exports pages before selected date)

### Upload (Bulk Import)
Import from ZIP file:
1. Navigate to `http://krawl:port/dashboard#deception` and click **Upload**
2. Select ZIP file
3. System auto-extracts files
4. Click **Upload**

## Contributing Deception Templates via PR

Open a pull request with the label **`deception`** to submit new deception pages. This can include:

- **Attacker-generated templates**: HTML files scraped or collected from real attacker probes
- **Ad-hoc generated HTML files**: handcrafted or templated pages that mimic specific applications or endpoints (eg: custom bank pages / specific services)

### Guidelines
Avoid real secrets or credentials, use fake/template values only. Each file should return a realistic-looking response so scanners believe they found a real target

To upload custom files:
- Place files in `src/templates/deception/`
- Use `__` as path separator in filenames (e.g. `admin__login.html` → `/admin/login`)
- `.html` extension is stripped from the URL; other extensions (`.php`, `.json`, `.xml`, `.env`, etc.) are preserved

or 

- Use the **Generated Deception Templates** download button in the dashboard (authenticated) to export existing templates as a ZIP and use them as reference or a starting point. The downloaded files are already formatted.




