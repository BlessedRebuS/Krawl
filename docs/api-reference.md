---
hide:
  - toc
---

# API reference

Every Dashboard API endpoint, generated from Krawl's OpenAPI schema. Paths
start with your dashboard secret path, shown here as `<DASHBOARD-PATH>`.
Authentication and examples are in [Dashboard API](dashboard-api.md).

This copy is read-only. To send requests, open `/<DASHBOARD-PATH>/docs` on your
own instance, which serves the same Swagger UI for its running version.

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css">
<div id="swagger-ui" class="krawl-swagger"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: "../api/openapi.json",
    dom_id: "#swagger-ui",
    supportedSubmitMethods: [],
    defaultModelsExpandDepth: -1,
    docExpansion: "list",
  });
</script>
