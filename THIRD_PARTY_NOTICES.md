# Upstream application sources and licences

The project's MIT licence covers its own deployment code. It does not relicense upstream applications, container base systems or their dependencies. The installer downloads the pinned images directly from their upstream registries; the project source archive does not contain these images.

| Component | Reviewed version | Source and upstream licensing information |
|---|---|---|
| Element Synapse | 1.161.0 | [Source and licensing section](https://github.com/element-hq/synapse/tree/v1.161.0): AGPL version 3 or later, with a separate commercial option. [AGPL text](https://github.com/element-hq/synapse/blob/v1.161.0/LICENSE-AGPL-3.0). |
| Element Web | 1.12.29 | [Source and licensing section](https://github.com/element-hq/element-web/tree/v1.12.29): AGPL version 3 or later, GPL version 3 or later, or a separate commercial agreement. [AGPL text](https://github.com/element-hq/element-web/blob/v1.12.29/LICENSE-AGPL-3.0); [GPL text](https://github.com/element-hq/element-web/blob/v1.12.29/LICENSE-GPL-3.0). |
| PostgreSQL | 17.11 | [Source](https://github.com/postgres/postgres/tree/REL_17_11); [PostgreSQL licence](https://www.postgresql.org/about/licence/). |
| Caddy | 2.11.4 | [Source](https://github.com/caddyserver/caddy/tree/v2.11.4); [Apache 2.0 licence](https://github.com/caddyserver/caddy/blob/v2.11.4/LICENSE). |

Exact image and configuration digests are recorded in `scripts/service_images.json`. Images also contain dependencies with their own notices. Preserve upstream notices when redistributing or modifying those components and consult their licence terms for applicable source-distribution requirements. Installing this kit does not purchase an upstream support contract or commercial licence.

Networking and backup component provenance is documented in [the provenance guide](docs/provenance.md), [releases](docs/releases.md) and [backup documentation](docs/backups.md). Ubuntu packages retain their package copyright and licence files under `/usr/share/doc` on the installed server.
