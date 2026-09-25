# Nextcloud implementation sequence

1. Review the pinned upstream container entrypoint, application version and supported database/runtime requirements. Record exact image and configuration digests plus upstream licences.
2. Add strict package-specific profile/ownership and guided setup tests. Preserve existing Matrix behavior and reject cross-package ownership adoption.
3. Implement fixed configuration, initial secret handling, runtime, readiness and background jobs. Test on disposable Ubuntu before describing the package as installed.
4. Add local account onboarding, the browser/file path, access isolation and explicit sharing tests.
5. Extend backup scope and restore validation through package-specific adapters. Exercise actual encrypted transport and file/database/identity restoration.
6. Add certificate lifecycle, actionable health output and beginner instructions. Run Matrix regression acceptance alongside Nextcloud acceptance.
7. Continue the regional gateway and remaining product acceptance; completing Nextcloud is not completing the whole product.
