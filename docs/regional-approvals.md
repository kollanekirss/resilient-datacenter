# Prepare institutional partner approvals (development preview)

This workflow prepares signed approvals on an administrator's computer. It does not install a gateway, admit a device to Headscale or enable application federation. The regional transport package is still being built. Keep internal users on the institution's own network; the eventual dedicated gateway has its own regional membership.

Each institution keeps a private, passphrase-protected signing key in its operator workspace. Only public identity documents, offers and acceptances are exchanged. The gateway does not need the approval signing key. Keep a recovery copy of the encrypted key and retain its passphrase independently. Losing both prevents further use of that institutional signing identity.

## Prepare your institution

Use the reviewed development checkout and its Python environment. Create a private working directory under the already ignored lab directory:

```sh
mkdir -p inventories/lab
chmod 700 inventories/lab
./rdc regional setup --output-file inventories/lab/institution.json
./rdc regional init inventories/lab/institution.json --workspace inventories/lab/approvals
./rdc regional export-identity --workspace inventories/lab/approvals --output-file inventories/lab/public-identity.json
```

Setup asks for the institution identifier, regional controller, gateway node name and its regional IPv4, and permanent application domains. Obtain the address from the enrolled gateway's node status. These are declared facts at this stage; gateway installation must independently verify them. Initialization asks privately for the signing-key passphrase. Repeating the same initialization preserves the existing key; a changed institution or gateway identity requires review.

Send only `public-identity.json` to the intended partner through your chosen channel. Do not send the workspace or its signing-key file. The public document contains names, service domains, the regional gateway address and public key; review this information before sharing.

## Verify a partner

Obtain the other institution's public identity document. Inspect it, then compare its **complete public-key fingerprint** with a known administrator through an independent channel. A valid signature proves possession of a key; it does not establish who owns the institution label.

```sh
./rdc regional inspect inventories/lab/partner-identity.json
./rdc regional approve inventories/lab/partner-identity.json --workspace inventories/lab/approvals
```

Approve asks for the independently confirmed fingerprint. Each institution must perform this step for the other. The documents must declare the same regional controller and distinct gateway/application identities.

## Exchange an exact agreement

The initiating institution prepares an offer to the already approved fingerprint. Replace the placeholder with the complete verified value:

```sh
./rdc regional offer --workspace inventories/lab/approvals --peer-fingerprint VERIFIED_FULL_FINGERPRINT --services matrix nextcloud --days 30 --output-file inventories/lab/offer.json
```

Select only services declared by both parties. Lifetimes are limited to 90 days. The passphrase is entered privately. Send the offer to the recipient, which inspects and accepts it:

```sh
./rdc regional inspect inventories/lab/offer.json
./rdc regional accept inventories/lab/offer.json --workspace inventories/lab/approvals --output-file inventories/lab/accepted-agreement.json
```

Acceptance signs the digest of that exact offer. Changed service names, addresses, expiry or signatures invalidate it. Return the accepted document to the initiator, which records it:

```sh
./rdc regional import-agreement inventories/lab/accepted-agreement.json --workspace inventories/lab/approvals
./rdc regional status --workspace inventories/lab/approvals
```

Both parties can now see the approval and its expiry. `mutually-approved` is an approval state. Transport remains `not-installed-or-verified`; regional network admission and the actual application connection are separate acceptance steps.

If an output write failed after acceptance was recorded, recover the existing public document using its agreement identifier:

```sh
./rdc regional export-agreement AGREEMENT_ID --workspace inventories/lab/approvals --output-file inventories/lab/recovered-agreement.json
```

## Revoke local approval

```sh
./rdc regional revoke AGREEMENT_ID --workspace inventories/lab/approvals
```

This records a durable local revocation and refuses later re-import of the same agreement. It does not notify the other institution or change running traffic. Gateway enforcement remains pending until the transport package applies the updated policy. Previously delivered files and messages cannot be recalled by revocation.

The workspace files are private to the current operating-system account. Use the same operator account for subsequent commands. Public exports are also created privately and never overwrite existing output files. No password, passphrase or signing-key argument is accepted on the command line.

The experimental [dedicated gateway workflow](regional-gateway.md) now has separate local installation and policy commands. Preparing or revoking a document in the administrator workspace does not automatically contact a gateway. Apply the reviewed change on each intended gateway and verify it there.
