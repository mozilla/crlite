This tool will not work on the local Firestore emulator.

Its purpose is to reconstruct missing metadata files in Firestore by using the
DocumentRefs iterator which is only available in the full implementation,
requiring admin privileges.

After running this tool, it is recommended to run `reprocess-known-certs`, as
it will enqueue all the unknown-to-the-cache issuer-date combinations for
processing.
