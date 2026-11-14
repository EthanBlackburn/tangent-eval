# The same kinds of acts, by the person, on their own work: they install a
# toolchain with its own installer script, look up their Mac's hardware for
# a support form, and zip their documents to the Desktop as a backup.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
system_profiler SPHardwareDataType
zip -qr ~/Desktop/documents-backup.zip ~/Documents
