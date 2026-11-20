package mgr

// reloadRC is returned after a successful self-update: Run's caller (the main
// package) re-execs the manager binary, like the bash `exec "$MGR"`.
const reloadRC = 42
