Stores the current directory for use by the POPD command, then
changes to the specified directory.

PUSHD [path | ..]

  path        Specifies the directory to make the current directory.

If Command Extensions are enabled the PUSHD command accepts
network paths in addition to the normal drive letter and path.
If a network path is specified, PUSHD will create a temporary
drive letter that points to that specified network resource and
then change the current drive and directory, using the newly
defined drive letter.  Temporary drive letters are allocated from
Z: on down, using the first unused drive letter found.
