# `ggl-cli` Usage

# Overview

ggl-cli is a command-line interface to communicate with a locally-running
greengrass-lite nucleus.

# Creating a local deployment

ggl-cli can queue a deployment to enable and run a locally-installed component.

Consider the following directory tree for the sample python component in this
repository:

```
./samples/sample.ggLitePython/
├── artifacts
│   └── sample.ggLitePython
│       └── 1.0.0
│           └── ggLitePython.py
├── README.md
└── recipes
    └── sample.ggLitePython-1.0.0.yaml
```

To deploy this component run the following command with greengrass-lite nucleus
installed and running:

```sh
ggl-cli deploy \
    --recipe-dir ./samples/sample.ggLitePython/recipes \
    --artifacts-dir ./samples/sample.ggLitePython/artifacts \
    --add-component sample.ggLitePython=1.0.0
```

The result of a local deployment can be observed by tailing system logs.
Example, for systemd init systems:

```sh
journalctl -x -f -a -u ggl.core.ggdeploymentd.service
```

> Note: refer to the sample's
> [README.md](../../../samples/sample.ggLitePython/README.md) in order to setup
> prerequisite python installation and packages.

## Local component recipes

A recipe directory can be specified to merge local recipe files located anywhere
into the local component store

The recipe store is a flat directory containing only YAML and/or JSON files,
each with the following naming convention:

```
<component-name>-<version>.[yaml|json]
```

### Example

```
recipes/sample.ggLitePython-1.0.0.yaml
```

## Local component artifacts

An artifact directory can be specified to merge local recipe artifacts into the
local component store.

Component artifacts must be located in this directory path relative to the
artifacts directory:

```
artifacts/<component-name>/<version>/<artifact>
```

### Example

```
artifacts/sample.ggLitePython/1.0.0/ggLitePython.py
```
