package main

import _ "embed"

//go:embed templates/docker-compose.yml.tmpl
var dockerComposeTmpl string

//go:embed templates/env.tmpl
var envTmpl string

//go:embed templates/cipherflag.toml.tmpl
var tomlTmpl string
