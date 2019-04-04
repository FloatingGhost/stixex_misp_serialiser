# StixexMispSerialiser

A serialiser from Stix to MISP (and maybe the other way around in the future)

For use with [StixEx](https://github.com/FloatingGhost/stixex)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `stixex_misp_serialiser` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:stixex_misp_serialiser, "~> 0.1.1"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/stixex_misp_serialiser](https://hexdocs.pm/stixex_misp_serialiser).

## Usage

```elixir
StixEx.Bundle.to_string(bundle, serialiser: StixEx.Serialiser.MISP)
```
