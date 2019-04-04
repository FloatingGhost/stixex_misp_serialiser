defmodule StixexMispSerialiser.MixProject do
  use Mix.Project

  def project do
    [
      app: :stixex_misp_serialiser,
      description: "A serialiser from Stix to MISP",
      source_url: "https://github.com/FloatingGhost/stixex_misp_serialiser",
      package: package(),
      version: "0.1.1",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:stixex, "~> 0.1.3"},
      {:mispex, "~> 0.1.8"},
      {:jason, "~> 1.1"},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp package() do
    [
      licenses: ["MIT"],
      links: %{
        "github" => "https://github.com/FloatingGhost/stixex_misp_serialiser"
      }
    ]
  end
end
