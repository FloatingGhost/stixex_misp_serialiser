defmodule StixexMispSerialiserTest do
  use ExUnit.Case

  describe "Example files" do
    test "Serialises" do
      {:ok, files} = File.ls("test/data/")

      for file <- files do
        {:ok, bundle} = StixEx.Bundle.from_file("test/data/" <> file)
        {:ok, _str} = StixEx.Bundle.to_string(bundle, serialiser: StixEx.Serialiser.MISP)
        :ok
      end
      |> Enum.all?(fn x -> x == :ok end)
    end

  end
end
