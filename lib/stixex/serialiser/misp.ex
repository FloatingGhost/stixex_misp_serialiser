defmodule StixEx.Serialiser.MISP do
  @behaviour StixEx.Serialiser

  require Logger
  alias MISP.Attribute

  @doc """
  Convert from a bundle to a MISP object
  """
  def convert(stix_object)

  def convert([stix_object | rest]) do
    [convert(stix_object) | convert(rest)]
    |> List.flatten()
    |> Enum.filter(&(not is_nil(&1.value)))
  end

  def convert([]), do: []

  def convert(%{type: "bundle", objects: objects} = struct) do
    %MISP.Event{
      Event: %MISP.EventInfo{
        info: "From STIX",
        Attribute: convert(objects)
      }
    }
  end

  def convert(%{type: "mutex", name: name}), do: %Attribute{type: "mutex", value: name}

  def convert(%{type: "windows_registry_key", key: key, values: values}) do
    if Enum.count(values) > 0 do
      Enum.map(values, &%{type: "regkey|value", value: "#{key}|#{&1.data}"})
    else
      %{type: "regkey", value: key}
    end
  end

  def convert(%{type: "mac-addr", value: value}) do
    %Attribute{type: "mac-address", value: value}
  end

  def convert(%{type: "email-addr", value: value}) do
    %Attribute{type: "email-dst", value: value}
  end

  def convert(%{type: "domain-name", value: value}) do
    %Attribute{type: "domain", value: value}
  end

  def convert(%{type: "x509-certificate", hashes: hashes}) when not is_nil(hashes) do
    get_common_hashes(hashes, type_prefix: "x509-fingerprint-")
  end

  def convert(%{type: "file", name: name, hashes: hashes}) do
    [
      %Attribute{type: "filename", value: name},
      get_common_hashes(hashes, type_prefix: "filename|", value_prefix: "#{name}|")
    ]
  end

  def convert(%{type: "ipv6-addr", value: value}) do
    %Attribute{type: "ip-dst", value: value}
  end

  def convert(%{type: "user-account", user_id: value}) do
    %Attribute{type: "target-user", value: value}
  end

  def convert(%{type: "ipv4-addr", value: value}) do
    %Attribute{type: "ip-dst", value: value}
  end

  def convert(%{type: "url", value: value}) do
    %Attribute{type: "url", value: value}
  end

  def convert(%{type: "autonomous-system", number: value}) do
    %Attribute{type: "AS", value: value}
  end

  def convert(%{type: "indicator", pattern: pattern}) do
    %Attribute{type: "stix2-pattern", value: pattern}
  end

  def convert(%{type: "campaign", name: name}) do
    %Attribute{type: "campaign-name", value: name}
  end

  def convert(%{type: "vulnerability", name: name}) do
    %Attribute{type: "vulnerability", value: name}
  end

  def convert(%{type: "identity", name: name}) do
    %Attribute{type: "first-name", value: name}
  end

  def convert(%{type: "threat-actor", name: name, aliases: aliases}) do
    [
      %Attribute{type: "threat-actor", value: name},
      if is_nil(aliases) do
        []
      else
        Enum.map(aliases, &%Attribute{type: "threat-actor", value: &1})
      end
    ]
  end

  def convert(other) do
    Logger.warn("Ignoring #{other.type}")
    []
  end

  @doc """
  Given a hashes object, convert to a list of common MISP hashes
  (which usually have a prefix!)
  """
  def get_common_hashes(hashes, opts \\ [type_prefix: "", value_prefix: ""])
  def get_common_hashes(nil, _opts), do: []

  def get_common_hashes(hashes, opts) do
    hashes =
      [
        {"md5", Map.get(hashes, :MD5)},
        {"sha1", Map.get(hashes, :SHA1)},
        {"sha256", Map.get(hashes, :SHA256)}
      ]
      |> Enum.filter(fn {_, x} -> not is_nil(x) end)
      |> Enum.map(fn {h, x} ->
        %Attribute{type: "#{opts[:type_prefix]}#{h}", value: "#{opts[:value_prefix]}#{x}"}
      end)
  end

  @impl StixEx.Serialiser
  def to_string(struct) do
    struct
    |> convert()
    |> Jason.encode()
  end
end
