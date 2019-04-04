defmodule StixEx.Serialiser.MISP do
  @moduledoc """
  A serialiser to convert to MISP's data format
  """

  @behaviour StixEx.Serialiser

  require Logger

  defp convert(stix_object)

  defp convert([stix_object | rest]) do
    [convert(stix_object) | convert(rest)]
    |> List.flatten()
    |> Enum.filter(&(not is_nil(&1.value)))
  end

  defp convert([]), do: []

  defp convert(%{type: "bundle", id: "bundle--" <> id, objects: objects}) do
    attrs = convert(objects)

    time =
      DateTime.utc_now()
      |> DateTime.to_unix()
      |> Kernel.to_string()

    %{
      Event: %{
        uuid: id,
        info: "From STIX",
        publish_timestamp: time,
        published: true,
        distribution: 3,
        analysis: 0,
        attribute_count: Enum.count(attrs),
        Org: %{},
        OrgC: %{},
        Galaxy: [],
        ShadowAttribute: [],
        RelatedEvent: [],
        Tag: [],
        Attribute: attrs
      }
    }
  end

  defp convert(%{type: "mutex", name: name, id: "mutex--" <> id}),
    do: %{type: "mutex", value: name, uuid: id}

  defp convert(%{type: "windows_registry_key", key: key, values: values}) do
    if Enum.count(values) > 0 do
      Enum.map(values, &%{type: "regkey|value", value: "#{key}|#{&1.data}"})
    else
      %{type: "regkey", value: key}
    end
  end

  defp convert(%{type: "mac-addr", value: value, id: "mac-addr--" <> id}) do
    %{type: "mac-address", value: value, uuid: id}
  end

  defp convert(%{type: "email-addr", value: value, id: "email-addr--" <> id}) do
    %{type: "email-dst", value: value, uuid: id}
  end

  defp convert(%{type: "domain-name", value: value, id: "domain-name--" <> id}) do
    %{type: "domain", value: value, uuid: id}
  end

  defp convert(%{type: "x509-certificate", hashes: hashes}) when not is_nil(hashes) do
    get_common_hashes(hashes, type_prefix: "x509-fingerprint-")
  end

  defp convert(%{type: "file", name: name, hashes: hashes, id: "file--" <> id}) do
    [
      %{type: "filename", value: name, uuid: id},
      get_common_hashes(hashes, type_prefix: "filename|", value_prefix: "#{name}|")
    ]
  end

  defp convert(%{type: "ipv6-addr", value: value, id: "ipv6-addr--" <> id}) do
    %{type: "ip-dst", value: value, uuid: id}
  end

  defp convert(%{type: "user-account", user_id: value, id: "user-account--" <> id}) do
    %{type: "target-user", value: value, uuid: id}
  end

  defp convert(%{type: "ipv4-addr", value: value, id: "ipv4-addr--" <> id}) do
    %{type: "ip-dst", value: value, uuid: id}
  end

  defp convert(%{type: "url", value: value, id: "url--" <> id}) do
    %{type: "url", value: value, uuid: id}
  end

  defp convert(%{type: "autonomous-system", number: value, id: "autonomous-system--" <> id}) do
    %{type: "AS", value: value, uuid: id}
  end

  defp convert(%{type: "indicator", pattern: pattern, id: "indicator--" <> id}) do
    %{type: "stix2-pattern", value: pattern, uuid: id}
  end

  defp convert(%{type: "campaign", name: name, id: "campaign--" <> id}) do
    %{type: "campaign-name", value: name, uuid: id}
  end

  defp convert(%{type: "vulnerability", name: name, id: "vulnerability--" <> id}) do
    %{type: "vulnerability", value: name, uuid: id}
  end

  defp convert(%{type: "identity", name: name, id: "identity--" <> id}) do
    %{type: "first-name", value: name, uuid: id}
  end

  defp convert(%{type: "threat-actor", name: name, aliases: aliases, id: "threat-actor--" <> id}) do
    [
      %{type: "threat-actor", value: name, uuid: id},
      if is_nil(aliases) do
        []
      else
        Enum.map(aliases, &%{type: "threat-actor", value: &1})
      end
    ]
  end

  defp convert(other) do
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
    [
      {"md5", Map.get(hashes, :MD5)},
      {"sha1", Map.get(hashes, :SHA1)},
      {"sha256", Map.get(hashes, :SHA256)}
    ]
    |> Enum.filter(fn {_, x} -> not is_nil(x) end)
    |> Enum.map(fn {h, x} ->
      %{type: "#{opts[:type_prefix]}#{h}", value: "#{opts[:value_prefix]}#{x}"}
    end)
  end

  @impl StixEx.Serialiser
  def to_string(struct) do
    struct
    |> convert()
    |> Jason.encode()
  end
end
