-module(tk_storage_machinegun_schema).

%% machinery_mg_schema behaviour
-behaviour(machinery_mg_schema).

-export([get_version/1]).
-export([marshal/3]).
-export([unmarshal/3]).

%% API Types

-type event() :: tk_events_thrift:'AuthDataChange'().

-export_type([event/0]).

%% Internal types

-type type() :: machinery_mg_schema:t().
-type value(T) :: machinery_mg_schema:v(T).
-type value_type() :: machinery_mg_schema:vt().
-type context() :: machinery_mg_schema:context().

-type aux_state() :: term().
-type call_args() :: term().
-type call_response() :: term().

-type data() ::
    aux_state()
    | event()
    | call_args()
    | call_response().

%%

-define(CURRENT_EVENT_FORMAT_VERSION, 1).

%% machinery_mg_schema callbacks

-spec get_version(value_type()) -> machinery_mg_schema:version().
get_version(event) ->
    ?CURRENT_EVENT_FORMAT_VERSION;
get_version(aux_state) ->
    undefined.

-spec marshal(type(), value(data()), context()) -> {machinery_msgpack:t(), context()}.
marshal({event, FormatVersion}, TimestampedChange, Context) ->
    marshal_event(FormatVersion, TimestampedChange, Context);
marshal(T, V, C) when
    T =:= {args, init} orelse
        T =:= {args, call} orelse
        T =:= {args, repair} orelse
        T =:= {aux_state, undefined} orelse
        T =:= {response, call} orelse
        T =:= {response, {repair, success}} orelse
        T =:= {response, {repair, failure}}
->
    machinery_mg_schema_generic:marshal(T, V, C).

-spec unmarshal(type(), machinery_msgpack:t(), context()) -> {data(), context()}.
unmarshal({event, FormatVersion}, EncodedChange, Context) ->
    unmarshal_event(FormatVersion, EncodedChange, Context);
unmarshal(T, V, C) when
    T =:= {args, init} orelse
        T =:= {args, call} orelse
        T =:= {args, repair} orelse
        T =:= {aux_state, undefined} orelse
        T =:= {response, call} orelse
        T =:= {response, {repair, success}} orelse
        T =:= {response, {repair, failure}}
->
    machinery_mg_schema_generic:unmarshal(T, V, C).

%% Internals

-spec marshal_event(machinery_mg_schema:version(), event(), context()) -> {machinery_msgpack:t(), context()}.
marshal_event(1, AuthDataChange, Context) ->
    Type = {struct, union, {tk_events_thrift, 'AuthDataChange'}},
    {{bin, serialize(Type, AuthDataChange)}, Context}.

-spec unmarshal_event(machinery_mg_schema:version(), machinery_msgpack:t(), context()) -> {event(), context()}.
unmarshal_event(1, EncodedChange, Context) ->
    {bin, EncodedThriftChange} = EncodedChange,
    Type = {struct, union, {tk_events_thrift, 'AuthDataChange'}},
    {deserialize(Type, EncodedThriftChange), Context}.

%%

serialize(Type, Data) ->
    Codec0 = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec0, Type, Data) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1);
        {error, Reason} ->
            erlang:error({thrift, {protocol, Reason}})
    end.

deserialize(Type, Data) ->
    Codec0 = thrift_strict_binary_codec:new(Data),
    case thrift_strict_binary_codec:read(Codec0, Type) of
        {ok, Result, Codec1} ->
            case thrift_strict_binary_codec:close(Codec1) of
                <<>> ->
                    Result;
                Leftovers ->
                    erlang:error({thrift, {protocol, {excess_binary_data, Leftovers}}})
            end;
        {error, Reason} ->
            erlang:error({thrift, {protocol, Reason}})
    end.

%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include_lib("token_keeper_proto/include/tk_events_thrift.hrl").

-spec test() -> _.

-spec marshal_unmarshal_created_test() -> _.
-spec marshal_unmarshal_status_changed_test() -> _.

marshal_unmarshal_created_test() ->
    Event =
        {created, #tk_events_AuthDataCreated{
            id = <<"TEST">>,
            status = active,
            context = #bctx_ContextFragment{type = v1_thrift_binary, content = <<"STUFF">>},
            metadata = #{}
        }},
    {Marshaled, _} = marshal_event(1, Event, {}),
    {Unmarshaled, _} = unmarshal_event(1, Marshaled, {}),
    ?assertEqual(Event, Unmarshaled).

marshal_unmarshal_status_changed_test() ->
    Event =
        {status_changed, #tk_events_AuthDataStatusChanged{
            status = revoked
        }},
    {Marshaled, _} = marshal_event(1, Event, {}),
    {Unmarshaled, _} = unmarshal_event(1, Marshaled, {}),
    ?assertEqual(Event, Unmarshaled).

-endif.
