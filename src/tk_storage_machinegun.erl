-module(tk_storage_machinegun).

-include_lib("token_keeper_proto/include/tk_events_thrift.hrl").

-behaviour(tk_storage).
-behaviour(machinery).

%% tk_storage interface
-export([get/2]).
-export([store/2]).
-export([revoke/2]).

%% machinery interface
-export([init/4]).
-export([process_repair/4]).
-export([process_timeout/3]).
-export([process_call/4]).

-type storage_opts() :: #{woody_ctx => woody_context:ctx()}.
-export_type([storage_opts/0]).

-define(NS, tk_authdata).

%%

-type storable_authdata() :: tk_storage:storable_authdata().
-type authdata_id() :: tk_authority:authdata_id().

-type schema() :: machinery_mg_schema_generic | atom().
-type event_handler() :: woody:ev_handler() | [woody:ev_handler()].

-type automaton() :: #{
    % machinegun's automaton url
    url := binary(),
    path := binary(),
    event_handler := event_handler(),
    schema => schema(),
    transport_opts => woody_client_thrift_http_transport:transport_options()
}.

-type events() :: tk_events_thrift:'AuthDataChange'().
-type machine() :: machinery:machine(events(), any()).
-type result() :: machinery:result(events(), any()).
-type handler_args() :: machinery:handler_args(any()).
-type handler_opts() :: machinery:handler_args(any()).

%%-------------------------------------
%% tk_storage behaviour implementation

%% Collapse history and return the auth data?
-spec get(authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get(ID, Opts) ->
    case machinery:get(?NS, ID, backend(Opts)) of
        {ok, Machine} ->
            collapse(Machine);
        {error, _} = Err ->
            Err
    end.

%% Start a new machine, post event, make claims with id
%% Consider ways to generate authdata ids?
-spec store(storable_authdata(), storage_opts()) -> ok | {error, exists}.
store(AuthData, Opts) ->
    DataID = tk_authority:get_authdata_id(AuthData),
    machinery:start(?NS, DataID, {store, AuthData}, backend(Opts)).

%% Post a revocation event?
-spec revoke(authdata_id(), storage_opts()) -> ok | {error, notfound}.
revoke(ID, Opts) ->
    case machinery:call(?NS, ID, revoke, backend(Opts)) of
        {ok, _Reply} ->
            ok;
        {error, notfound} = Err ->
            Err
    end.

%%-------------------------------------
%% machinery behaviour implementation

-spec init(machinery:args({store, storable_authdata()}), machine(), handler_args(), handler_opts()) -> result().
init({store, AuthData}, _Machine, _, _) ->
    #{
        events => [
            {created, #tk_events_AuthDataCreated{
                id = tk_authority:get_authdata_id(AuthData),
                status = tk_authority:get_value(status, AuthData),
                context = tk_authority:get_value(context, AuthData),
                metadata = tk_authority:get_value(metadata, AuthData)
            }}
        ]
    }.

-spec process_repair(machinery:args(_), machine(), handler_args(), handler_opts()) -> no_return().
process_repair(_Args, _Machine, _, _) ->
    erlang:error({not_implemented, process_repair}).

-spec process_timeout(machine(), handler_args(), handler_opts()) -> no_return().
process_timeout(_Machine, _, _) ->
    erlang:error({not_implemented, process_timeout}).

-spec process_call(machinery:args(revoke), machine(), handler_args(), handler_opts()) ->
    {machinery:response(ok), result()}.
process_call(revoke, _Machine, _, _) ->
    {ok, #{
        events => [{status_changed, #tk_events_AuthDataStatusChanged{status = revoked}}]
    }}.

%%-------------------------------------
%% internal

backend(#{woody_ctx := WC}) ->
    case genlib_app:env(token_keeper, service_clients, #{}) of
        #{storage := Automaton} ->
            machinery_mg_backend:new(WC, #{
                client => get_woody_client(Automaton),
                schema => machinery_mg_schema_generic
            });
        #{} ->
            erlang:error({misconfiguration, automaton})
    end.

-spec get_woody_client(automaton()) -> machinery_mg_client:woody_client().
get_woody_client(#{url := Url} = Automaton) ->
    genlib_map:compact(#{
        url => Url,
        event_handler => genlib_app:env(token_keeper, woody_event_handlers, [scoper_woody_event_handler]),
        transport_opts => maps:get(transport_opts, Automaton, undefined)
    }).

collapse(#{history := History}) ->
    case collapse_history(History, undefined) of
        {ok, _AuthData} = Res -> Res;
        {error, wrong_history} -> {error, {wrong_history, History}}
    end.

collapse_history([], AuthData) when AuthData =/= undefined ->
    {ok, AuthData};
collapse_history([{_, _, {created, AuthData}} | Rest], undefined) ->
    #tk_events_AuthDataCreated{id = ID, context = Ctx, status = Status, metadata = Meta} = AuthData,
    collapse_history(Rest, #{id => ID, context => Ctx, status => Status, metadata => Meta});
collapse_history([{_, _, {status_changed, StatusChanged}} | Rest], AuthData) when AuthData =/= undefined ->
    #tk_events_AuthDataStatusChanged{status = Status} = StatusChanged,
    collapse_history(Rest, AuthData#{status => Status});
collapse_history(_, _) ->
    {error, wrong_history}.
