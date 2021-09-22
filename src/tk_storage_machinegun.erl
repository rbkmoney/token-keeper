-module(tk_storage_machinegun).

%% NOTE: This storage is not yet implemented

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-behaviour(tk_storage).
-behaviour(machinery).

%% API
-export([get_by_claims/2]).

%% tk_storage interface
-export([get/2]).
-export([store/2]).
-export([revoke/2]).

%% machinery interface
-export([init/4]).
-export([process_repair/4]).
-export([process_timeout/3]).
-export([process_call/4]).

-type storage_opts() :: #{}.
-export_type([storage_opts/0]).

-define(NS, tk_authdata).

%%

-type storable_authdata() :: tk_storage:storable_authdata().
-type authdata_id() :: tk_authority:authdata_id().
-type claims() :: tk_token_jwt:claims().

%% TODO: ????
-type machine() :: machinery:machine(claims(), any()).
-type result() :: machinery:result(claims(), any()).
-type handler_args() :: machinery:handler_args(any()).
-type handler_opts() :: machinery:handler_args(any()).

%%

-spec get_by_claims(claims(), storage_opts()) -> {ok, storable_authdata()} | {error, not_found}.
get_by_claims(_Claims, _Opts) ->
    %% Extract id from claims, collapse history and return the auth data?
    {error, not_found}.

%%-------------------------------------
%% tk_storage behaviour implementation

%% Collapse history and return the auth data?
-spec get(authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, not_found}.
get(ID, Opts) ->
    case machinery:get(?NS, ID, {undefined, undefined, forward}, backend(Opts)) of
        {ok, Machine} ->
            collapse(Machine);
        {error, _} = Err ->
            Err
    end.

%% Start a new machine, post event, make claims with id
%% Consider ways to generate authdata ids?
-spec store(storable_authdata(), storage_opts()) -> {ok, claims()} | {error, _Reason}.
store(AuthData, Opts) ->
    Claims = tk_token_claim_utils:encode_authdata(AuthData),
    DataID = tk_authority:get_authdata_id(AuthData),
    case machinery:start(?NS, DataID, Claims, backend(Opts)) of
        ok ->
            {ok, Claims};
        {error, _} = Err ->
            Err
    end.

%% Post a revocation event?
-spec revoke(authdata_id(), storage_opts()) -> ok | {error, _Reason}.
revoke(ID, Opts) ->
    case machinery:call(?NS, ID, revoke, backend(Opts)) of
        {ok, _Reply} ->
            ok;
        {error, _} = Err ->
            Err
    end.

%%-------------------------------------
%% machinery behaviour implementation
%% TODO: ????

-spec init(machinery:args(_), machine(), handler_args(), handler_opts()) -> result().
init(_Args, _Machine, _, _) ->
    erlang:error({not_implemented, init}).

-spec process_repair(machinery:args(_), machine(), handler_args(), handler_opts()) ->
    {ok, {machinery:response(_), result()}} | {error, _}.
process_repair(_Args, _Machine, _, _) ->
    erlang:error({not_implemented, process_repair}).

-spec process_timeout(machine(), handler_args(), handler_opts()) -> result().
process_timeout(_Machine, _, _) ->
    erlang:error({not_implemented, process_timeout}).

-spec process_call(machinery:args(_), machine(), handler_args(), handler_opts()) -> {machinery:response(_), result()}.
process_call(_Args, _Machine, _, _) ->
    erlang:error({not_implemented, process_call}).

%%-------------------------------------
%% internal

backend(Opts) ->
    %% TODO: backend handler ?????
    {tk_storage_machinegun, Opts}.

collapse(#{history := [{_ID, _Ts, Claim}]}) ->
    %% TODO: decode options ???
    tk_token_claim_utils:decode_authdata(Claim, #{}).
