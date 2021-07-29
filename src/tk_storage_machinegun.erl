-module(tk_storage_machinegun).

%% NOTE: This storage is not yet implemented

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-behaviour(tk_storage).
-export([get/2]).
-export([get_by_claims/2]).
-export([store/2]).
-export([revoke/2]).

-type storage_opts() :: #{}.
-export_type([storage_opts/0]).

%%

-type storable_authdata() :: tk_storage:storable_authdata().
-type authdata_id() :: tk_authority:authdata_id().
-type claims() :: tk_token_jwt:claims().

%%

-spec get(authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, not_found}.
get(_DataID, _Opts) ->
    %% Collapse history and return the auth data?
    {error, not_found}.

-spec get_by_claims(claims(), storage_opts()) -> {ok, storable_authdata()} | {error, not_found}.
get_by_claims(_Claims, _Opts) ->
    %% Extract id from claims, collapse history and return the auth data?
    {error, not_found}.

-spec store(storable_authdata(), storage_opts()) -> {ok, claims()} | {error, _Reason}.
store(_AuthData, _Opts) ->
    %% Start a new machine, post event, make claims with id
    %% Consider ways to generate authdata ids?
    {error, not_implemented}.

-spec revoke(authdata_id(), storage_opts()) -> ok | {error, _Reason}.
revoke(_DataID, _Opts) ->
    %% Post a revocation event?
    {error, not_implemented}.
