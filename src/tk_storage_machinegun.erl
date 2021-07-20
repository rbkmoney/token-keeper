-module(tk_storage_machinegun).

%% NOTE: This storage is not yet implemented

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-behaviour(tk_storage).
-export([get/2]).
-export([store/1]).
-export([revoke/1]).

-type storage_opts() :: #{}.
-export_type([storage_opts/0]).

%%

-type claims() :: tk_token_jwt:claims().

%%

-spec get(claims(), storage_opts()) -> {ok, tk_storage:stored_authdata()} | {error, not_found}.
get(_Claims, _Opts) ->
    %% Collapse history and get the auth data?
    {error, not_found}.

-spec store(tk_storage:stored_authdata()) -> {ok, claims()} | {error, _Reason}.
store(_AuthData) ->
    %% Start a new machine, post event
    %% Consider ways to generate authdata ids?
    {error, not_implemented}.

-spec revoke(claims()) -> ok | {error, _Reason}.
revoke(_Claims) ->
    %% Post a revocation event?
    {error, not_implemented}.
