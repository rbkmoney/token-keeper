-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/2]).
-export([store_authdata/2]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: tk_storage:storage_opts().

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_authdata_source:selector(), source_opts()) -> stored_authdata() | undefined.
get_authdata({token, V}, StorageOpts) ->
    get_authdata({id, get_authdata_id(V)}, StorageOpts);
get_authdata({id, V}, StorageOpts) ->
    case tk_storage:get(V, StorageOpts) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed storage get: ~p", [Reason]),
            undefined
    end.

-spec store_authdata(stored_authdata(), source_opts()) -> {ok, tk_token_jwt:claims()} | undefined.
store_authdata(AuthData, Opts) ->
    tk_storage:store(AuthData, Opts).

%%

get_authdata_id(Claims) ->
    tk_token_jwt:get_token_id(Claims).
