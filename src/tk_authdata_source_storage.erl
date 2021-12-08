-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/3]).

%% API types

-type opts() :: #{
    name := tk_storage:storage_name()
}.
-export_type([opts/0]).

%% Internal types

-type authdata() :: tk_authdata:prototype().

%% Behaviour functions

-spec get_authdata(tk_token:token_data(), opts(), woody_context:ctx()) -> authdata() | undefined.
get_authdata(#{id := ID}, #{name := StorageName}, Context) ->
    case tk_storage:get(ID, StorageName, Context) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed attempt to get bouncer context from storage: ~p", [Reason]),
            undefined
    end.
