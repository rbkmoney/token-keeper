-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/2]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: tk_storage:storage_opts().

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), source_opts()) -> stored_authdata() | undefined.
get_authdata(Token, StorageOpts) ->
    Claims = tk_token_jwt:get_claims(Token),
    AuthDataID = get_authdata_id(Claims),
    case tk_storage:get(AuthDataID, StorageOpts) of
        %% Not implemented
        %% {ok, AuthData} ->
        %%     AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed storage get: ~p", [Reason]),
            undefined
    end.

%%

get_authdata_id(_Claims) ->
    %% Not implemented
    <<>>.
