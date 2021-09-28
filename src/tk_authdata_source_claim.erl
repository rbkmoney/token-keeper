-module(tk_authdata_source_claim).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/2]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: tk_token_claim_utils:decode_opts().

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_authdata_source:selector(), source_opts()) -> stored_authdata() | undefined.
get_authdata({token, V}, Opts) ->
    Claims = tk_token_jwt:get_claims(V),
    case tk_token_claim_utils:decode_authdata(Claims, Opts) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed claim get: ~p", [Reason]),
            undefined
    end;
get_authdata(_, _Opts) ->
    undefined.
