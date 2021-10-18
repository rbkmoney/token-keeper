-module(tk_authdata_source_claim).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/3]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: tk_token_claim_utils:decode_opts().

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), source_opts(), tk_woody_handler:handle_ctx()) -> stored_authdata() | undefined.
get_authdata(Token, Opts, _Ctx) ->
    Claims = tk_token_jwt:get_claims(Token),
    case tk_token_claim_utils:decode_authdata(Claims, Opts) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed claim get: ~p", [Reason]),
            undefined
    end.
