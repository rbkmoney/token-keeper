-module(tk_authdata_source_claim).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/3]).

%% API types

-type opts() :: #{}.
-export_type([opts/0]).

%% Internal types

-type authdata() :: tk_authdata:prototype().

%% Behaviour functions

-spec get_authdata(tk_token:token_data(), opts(), woody_context:ctx()) -> authdata() | undefined.
get_authdata(#{payload := TokenPayload}, _Opts, _Context) ->
    case tk_claim_utils:decode_authdata(TokenPayload) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed attempt to decode bouncer context from claims: ~p", [Reason]),
            undefined
    end.
