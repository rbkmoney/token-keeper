-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/3]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: #{}.

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), source_opts(), tk_woody_handler:handle_ctx()) -> stored_authdata() | undefined.
get_authdata(Token, _SourceOpts, Ctx) ->
    case tk_storage:get(get_authdata_id(Token), Ctx) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed storage get: ~p", [Reason]),
            undefined
    end.

%%

get_authdata_id(Claims) ->
    tk_token_jwt:get_token_id(Claims).
