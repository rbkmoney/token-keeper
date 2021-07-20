-module(tk_storage).

-export([get/3]).
-export([store/2]).
-export([revoke/2]).

%%

-callback get(claims(), storage_opts()) -> {ok, tk_storage:stored_authdata()} | {error, _Reason}.
-callback store(tk_storage:stored_authdata()) -> {ok, claims()} | {error, _Reason}.
-callback revoke(claims()) -> ok | {error, _Reason}.

%%

-type stored_authdata() :: #{
    id => tk_authority:id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    authority => tk_authority:autority_id(),
    metadata => tk_authority:metadata()
}.

-export_type([stored_authdata/0]).

%%

-type storage() :: claim.
-type claims() :: tk_token_jwt:claims().
-type storage_opts() :: tk_storage_claim:storage_opts().

%%

-spec get(storage(), claims(), storage_opts()) -> {ok, tk_storage:stored_authdata()} | {error, _Reason}.
get(Storage, Claims, Opts) ->
    Handler = get_storage_handler(Storage),
    Handler:get(Claims, Opts).

-spec store(storage(), tk_storage:stored_authdata()) -> {ok, claims()} | {error, _Reason}.
store(Storage, AuthData) ->
    Handler = get_storage_handler(Storage),
    Handler:store(AuthData).

-spec revoke(storage(), claims()) -> ok | {error, _Reason}.
revoke(Storage, Claims) ->
    Handler = get_storage_handler(Storage),
    Handler:revoke(Claims).

%%

get_storage_handler(claim) ->
    tk_storage_claim.
