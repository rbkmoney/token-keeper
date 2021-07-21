-module(tk_storage).

-export([get/3]).
-export([get_by_claims/3]).
-export([store/2]).
-export([revoke/2]).

%%

-callback get(authdata_id(), storage_opts()) -> {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback get_by_claims(claims(), storage_opts()) -> {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback store(tk_storage:storable_authdata()) -> {ok, claims()} | {error, _Reason}.
-callback revoke(authdata_id()) -> ok | {error, _Reason}.

%%

-type storable_authdata() :: #{
    id => tk_authority:authdata_id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    authority => tk_authority:autority_id(),
    metadata => tk_authority:metadata()
}.

-export_type([storable_authdata/0]).

%%

-type authdata_id() :: tk_authority:authdata_id().
-type storage() :: claim.
-type claims() :: tk_token_jwt:claims().
-type storage_opts() :: tk_storage_claim:storage_opts().

%%

-spec get(storage(), authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get(Storage, DataID, Opts) ->
    Handler = get_storage_handler(Storage),
    Handler:get(DataID, Opts).

-spec get_by_claims(storage(), claims(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get_by_claims(Storage, Claims, Opts) ->
    Handler = get_storage_handler(Storage),
    Handler:get_by_claims(Claims, Opts).

-spec store(storage(), storable_authdata()) -> {ok, claims()} | {error, _Reason}.
store(Storage, AuthData) ->
    Handler = get_storage_handler(Storage),
    Handler:store(AuthData).

-spec revoke(storage(), authdata_id()) -> ok | {error, _Reason}.
revoke(Storage, DataID) ->
    Handler = get_storage_handler(Storage),
    Handler:revoke(DataID).

%%

get_storage_handler(claim) ->
    tk_storage_claim.