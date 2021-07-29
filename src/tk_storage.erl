-module(tk_storage).

-export([get/2]).
-export([get_by_claims/2]).
-export([store/2]).
-export([revoke/2]).

%%

-callback get(authdata_id(), opts()) -> {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback get_by_claims(claims(), opts()) -> {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback store(tk_storage:storable_authdata(), opts()) -> {ok, claims()} | {error, _Reason}.
-callback revoke(authdata_id(), opts()) -> ok | {error, _Reason}.

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
-type claims() :: tk_token_jwt:claims().

-type storage_opts() :: {storage(), opts()} | storage().
-type storage() :: claim.
-type opts() :: tk_storage_claim:storage_opts().

%%

-spec get(authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get(DataID, StorageOpts) ->
    {Storage, Opts} = get_storage_opts(StorageOpts),
    Handler = get_storage_handler(Storage),
    Handler:get(DataID, Opts).

-spec get_by_claims(claims(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get_by_claims(Claims, StorageOpts) ->
    {Storage, Opts} = get_storage_opts(StorageOpts),
    Handler = get_storage_handler(Storage),
    Handler:get_by_claims(Claims, Opts).

-spec store(storable_authdata(), storage_opts()) -> {ok, claims()} | {error, _Reason}.
store(AuthData, StorageOpts) ->
    {Storage, Opts} = get_storage_opts(StorageOpts),
    Handler = get_storage_handler(Storage),
    Handler:store(AuthData, Opts).

-spec revoke(authdata_id(), storage_opts()) -> ok | {error, _Reason}.
revoke(DataID, StorageOpts) ->
    {Storage, Opts} = get_storage_opts(StorageOpts),
    Handler = get_storage_handler(Storage),
    Handler:revoke(DataID, Opts).

%%

get_storage_handler(claim) ->
    tk_storage_claim.

get_storage_opts({_Storage, _Opts} = StorageOpts) ->
    StorageOpts;
get_storage_opts(Storage) when is_atom(Storage) ->
    {Storage, #{}}.
