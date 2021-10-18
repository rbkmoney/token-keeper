-module(tk_storage).

-export([get/2]).
-export([store/2]).
-export([revoke/2]).

%%

-callback get(authdata_id(), storage_opts(), tk_woody_handler:handle_ctx()) ->
    {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback store(tk_storage:storable_authdata(), storage_opts(), tk_woody_handler:handle_ctx()) -> ok | {error, _Reason}.
-callback revoke(authdata_id(), storage_opts(), tk_woody_handler:handle_ctx()) -> ok | {error, _Reason}.

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

-type storage() :: machinegun.
-type storage_opts() :: tk_storage_machinegun:storage_opts().

-type storage_config() :: storage() | {storage(), storage_opts()}.

%%

-spec get(authdata_id(), tk_woody_handler:handle_ctx()) -> {ok, storable_authdata()} | {error, _Reason}.
get(DataID, Ctx) ->
    call(DataID, get_storage_config(), Ctx, get).

-spec store(storable_authdata(), tk_woody_handler:handle_ctx()) -> ok | {error, exists}.
store(AuthData, Ctx) ->
    call(AuthData, get_storage_config(), Ctx, store).

-spec revoke(authdata_id(), tk_woody_handler:handle_ctx()) -> ok | {error, notfound}.
revoke(DataID, Ctx) ->
    call(DataID, get_storage_config(), Ctx, revoke).

%%

-spec get_storage_config() -> storage_config() | no_return().
get_storage_config() ->
    case genlib_app:env(token_keeper, storage) of
        StorageConf when StorageConf =/= undefined ->
            StorageConf;
        _ ->
            error({misconfiguration, {storage, not_configured}})
    end.

-spec get_storage_handler(storage()) -> machinery:logic_handler(_).
get_storage_handler(machinegun) ->
    tk_storage_machinegun.

call(Operand, StorageOpts, Ctx, Func) ->
    {Storage, Opts} = get_storage_opts(StorageOpts),
    Handler = get_storage_handler(Storage),
    Handler:Func(Operand, Opts, Ctx).

get_storage_opts(Storage) when is_atom(Storage) ->
    {Storage, #{}};
get_storage_opts({_, _} = StorageOpts) ->
    StorageOpts.
