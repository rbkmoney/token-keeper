-module(tk_storage).

%%

-export([child_specs/1]).
-behaviour(supervisor).
-export([init/1]).

%%

-export([get/3]).
-export([store/3]).
-export([revoke/3]).

%%

-callback get(authdata_id(), storage_opts(), woody_context:ctx()) -> {ok, authdata()} | {error, _Reason}.
-callback store(authdata(), storage_opts(), woody_context:ctx()) -> ok | {error, _Reason}.
-callback revoke(authdata_id(), storage_opts(), woody_context:ctx()) -> ok | {error, _Reason}.

%%

-type storage_name() :: binary().

-export_type([storage_name/0]).

%%

-type authdata() :: tk_authdata:prototype().
-type authdata_id() :: tk_authdata:id().
-type storage_opts() :: tk_storage_machinegun:storage_opts().
-type storages_config() :: #{storage_name() => storage_config()}.
-type storage_config() :: machinegun_storage_config().
-type machinegun_storage_config() :: {machinegun, tk_storage_machinegun:storage_opts()}.

%%

-define(PTERM_KEY(Key), {?MODULE, Key}).
-define(STORAGE_NAME(StorageName), ?PTERM_KEY({storage_name, StorageName})).

%%

-spec child_specs(storages_config()) -> [supervisor:child_spec()].
child_specs(StorageOpts) ->
    [
        #{
            id => ?MODULE,
            start => {supervisor, start_link, [?MODULE, StorageOpts]},
            type => supervisor
        }
    ].

-spec init(storages_config()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(StoragesConfig) ->
    _ = store_configs(StoragesConfig),
    {ok, {#{}, []}}.

%%

-spec get(authdata_id(), storage_name(), woody_context:ctx()) -> {ok, authdata()} | {error, _Reason}.
get(AuthDataID, StorageName, Ctx) ->
    call(get, AuthDataID, get_config(StorageName), Ctx).

-spec store(authdata(), storage_name(), woody_context:ctx()) -> ok | {error, exists}.
store(AuthData, StorageName, Ctx) ->
    call(store, AuthData, get_config(StorageName), Ctx).

-spec revoke(authdata_id(), storage_name(), woody_context:ctx()) -> ok | {error, notfound}.
revoke(AuthDataID, StorageName, Ctx) ->
    call(revoke, AuthDataID, get_config(StorageName), Ctx).

%%

store_configs(StoragesConfig) ->
    maps:foreach(fun store_config/2, StoragesConfig).

store_config(StorageName, StorageOpts) ->
    ok = persistent_term:put(?STORAGE_NAME(StorageName), StorageOpts).

get_config(StorageName) ->
    persistent_term:get(?STORAGE_NAME(StorageName), undefined).

%%

get_storage_handler(machinegun) ->
    tk_storage_machinegun.

call(Func, Operand, {Storage, Opts}, Ctx) ->
    Handler = get_storage_handler(Storage),
    Handler:Func(Operand, Opts, Ctx).
