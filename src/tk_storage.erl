-module(tk_storage).

-export([get/2]).
-export([store/2]).
-export([revoke/2]).
-export([get_storage_handler/1]).

%%

-callback get(authdata_id(), opts()) -> {ok, tk_storage:storable_authdata()} | {error, _Reason}.
-callback store(tk_storage:storable_authdata(), opts()) -> ok | {error, _Reason}.
-callback revoke(authdata_id(), opts()) -> ok | {error, _Reason}.

%%

-type storage_opts() :: opts().

-type storable_authdata() :: #{
    id => tk_authority:authdata_id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    authority => tk_authority:autority_id(),
    metadata => tk_authority:metadata()
}.

-export_type([storable_authdata/0]).
-export_type([storage_opts/0]).

%%

-type authdata_id() :: tk_authority:authdata_id().

-type storage() :: machinegun.
-type opts() :: tk_storage_machinegun:storage_opts().

%%

-spec get(authdata_id(), storage_opts()) -> {ok, storable_authdata()} | {error, _Reason}.
get(DataID, StorageOpts) ->
    call(DataID, StorageOpts, get).

-spec store(storable_authdata(), storage_opts()) -> ok | {error, exists}.
store(AuthData, StorageOpts) ->
    call(AuthData, StorageOpts, store).

-spec revoke(authdata_id(), storage_opts()) -> ok | {error, notfound}.
revoke(DataID, StorageOpts) ->
    call(DataID, StorageOpts, revoke).

-spec get_storage_handler(storage()) -> machinery:logic_handler(_).
get_storage_handler(machinegun) ->
    tk_storage_machinegun.

%%

call(Operand, StorageOpts, Func) ->
    case get_storage_opts(StorageOpts) of
        {error, _} = Err ->
            Err;
        {Storage, Opts} ->
            Handler = get_storage_handler(Storage),
            Handler:Func(Operand, Opts)
    end.

get_storage_opts(#{backend := Storage} = StorageOpts) when is_atom(Storage) ->
    {Storage, StorageOpts};
get_storage_opts(#{} = StorageOpts) ->
    {machinegun, StorageOpts};
get_storage_opts(StorageOpts) ->
    {error, {misconfiguration, {no_storage_options, StorageOpts}}}.
