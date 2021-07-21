-module(tk_authdata_source_storage).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/2]).

%%

-type stored_authdata() :: tk_storage:storable_authdata().
-type source_opts() :: claim_storage().

-export_type([stored_authdata/0]).
-export_type([source_opts/0]).

%%

-type claim_storage() :: maybe_opts(claim, tk_storage_claim:storage_opts()).
-type maybe_opts(Source, Opts) :: Source | {Source, Opts}.

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), source_opts()) -> stored_authdata() | undefined.
get_authdata(Token, Opts) ->
    {Storage, StorageOpts} = get_storage_opts(Opts),
    Claims = tk_token_jwt:get_claims(Token),
    case tk_storage:get_by_claims(Storage, Claims, StorageOpts) of
        {ok, AuthData} ->
            AuthData;
        {error, Reason} ->
            _ = logger:warning("Failed storage get: ~p", [Reason]),
            undefined
    end.

get_storage_opts({_Storage, _Opts} = StorageOpts) ->
    StorageOpts;
get_storage_opts(Storage) when is_atom(Storage) ->
    {Storage, #{}}.
