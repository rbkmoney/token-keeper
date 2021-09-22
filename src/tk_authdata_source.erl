-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(selector(), source_opts()) -> sourced_authdata() | undefined.
-callback store_authdata(sourced_authdata(), source_opts()) -> {ok, tk_token_jwt:claims()} | undefined.

%% API functions

-export([get_authdata/2]).
-export([store_authdata/2]).

%% API Types

-type selector() :: {token, tk_token_jwt:t()} | {id, tk_authority:authdata_id()}.

-type authdata_source() :: storage_source() | claim_source() | extractor_source().
-type sourced_authdata() :: #{
    id => tk_authority:authdata_id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    authority => tk_authority:autority_id(),
    metadata => tk_authority:metadata()
}.

-export_type([authdata_source/0]).
-export_type([sourced_authdata/0]).
-export_type([selector/0]).

%% Internal types

-type storage_source() :: {storage, tk_authdata_source_storage:source_opts()}.
-type claim_source() :: {claim, tk_authdata_source_claim:source_opts()}.
-type extractor_source() :: maybe_opts(extractor, tk_authdata_source_extractor:source_opts()).

-type maybe_opts(Source, Opts) :: Source | {Source, Opts}.

-type source_opts() ::
    tk_authdata_source_extractor:source_opts()
    | tk_authdata_source_claim:source_opts()
    | tk_authdata_source_storage:source_opts().

%% API functions

-spec get_authdata(authdata_source(), selector()) -> sourced_authdata() | undefined.
get_authdata(AuthDataSource, Selector) ->
    {Source, Opts} = get_source_opts(AuthDataSource),
    Hander = get_source_handler(Source),
    Hander:get_authdata(Selector, Opts).

-spec store_authdata(authdata_source(), sourced_authdata()) -> {ok, tk_token_jwt:claims()} | undefined.
store_authdata(AuthDataSource, AuthData) ->
    {Source, Opts} = get_source_opts(AuthDataSource),
    Hander = get_source_handler(Source),
    Hander:store_authdata(AuthData, Opts).

%%

get_source_opts({_Source, _Opts} = SourceOpts) ->
    SourceOpts;
get_source_opts(Source) when is_atom(Source) ->
    {Source, #{}}.

get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(claim) ->
    tk_authdata_source_claim;
get_source_handler(extract) ->
    tk_authdata_source_extractor.
