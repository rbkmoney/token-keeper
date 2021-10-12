-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token_jwt:t(), source_opts()) -> sourced_authdata() | undefined.

%% API functions

-export([get_authdata/3]).

%% API Types

-type authdata_source() :: storage_source() | claim_source() | extractor_source().
-type sourced_authdata() :: #{
    id => tk_authority:authdata_id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    authority => tk_authority:autority_id(),
    metadata => tk_authority:metadata()
}.

-type source_opts() ::
    tk_authdata_source_extractor:source_opts()
    | tk_authdata_source_claim:source_opts()
    | tk_authdata_source_storage:source_opts().

-export_type([authdata_source/0]).
-export_type([sourced_authdata/0]).
-export_type([source_opts/0]).

%% Internal types

-type storage_source() :: {storage, tk_authdata_source_storage:source_opts()}.
-type claim_source() :: {claim, tk_authdata_source_claim:source_opts()}.
-type extractor_source() :: maybe_opts(extractor, tk_authdata_source_extractor:source_opts()).

-type maybe_opts(Source, Opts) :: Source | {Source, Opts}.

%% API functions

-spec get_authdata(authdata_source(), tk_token_jwt:t(), source_opts()) -> sourced_authdata() | undefined.
get_authdata(AuthDataSource, Token, GOpts) ->
    {Source, Opts} = get_source_opts(AuthDataSource, GOpts),
    Hander = get_source_handler(Source),
    Hander:get_authdata(Token, Opts).

%%

get_source_opts({Source, Opts}, GOpts) ->
    {Source, maps:merge(GOpts, Opts)};
get_source_opts(Source, GOpts) when is_atom(Source) ->
    {Source, GOpts}.

get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(claim) ->
    tk_authdata_source_claim;
get_source_handler(extract) ->
    tk_authdata_source_extractor.
