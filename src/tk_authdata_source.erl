-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token_jwt:t(), source_opts()) -> stored_authdata() | undefined.

%% API functions

-export([get_authdata/2]).

%% API Types

-type authdata_source() :: storage_source() | extractor_source().

-type stored_authdata() :: #{
    id => tk_authority:id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    metadata => tk_authority:metadata()
}.

-export_type([authdata_source/0]).
-export_type([stored_authdata/0]).

%% Internal types

-type storage_source() :: maybe_opts(storage, tk_authdata_source_storage:source_opts()).
-type extractor_source() :: maybe_opts(extractor, tk_authdata_source_extractor:source_opts()).
-type maybe_opts(Source, Opts) :: Source | {Source, Opts}.

-type source_opts() ::
    tk_authdata_source_extractor:source_opts()
    | tk_authdata_source_storage:source_opts().

%% API functions

-spec get_authdata(authdata_source(), tk_token_jwt:t()) -> stored_authdata() | undefined.
get_authdata(AuthDataSource, Token) ->
    {Source, Opts} = get_source_opts(AuthDataSource),
    Hander = get_source_handler(Source),
    Hander:get_authdata(Token, Opts).

%%

get_source_opts({_Source, _Opts} = SourceOpts) ->
    SourceOpts;
get_source_opts(Source) when is_atom(Source) ->
    {Source, #{}}.

get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(extract) ->
    tk_authdata_source_extractor.
