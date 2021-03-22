-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token_jwt:t(), source_opts()) -> tk_authority:authdata() | undefined.

%% API functions

-export([get_authdata/3]).

%% API Types

-type authdata_source() :: token_source() | {token_source(), source_opts()}.

-type token_source() :: storage | extractor.

-type source_opts() :: #{
    methods => tk_context_extractor:methods(),
    metadata_ns => binary()
}.

-export_type([authdata_source/0]).
-export_type([token_source/0]).
-export_type([source_opts/0]).

%% API functions

-spec get_authdata(token_source(), tk_token_jwt:t(), source_opts()) -> tk_authority:authdata() | undefined.
get_authdata(Source, Token, Opts) ->
    Hander = get_source_handler(Source),
    Hander:get_authdata(Token, Opts).

%%

get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(extract) ->
    tk_authdata_source_extractor.
