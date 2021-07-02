-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token_jwt:t(), source_opts()) -> stored_authdata() | undefined.

%% API functions

-export([get_authdata/3]).

%% API Types

-type authdata_source() :: token_source() | {token_source(), source_opts()}.

-type token_source() :: storage | extractor.

-type source_opts() ::
    tk_authdata_source_extractor:source_opts()
    | tk_authdata_source_storage:source_opts().

-type stored_authdata() :: #{
    id => tk_authority:id(),
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    metadata => tk_authority:metadata()
}.

-export_type([authdata_source/0]).
-export_type([token_source/0]).
-export_type([source_opts/0]).
-export_type([stored_authdata/0]).

%% API functions

-spec get_authdata(token_source(), tk_token_jwt:t(), source_opts()) -> stored_authdata() | undefined.
get_authdata(Source, Token, Opts) ->
    Hander = get_source_handler(Source),
    Hander:get_authdata(Token, Opts).

%%

get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(extract) ->
    tk_authdata_source_extractor.
