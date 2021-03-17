-module(tk_context_extractor).

%% Behaviour

-callback get_context(tk_token_jwt:t(), extractor_opts()) -> extracted_context() | undefined.

%% API functions

-export([get_context/3]).

%% API Types

-type methods() :: [{method(), extractor_opts()} | method()].
-type method() :: claim | detect_token | api_key_token | user_session_token.

-type extractor_opts() :: #{
    user_session_token_origins => list(binary()),
    user_realm => binary()
}.

-type extracted_context() :: {context_fragment(), tk_authdata:metadata() | undefined}.

-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type context_fragment() ::
    {encoded_context_fragment, encoded_context_fragment()}
    | bouncer_context_helpers:context_fragment().

-export_type([methods/0]).
-export_type([method/0]).
-export_type([extractor_opts/0]).
-export_type([extracted_context/0]).
-export_type([encoded_context_fragment/0]).
-export_type([context_fragment/0]).

%% API functions

-spec get_context(method(), tk_token_jwt:t(), extractor_opts()) -> extracted_context() | undefined.
get_context(Method, Token, Opts) ->
    Hander = get_extractor_handler(Method),
    Hander:get_context(Token, Opts).

%%

get_extractor_handler(claim) ->
    tk_extractor_claim;
get_extractor_handler(detect_token) ->
    tk_extractor_detect_token;
get_extractor_handler(api_key_token) ->
    tk_extractor_api_key_token;
get_extractor_handler(user_session_token) ->
    tk_extractor_user_session_token.
