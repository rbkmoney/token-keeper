-module(tk_context_extractor).

%% Behaviour

-callback get_context(tk_token_jwt:t(), extractor_opts()) -> extracted_context() | undefined.

%% API functions

-export([get_context/3]).

%% API Types

-type methods() :: [{method(), extractor_opts()} | method()].
-type method() :: detect_token | api_key_token | user_session_token | invoice_template_access_token.

-type extractor_opts() ::
    tk_extractor_detect_token:extractor_opts()
    | tk_extractor_phony_api_key:extractor_opts()
    | tk_extractor_user_session_token:extractor_opts()
    | tk_extractor_invoice_tpl_token:extractor_opts().

-type extracted_context() :: {context_fragment(), tk_authority:metadata() | undefined}.
-type context_fragment() :: bouncer_context_helpers:context_fragment().

-export_type([methods/0]).
-export_type([method/0]).
-export_type([extractor_opts/0]).
-export_type([extracted_context/0]).
-export_type([context_fragment/0]).

%% API functions

-spec get_context(method(), tk_token_jwt:t(), extractor_opts()) -> extracted_context() | undefined.
get_context(Method, Token, Opts) ->
    Hander = get_extractor_handler(Method),
    Hander:get_context(Token, Opts).

%%

get_extractor_handler(detect_token) ->
    tk_extractor_detect_token;
get_extractor_handler(phony_api_key) ->
    tk_extractor_phony_api_key;
get_extractor_handler(user_session_token) ->
    tk_extractor_user_session_token;
get_extractor_handler(invoice_template_access_token) ->
    tk_extractor_invoice_tpl_token.
