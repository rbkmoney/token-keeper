-module(tk_extractor_detect_token).
-behaviour(tk_extractor).

%% Behaviour

-export([get_context/2]).

%% API Types

-type token_source() :: #{
    request_origin => binary()
}.

-type extractor_opts() :: #{
    phony_api_key_opts := tk_extractor_phony_api_key:extractor_opts(),
    user_session_token_opts := tk_extractor_user_session_token:extractor_opts(),
    user_session_token_origins := list(binary())
}.

-export_type([extractor_opts/0]).
-export_type([token_source/0]).

%% Behaviour

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_extractor:extracted_context() | undefined.
get_context(Token, Opts = #{user_session_token_origins := UserTokenOrigins}) ->
    TokenSourceContext = tk_token_jwt:get_source_context(Token),
    TokenType = determine_token_type(TokenSourceContext, UserTokenOrigins),
    tk_extractor:get_context(TokenType, Token, get_opts(TokenType, Opts)).

%% Internal functions

determine_token_type(#{request_origin := Origin}, UserTokenOrigins) ->
    case lists:member(Origin, UserTokenOrigins) of
        true ->
            user_session_token;
        false ->
            phony_api_key
    end;
determine_token_type(#{}, _UserTokenOrigins) ->
    phony_api_key.

get_opts(user_session_token, #{user_session_token_opts := Opts}) ->
    Opts;
get_opts(phony_api_key, #{phony_api_key_opts := Opts}) ->
    Opts.
