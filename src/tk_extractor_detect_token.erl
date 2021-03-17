-module(tk_extractor_detect_token).
-behaviour(tk_context_extractor).

%% Behaviour

-export([get_context/2]).

%% API Types

-type token_source() :: #{
    request_origin => binary()
}.

-export_type([token_source/0]).

%% Behaviour

-spec get_context(tk_token_jwt:t(), tk_context_extractor:extractor_opts()) ->
    tk_context_extractor:extracted_context() | undefined.
get_context(Token, Opts = #{user_session_token_origins := UserTokenOrigins}) ->
    TokenSourceContext = tk_token_jwt:get_source_context(Token),
    Opts1 = maps:without([user_session_token_origins], Opts),
    tk_context_extractor:get_context(
        determine_token_type(TokenSourceContext, UserTokenOrigins),
        Token,
        Opts1
    ).

%% Internal functions

determine_token_type(#{request_origin := Origin}, UserTokenOrigins) ->
    case lists:member(Origin, UserTokenOrigins) of
        true ->
            user_session_token;
        false ->
            api_key_token
    end;
determine_token_type(#{}, _UserTokenOrigins) ->
    api_key_token.
