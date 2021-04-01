-module(tk_extractor_detect_token).
-behaviour(tk_context_extractor).

%% Behaviour

-export([get_context/2]).

%% API Types

-type token_source() :: #{
    request_origin => binary()
}.

-type extractor_opts() :: #{
    phony_api_key_opts := tk_extractor_phony_api_key:extractor_opts(),
    user_session_token_opts := tk_extractor_user_session_token:extractor_opts(),
    user_session_token_origins := list(binary()),
    metadata_ns := binary()
}.

-export_type([extractor_opts/0]).
-export_type([token_source/0]).

%% Behaviour

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_context_extractor:extracted_context() | undefined.
get_context(Token, Opts = #{user_session_token_origins := UserTokenOrigins}) ->
    TokenSourceContext = tk_token_jwt:get_source_context(Token),
    TokenType = determine_token_type(TokenSourceContext, UserTokenOrigins),
    case do_get_context(TokenType, Token, Opts) of
        {ContextFragment, Metadata0} ->
            {ContextFragment, merge_detector_metadata(TokenType, Metadata0, Opts)};
        undefined ->
            undefined
    end.

%% Internal functions

do_get_context(TokenType, Token, Opts) ->
    tk_context_extractor:get_context(TokenType, Token, get_opts(TokenType, Opts)).

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

%% @TEMP: We can't really rely on authority id like I initally thought to determine whether or not
%% we need to call userorgmgmt from *API side of things, at least for now, when the whole
%% token classification hack is in place. Will probably need to get rid of it later.
merge_detector_metadata(TokenType, Metadata0, Opts) ->
    maps:merge(Metadata0, wrap_metadata(#{<<"class">> => atom_to_binary(TokenType, utf8)}, Opts)).

wrap_metadata(Metadata, ExtractorOpts) ->
    MetadataNS = maps:get(metadata_ns, ExtractorOpts),
    #{MetadataNS => Metadata}.
