-module(tk_bouncer_context).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([extract_context_fragment/2]).

%%

%% Is extraction from claims a thing here?
%% Who's the authority for such tokens?
-spec extract_context_fragment(tk_token_jwt:t(), tokenkeeper:token_type()) ->
    bouncer_context_helpers:context_fragment() | undefined.
extract_context_fragment(TokenInfo, TokenType) ->
    extract_context_fragment([metadata], TokenInfo, TokenType).

extract_context_fragment([Method | Rest], TokenInfo, TokenType) ->
    case extract_context_fragment_by(Method, TokenInfo, TokenType) of
        Fragment when Fragment =/= undefined ->
            Fragment;
        undefined ->
            extract_context_fragment(Rest, TokenInfo, TokenType)
    end;
extract_context_fragment([], _, _) ->
    undefined.

%%

extract_context_fragment_by(metadata, TokenInfo, TokenType) ->
    case tk_token_jwt:get_metadata(TokenInfo) of
        #{auth_method := detect} ->
            AuthMethod = detect_auth_method(TokenType),
            build_auth_context_fragment(AuthMethod, TokenInfo);
        #{auth_method := AuthMethod} ->
            build_auth_context_fragment(AuthMethod, TokenInfo);
        #{} ->
            undefined
    end.

-spec detect_auth_method(tokenkeeper:token_type()) -> tk_token_jwt:auth_method().
detect_auth_method(api_key) ->
    api_key_token;
detect_auth_method(user_session_token) ->
    user_session_token.

-spec build_auth_context_fragment(
    tk_token_jwt:auth_method(),
    tk_token_jwt:t()
) -> bouncer_context_helpers:context_fragment().
build_auth_context_fragment(api_key_token, TokenInfo) ->
    UserID = tk_token_jwt:get_subject_id(TokenInfo),
    Acc0 = bouncer_context_helpers:empty(),
    bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => tk_token_jwt:get_token_id(TokenInfo)},
            scope => [#{party => #{id => UserID}}]
        },
        Acc0
    );
build_auth_context_fragment(user_session_token, TokenInfo) ->
    Metadata = tk_token_jwt:get_metadata(TokenInfo),
    UserID = tk_token_jwt:get_subject_id(TokenInfo),
    Expiration = tk_token_jwt:get_expires_at(TokenInfo),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_user(
        #{
            id => UserID,
            email => tk_token_jwt:get_subject_email(TokenInfo),
            realm => #{id => maps:get(user_realm, Metadata, undefined)}
        },
        Acc0
    ),
    bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(Expiration),
            token => #{id => tk_token_jwt:get_token_id(TokenInfo)}
        },
        Acc1
    ).

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.
