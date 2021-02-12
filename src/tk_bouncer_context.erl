-module(tk_bouncer_context).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([extract_context_fragment/2]).

-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().

%%

%% Is extraction from claims a thing here?
%% Who's the authority for such tokens?
-spec extract_context_fragment(tk_token_jwt:t(), token_keeper:token_type()) -> encoded_context_fragment() | undefined.
extract_context_fragment(TokenInfo, TokenType) ->
    extract_context_fragment([claim, metadata], TokenInfo, TokenType).

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

extract_context_fragment_by(claim, TokenInfo, _TokenType) ->
    % TODO
    % We deliberately do not handle decoding errors here since we extract claims from verified
    % tokens only, hence they must be well-formed here.
    Claims = tk_token_jwt:get_claims(TokenInfo),
    case get_claim(Claims) of
        {ok, ClaimFragment} ->
            ClaimFragment;
        undefined ->
            undefined
    end;
extract_context_fragment_by(metadata, TokenInfo, TokenType) ->
    case tk_token_jwt:get_metadata(TokenInfo) of
        #{auth_method := detect} ->
            AuthMethod = get_auth_method(TokenType),
            build_auth_context_fragment(AuthMethod, TokenInfo);
        #{auth_method := AuthMethod} ->
            build_auth_context_fragment(AuthMethod, TokenInfo);
        #{} ->
            undefined
    end.

get_auth_method(TokenType) ->
    TokenType.

-spec build_auth_context_fragment(
    tk_token_jwt:auth_method(),
    tk_token_jwt:t()
) -> encoded_context_fragment().
build_auth_context_fragment(api_key_token, TokenInfo) ->
    UserID = tk_token_jwt:get_subject_id(TokenInfo),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => tk_token_jwt:get_token_id(TokenInfo)},
            scope => [#{party => #{id => UserID}}]
        },
        Acc0
    ),
    encode_context_fragment(Acc1);
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
    Acc2 = bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(Expiration),
            token => #{id => tk_token_jwt:get_token_id(TokenInfo)}
        },
        Acc1
    ),
    encode_context_fragment(Acc2).

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

%%

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).

-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

-type claim() :: tk_token_jwt:claim().
-type claims() :: tk_token_jwt:claims().

-spec get_claim(claims()) ->
    {ok, encoded_context_fragment()} | {error, {unsupported, claim()} | {malformed, binary()}} | undefined.
get_claim(Claims) ->
    case maps:get(?CLAIM_BOUNCER_CTX, Claims, undefined) of
        Claim when Claim /= undefined ->
            decode_claim(Claim);
        undefined ->
            undefined
    end.

-spec decode_claim(claim()) ->
    {ok, encoded_context_fragment()} | {error, {unsupported, claim()} | {malformed, binary()}}.
decode_claim(#{
    ?CLAIM_CTX_TYPE := ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
    ?CLAIM_CTX_CONTEXT := Content
}) ->
    try
        {ok, #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = base64:decode(Content)
        }}
    catch
        % NOTE
        % The `base64:decode/1` fails in unpredictable ways.
        error:_ ->
            {error, {malformed, Content}}
    end;
decode_claim(Ctx) ->
    {error, {unsupported, Ctx}}.

%%

encode_context_fragment(ContextFragment) ->
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_fragment_content(ContextFragment)
    }.

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.
