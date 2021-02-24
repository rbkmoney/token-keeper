-module(tk_extractor_claim).
-behaviour(tk_context_extractor).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([get_context/2]).

%% API functions

-spec get_context(tk_token_jwt:t(), tk_context_extractor:extractor_opts()) ->
    tk_context_extractor:extracted_context() | undefined.
get_context(Token, _ExtractorOpts) ->
    % TODO
    % We deliberately do not handle decoding errors here since we extract claims from verified
    % tokens only, hence they must be well-formed here.
    Claims = tk_token_jwt:get_claims(Token),
    case get_claim(Claims) of
        {ok, ClaimFragment} ->
            {ClaimFragment, undefined};
        undefined ->
            undefined
    end.

%% Internal functions

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).

-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

-type claim() :: tk_token_jwt:claim().
-type claims() :: tk_token_jwt:claims().

-spec get_claim(claims()) ->
    {ok, tk_context_extractor:context_fragment()}
    | {error, {unsupported, claim()} | {malformed, binary()}}
    | undefined.
get_claim(Claims) ->
    case maps:get(?CLAIM_BOUNCER_CTX, Claims, undefined) of
        Claim when Claim /= undefined ->
            decode_claim(Claim);
        undefined ->
            undefined
    end.

-spec decode_claim(claim()) ->
    {ok, tk_context_extractor:context_fragment()} | {error, {unsupported, claim()} | {malformed, binary()}}.
decode_claim(#{
    ?CLAIM_CTX_TYPE := ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
    ?CLAIM_CTX_CONTEXT := Content
}) ->
    try
        {ok,
            {encoded_context_fragment, #bctx_ContextFragment{
                type = v1_thrift_binary,
                content = base64:decode(Content)
            }}}
    catch
        % NOTE
        % The `base64:decode/1` fails in unpredictable ways.
        error:_ ->
            {error, {malformed, Content}}
    end;
decode_claim(Ctx) ->
    {error, {unsupported, Ctx}}.
