-module(tk_extractor_claim).
-behaviour(tk_context_extractor).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    metadata_ns := binary()
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_context_extractor:extracted_context() | undefined.
get_context(Token, ExtractorOpts) ->
    % TODO
    % We deliberately do not handle decoding errors here since we extract claims from verified
    % tokens only, hence they must be well-formed here.
    case get_bouncer_claim(Token) of
        {ok, ClaimFragment} ->
            {ClaimFragment, wrap_metadata(get_metadata(Token), ExtractorOpts)};
        undefined ->
            undefined
    end.

%% Internal functions

get_metadata(Token) ->
    Metadata = maps:with(get_passthrough_claim_names(), tk_token_jwt:get_claims(Token)),
    %% @TEMP: This is a temporary hack.
    %% When some external services will stop requiring woody user identity to be present it must be removed too
    genlib_map:compact(Metadata#{
        <<"party_id">> => tk_token_jwt:get_subject_id(Token)
    }).

wrap_metadata(Metadata, _ExtractorOpts) when map_size(Metadata) =:= 0 ->
    undefined;
wrap_metadata(Metadata, ExtractorOpts) ->
    MetadataNS = maps:get(metadata_ns, ExtractorOpts),
    #{MetadataNS => Metadata}.

get_passthrough_claim_names() ->
    [
        %% token consumer
        <<"cons">>
    ].

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).

-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

-type claim() :: tk_token_jwt:claim().

-spec get_bouncer_claim(tk_token_jwt:t()) ->
    {ok, tk_context_extractor:context_fragment()}
    | {error, {unsupported, claim()} | {malformed, binary()}}
    | undefined.
get_bouncer_claim(Token) ->
    case tk_token_jwt:get_claim(?CLAIM_BOUNCER_CTX, Token, undefined) of
        Claim when Claim /= undefined ->
            decode_bouncer_claim(Claim);
        undefined ->
            undefined
    end.

-spec decode_bouncer_claim(claim()) ->
    {ok, tk_context_extractor:context_fragment()} | {error, {unsupported, claim()} | {malformed, binary()}}.
decode_bouncer_claim(#{
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
decode_bouncer_claim(Ctx) ->
    {error, {unsupported, Ctx}}.
