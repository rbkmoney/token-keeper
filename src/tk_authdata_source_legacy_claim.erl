-module(tk_authdata_source_legacy_claim).
-behaviour(tk_authdata_source).

%% Behaviour

-export([get_authdata/3]).

%% API types

-type opts() :: #{
    metadata_mappings := #{
        party_id := binary(),
        token_consumer := binary()
    }
}.
-export_type([opts/0]).

%% Internal types

-type authdata() :: tk_authdata:prototype().

%%

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_PARTY_ID, <<"sub">>).
-define(CLAIM_CONSUMER_TYPE, <<"cons">>).

%% Behaviour functions

-spec get_authdata(tk_token:token_data(), opts(), woody_context:ctx()) -> authdata() | undefined.
get_authdata(#{payload := TokenPayload}, Opts, _Context) ->
    case decode_bouncer_claim(TokenPayload) of
        {ok, ContextFragment} ->
            create_authdata(ContextFragment, create_metadata(TokenPayload, Opts));
        {error, Reason} ->
            _ = logger:warning("Failed attempt to decode bouncer context from legacy claims: ~p", [Reason]),
            undefined
    end.

%%

decode_bouncer_claim(#{?CLAIM_BOUNCER_CTX := BouncerClaim}) ->
    tk_claim_utils:decode_bouncer_claim(BouncerClaim);
decode_bouncer_claim(_Claims) ->
    {error, bouncer_claim_not_found}.

create_authdata(ContextFragment, Metadata) ->
    genlib_map:compact(#{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    }).

create_metadata(TokenPayload, Opts) ->
    Metadata = #{
        %% TODO: This is a temporary hack.
        %% When some external services will stop requiring woody user identity to be present it must be removed too
        party_id => maps:get(?CLAIM_PARTY_ID, TokenPayload, undefined),
        consumer => maps:get(?CLAIM_CONSUMER_TYPE, TokenPayload, undefined)
    },
    tk_utils:remap(genlib_map:compact(Metadata), maps:get(metadata_mappings, Opts)).
