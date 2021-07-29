-module(tk_woody_handler).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% Woody handler

-behaviour(woody_server_thrift_handler).
-export([handle_function/4]).

%% Internal types

-type opts() :: #{
    pulse => tk_pulse:handlers()
}.

-record(state, {
    woody_context :: woody_context:ctx(),
    pulse :: tk_pulse:handlers(),
    pulse_metadata :: tk_pulse:metadata()
}).

%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()}.
handle_function(Op, Args, WoodyCtx, Opts) ->
    State = make_state(WoodyCtx, Opts),
    handle_function_(Op, Args, State).

handle_function_('Create', {_ID, _ContextFragment, _Metadata}, _State) ->
    %% TODO: Change protocol to include authdata id
    erlang:error(not_implemented);
handle_function_('CreateEphemeral' = Op, {ContextFragment, Metadata}, State) ->
    _ = handle_beat(Op, started, State),
    StorageType = claim,
    AuthorityID = get_issuing_authority(),
    AuthData = issue_token(ContextFragment, Metadata, AuthorityID, StorageType),
    _ = handle_beat(Op, succeeded, State),
    {ok, AuthData};
handle_function_('AddExistingToken', _, _State) ->
    erlang:error(not_implemented);
handle_function_('GetByToken' = Op, {Token, TokenSourceContext}, State) ->
    _ = handle_beat(Op, started, State),
    TokenSourceContextDecoded = decode_source_context(TokenSourceContext),
    case tk_token_jwt:verify(Token, TokenSourceContextDecoded) of
        {ok, TokenInfo} ->
            State1 = save_pulse_metadata(#{token => TokenInfo}, State),
            Authority = get_autority_config(get_token_authority(TokenInfo)),
            case tk_authority:get_authdata_by_token(TokenInfo, Authority) of
                {ok, AuthDataPrototype} ->
                    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
                    _ = handle_beat(Op, succeeded, State1),
                    {ok, EncodedAuthData};
                {error, Reason} ->
                    _ = handle_beat(Op, {failed, {not_found, Reason}}, State1),
                    woody_error:raise(business, #token_keeper_AuthDataNotFound{})
            end;
        {error, Reason} ->
            _ = handle_beat(Op, {failed, {token_verification, Reason}}, State),
            woody_error:raise(business, #token_keeper_InvalidToken{})
    end;
handle_function_('Get', _, _State) ->
    erlang:error(not_implemented);
handle_function_('Revoke', _, _State) ->
    erlang:error(not_implemented).

%% Internal functions

issue_token(ContextFragment, Metadata, AuthorityID, StorageType) ->
    issue_token(undefined, ContextFragment, Metadata, AuthorityID, StorageType).

issue_token(ID, ContextFragment, Metadata, AuthorityID, StorageType) ->
    Authority = get_autority_config(AuthorityID),
    AuthDataPrototype = tk_authority:create_authdata(ID, ContextFragment, Metadata, Authority),
    {ok, StorageClaims} = tk_storage:store(AuthDataPrototype, StorageType),
    {ok, Token} = tk_token_jwt:issue(StorageClaims, get_signer(AuthorityID, Authority)),
    encode_auth_data(AuthDataPrototype#{token => Token}).

make_state(WoodyCtx, Opts) ->
    #state{
        woody_context = WoodyCtx,
        pulse = maps:get(pulse, Opts, []),
        pulse_metadata = #{woody_ctx => WoodyCtx}
    }.

encode_auth_data(AuthData) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = maps:get(token, AuthData),
        %% Assume active?
        status = maps:get(status, AuthData),
        context = maps:get(context, AuthData),
        metadata = maps:get(metadata, AuthData, #{}),
        authority = maps:get(authority, AuthData)
    }.

decode_source_context(TokenSourceContext) ->
    genlib_map:compact(#{
        request_origin => TokenSourceContext#token_keeper_TokenSourceContext.request_origin
    }).

%%

get_token_authority(TokenInfo) ->
    tk_token_jwt:get_authority(TokenInfo).

get_autority_config(AuthorityID) ->
    Authorities = application:get_env(token_keeper, authorities, #{}),
    case maps:get(AuthorityID, Authorities, undefined) of
        Config when Config =/= undefined ->
            Config;
        undefined ->
            throw({misconfiguration, {no_such_authority, AuthorityID}})
    end.

get_issuing_authority() ->
    maps:get(authority, get_issuing_config()).

get_issuing_config() ->
    case application:get_env(token_keeper, issuing, undefined) of
        Config when Config =/= undefined ->
            Config;
        undefined ->
            throw({misconfiguration, {issuing, not_configured}})
    end.

%%

get_signer(AuthorityID, Authority) ->
    SignerKID = tk_authority:get_signer(Authority),
    case tk_token_jwt:get_key_authority(SignerKID) of
        {ok, AuthorityID} ->
            SignerKID;
        {ok, OtherAuthorityID} ->
            throw({misconfiguration, {issuing, {key_ownership_error, {AuthorityID, OtherAuthorityID}}}});
        _ ->
            throw({misconfiguration, {issuing, {no_key, SignerKID}}})
    end.

%%

handle_beat(Op, Event, State) ->
    tk_pulse:handle_beat({encode_pulse_op(Op), Event}, State#state.pulse_metadata, State#state.pulse).

save_pulse_metadata(Metadata, State = #state{pulse_metadata = PulseMetadata}) ->
    State#state{pulse_metadata = maps:merge(Metadata, PulseMetadata)}.

encode_pulse_op('CreateEphemeral') ->
    create_ephemeral;
encode_pulse_op('GetByToken') ->
    get_by_token.
