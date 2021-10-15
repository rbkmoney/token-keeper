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

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()} | no_return().
handle_function(Op, Args, WoodyCtx, Opts) ->
    State = make_state(WoodyCtx, Opts),
    handle_function_(Op, Args, State).

handle_function_('Create' = Op, {ID, ContextFragment, Metadata}, State) ->
    %% Create - создает новую AuthData, используя переданные в качестве
    %% аргументов данные и сохраняет их в хранилище, после чего выписывает
    %% новый JWT-токен, в котором содержится AuthDataID (на данный момент
    %% предполагается, что AuthDataID == jwt-клейму “JTI”). По умолчанию
    %% status токена - active; authority - id выписывающей authority.
    _ = handle_beat(Op, started, State),
    AuthorityConf = get_autority_config(get_issuing_authority()),
    AuthData = issue_auth_data(ID, ContextFragment, Metadata, AuthorityConf),
    case store(AuthData, build_context(State)) of
        ok ->
            {ok, Token} = tk_token_jwt:issue(ID, #{}, get_signer(AuthorityConf)),
            EncodedAuthData = encode_auth_data(AuthData#{token => Token}),
            _ = handle_beat(Op, succeeded, State),
            {ok, EncodedAuthData};
        {error, exists} ->
            _ = handle_beat(Op, {failed, exists}, State),
            woody_error:raise(business, #token_keeper_AuthDataAlreadyExists{})
    end;
handle_function_('CreateEphemeral' = Op, {ContextFragment, Metadata}, State) ->
    _ = handle_beat(Op, started, State),
    AuthorityConf = get_autority_config(get_issuing_authority()),
    AuthData = issue_auth_data(ContextFragment, Metadata, AuthorityConf),
    Claims = tk_token_claim_utils:encode_authdata(AuthData),
    {ok, Token} = tk_token_jwt:issue(unique_id(), Claims, get_signer(AuthorityConf)),
    EncodedAuthData = encode_auth_data(AuthData#{token => Token}),
    _ = handle_beat(Op, succeeded, State),
    {ok, EncodedAuthData};
handle_function_('AddExistingToken', _, _State) ->
    erlang:error(not_implemented);
handle_function_('GetByToken' = Op, {Token, TokenSourceContext}, State) ->
    _ = handle_beat(Op, started, State),
    TokenSourceContextDecoded = decode_source_context(TokenSourceContext),
    case verify_token(Token, TokenSourceContextDecoded) of
        {ok, TokenInfo} ->
            State1 = save_pulse_metadata(#{token => TokenInfo}, State),
            {_, Authority} = get_autority_config(get_token_authority(TokenInfo)),
            case tk_authority:get_authdata_by_token(TokenInfo, Authority, build_context(State)) of
                {ok, AuthDataPrototype} ->
                    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
                    _ = handle_beat(Op, succeeded, State1),
                    {ok, EncodedAuthData};
                {error, Reason} ->
                    _ = handle_beat(Op, {failed, Reason}, State1),
                    woody_error:raise(business, #token_keeper_AuthDataNotFound{})
            end;
        {error, {verification, Reason}} ->
            _ = handle_beat(Op, {failed, {token_verification, Reason}}, State),
            woody_error:raise(business, #token_keeper_InvalidToken{});
        {error, blacklisted} ->
            _ = handle_beat(Op, {failed, blacklisted}, State),
            woody_error:raise(business, #token_keeper_AuthDataRevoked{})
    end;
handle_function_('Get' = Op, {ID}, State) ->
    _ = handle_beat(Op, started, State),

    case get_authdata_by_id(ID, build_context(State)) of
        {ok, AuthData} ->
            EncodedAuthData = encode_auth_data(AuthData),
            _ = handle_beat(Op, succeeded, State),
            {ok, EncodedAuthData};
        {error, Reason} ->
            _ = handle_beat(Op, {failed, Reason}, State),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end;
handle_function_('Revoke' = Op, {ID}, State) ->
    _ = handle_beat(Op, started, State),

    case revoke(ID, build_context(State)) of
        ok ->
            _ = handle_beat(Op, succeeded, State),
            {ok, ok};
        {error, notfound} ->
            _ = handle_beat(Op, {failed, notfound}, State),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end.

%% Internal functions

verify_token(Token, TokenSourceContextDecoded) ->
    case tk_token_jwt:verify(Token, TokenSourceContextDecoded) of
        {ok, TokenInfo} ->
            case check_blacklist(TokenInfo) of
                false ->
                    {ok, TokenInfo};
                true ->
                    {error, blacklisted}
            end;
        {error, Reason} ->
            {error, {verification, Reason}}
    end.

check_blacklist(TokenInfo) ->
    tk_token_blacklist:is_blacklisted(get_token_id(TokenInfo), get_token_authority(TokenInfo)).

%%

issue_auth_data(ContextFragment, Metadata, AuthorityConf) ->
    issue_auth_data(undefined, ContextFragment, Metadata, AuthorityConf).

issue_auth_data(ID, ContextFragment, Metadata, {_, Authority}) ->
    tk_authority:create_authdata(ID, ContextFragment, Metadata, Authority).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

build_context(#state{woody_context = WC}) ->
    #{woody_ctx => WC}.

make_state(WoodyCtx, Opts) ->
    #state{
        woody_context = WoodyCtx,
        pulse = maps:get(pulse, Opts, []),
        pulse_metadata = #{woody_ctx => WoodyCtx}
    }.

encode_auth_data(AuthData) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = maps:get(token, AuthData, undefined),
        %% Assume active?
        status = maps:get(status, AuthData),
        context = maps:get(context, AuthData),
        metadata = maps:get(metadata, AuthData, #{}),
        authority = maps:get(authority, AuthData, undefined)
    }.

decode_source_context(TokenSourceContext) ->
    genlib_map:compact(#{
        request_origin => TokenSourceContext#token_keeper_TokenSourceContext.request_origin
    }).

%%

get_token_id(TokenInfo) ->
    tk_token_jwt:get_token_id(TokenInfo).

get_token_authority(TokenInfo) ->
    tk_token_jwt:get_authority(TokenInfo).

get_autority_config(AuthorityID) ->
    Authorities = application:get_env(token_keeper, authorities, #{}),
    case maps:get(AuthorityID, Authorities, undefined) of
        Config when Config =/= undefined ->
            {AuthorityID, Config};
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
            error({misconfiguration, {issuing, not_configured}})
    end.

%%

get_signer({AuthorityID, AuthorityConf}) ->
    SignerKID = tk_authority:get_signer(AuthorityConf),
    case tk_token_jwt:get_key_authority(SignerKID) of
        {ok, AuthorityID} ->
            SignerKID;
        {ok, OtherAuthorityID} ->
            error({misconfiguration, {issuing, {key_ownership_error, {AuthorityID, OtherAuthorityID}}}});
        _ ->
            error({misconfiguration, {issuing, {no_key, SignerKID}}})
    end.

%%

get_authdata_by_id(ID, Ctx) ->
    tk_storage:get(ID, get_storage_opts(), Ctx).

store(AuthData, Ctx) ->
    tk_storage:store(AuthData, get_storage_opts(), Ctx).

revoke(ID, Ctx) ->
    tk_storage:revoke(ID, get_storage_opts(), Ctx).

get_storage_opts() ->
    application:get_env(token_keeper, storage, #{}).

%%

handle_beat(Op, Event, State) ->
    tk_pulse:handle_beat({encode_pulse_op(Op), Event}, State#state.pulse_metadata, State#state.pulse).

save_pulse_metadata(Metadata, State = #state{pulse_metadata = PulseMetadata}) ->
    State#state{pulse_metadata = maps:merge(Metadata, PulseMetadata)}.

encode_pulse_op('CreateEphemeral') ->
    create_ephemeral;
encode_pulse_op('GetByToken') ->
    get_by_token;
encode_pulse_op('Create') ->
    create;
encode_pulse_op('Get') ->
    get;
encode_pulse_op('Revoke') ->
    revoke.
