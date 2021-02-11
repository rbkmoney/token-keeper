-module(tk_handler).

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

-define(TK_METADATA_NS, <<"com.rbkmoney.token-keeper">>).

%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()}.
handle_function(Op, Args, WoodyCtx, Opts) ->
    State = make_state(WoodyCtx, Opts),
    do_handle_function(Op, Args, State).

do_handle_function('Create', _, _State) ->
    erlang:error(not_implemented);
do_handle_function('CreateEphemeral', _, _State) ->
    erlang:error(not_implemented);
do_handle_function('AddExistingToken', _, _State) ->
    erlang:error(not_implemented);
do_handle_function('GetByToken' = Op, {Token, TokenSourceContext}, State) ->
    _ = handle_beat(Op, started, State),
    case tk_token_jwt:verify(Token) of
        {ok, TokenInfo} ->
            TokenSourceContextDecoded = decode_source_context(TokenSourceContext),
            State1 = save_pulse_metadata(#{token_info => TokenInfo, token_source => TokenSourceContextDecoded}, State),
            case extract_auth_data(TokenInfo, TokenSourceContextDecoded) of
                {ok, AuthDataPrototype} ->
                    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
                    _ = handle_beat(Op, succeeded, State1),
                    {ok, EncodedAuthData};
                {error, Reason} ->
                    _ = handle_beat(Op, {failed, {context_creaton, Reason}}, State1),
                    woody_error:raise(business, #token_keeper_ContextCreationFailed{})
            end;
        {error, Reason} ->
            _ = handle_beat(Op, {failed, {token_verification, Reason}}, State),
            woody_error:raise(business, #token_keeper_InvalidToken{})
    end;
do_handle_function('Get', _, _State) ->
    erlang:error(not_implemented);
do_handle_function('Revoke', _, _State) ->
    erlang:error(not_implemented).

%% Internal functions

make_state(WoodyCtx, Opts) ->
    #state{
        woody_context = WoodyCtx,
        pulse = maps:get(pulse, Opts, []),
        pulse_metadata = #{woody_ctx => WoodyCtx}
    }.

extract_auth_data(TokenInfo, TokenSourceContext) ->
    TokenType = determine_token_type(TokenSourceContext),
    case tk_bouncer_context:extract_context_fragment(TokenInfo, TokenType) of
        ContextFragment when ContextFragment =/= undefined ->
            AuthDataPrototype = #{
                %% Assume active?
                status => active,
                context => ContextFragment,
                metadata => extract_token_metadata(TokenType, TokenInfo),
                authority => get_authority(TokenInfo)
            },
            {ok, AuthDataPrototype};
        undefined ->
            {error, unable_to_infer_auth_data}
    end.

determine_token_type(#{request_origin := Origin}) ->
    UserTokenOrigins = application:get_env(token_keeper, user_session_token_origins, []),
    case lists:member(Origin, UserTokenOrigins) of
        true ->
            user_session_token;
        false ->
            api_key_token
    end;
determine_token_type(#{}) ->
    api_key_token.

get_authority(TokenInfo) ->
    Metadata = tk_token_jwt:get_metadata(TokenInfo),
    maps:get(authority, Metadata).

extract_token_metadata(api_key_token, TokenInfo) ->
    #{
        <<"party_id">> => tk_token_jwt:get_subject_id(TokenInfo)
    };
extract_token_metadata(user_session_token, _TokenInfo) ->
    undefined.

encode_auth_data(AuthData) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = maps:get(token, AuthData),
        status = maps:get(status, AuthData),
        context = encode_context_fragment(maps:get(context, AuthData)),
        metadata = encode_metadata(maps:get(metadata, AuthData, undefined)),
        authority = maps:get(authority, AuthData)
    }.

encode_metadata(Metadata) ->
    genlib_map:compact(#{?TK_METADATA_NS => Metadata}).

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

decode_source_context(TokenSourceContext) ->
    genlib_map:compact(#{
        request_origin => TokenSourceContext#token_keeper_TokenSourceContext.request_origin
    }).

%%

handle_beat(Op, Event, State) ->
    tk_pulse:handle_beat({encode_pulse_op(Op), Event}, State#state.pulse_metadata, State#state.pulse).

save_pulse_metadata(Metadata, State = #state{pulse_metadata = PulseMetadata}) ->
    State#state{pulse_metadata = maps:merge(Metadata, PulseMetadata)}.

encode_pulse_op('GetByToken') ->
    get_by_token.
