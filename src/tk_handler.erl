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
            State1 = save_pulse_metadata(#{token => TokenInfo, source => TokenSourceContextDecoded}, State),
            case tk_authdata:from_token(TokenInfo, make_source_opts(TokenSourceContextDecoded)) of
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

make_source_opts(TokenSourceContext) ->
    #{
        extractor_opts => #{
            token_source => TokenSourceContext
        }
    }.

encode_auth_data(AuthData) ->
    #token_keeper_AuthData{
        id = maps:get(id, AuthData, undefined),
        token = maps:get(token, AuthData),
        %% Assume active?
        status = maps:get(status, AuthData, active),
        context = maps:get(context, AuthData),
        metadata = maps:get(metadata, AuthData, #{}),
        authority = maps:get(authority, AuthData)
    }.

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
