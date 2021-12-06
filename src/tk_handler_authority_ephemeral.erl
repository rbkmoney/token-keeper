-module(tk_handler_authority_ephemeral).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% Woody handler

-behaviour(tk_handler).
-export([handle_function/4]).

%% Internal types

-type opts() :: #{
    token := token_opts()
}.

-type token_opts() :: #{
    type := tk_token:token_type(),
    authority_id := tk_token:authority_id()
}.

%%

-spec handle_function(woody:func(), woody:args(), opts(), tk_handler:state()) -> {ok, woody:result()} | no_return().
handle_function('Create' = Op, {ContextFragment, Metadata}, Opts, State) ->
    _ = pulse_op_stated(Op, State),
    AuthDataPrototype = create_auth_data(ContextFragment, Metadata),
    Claims = tk_claim_utils:encode_authdata(AuthDataPrototype),
    {ok, Token} = tk_token_jwt:issue(create_token_data(Claims, Opts)),
    EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
    _ = pulse_op_succeeded(Op, State),
    {ok, EncodedAuthData}.

%% Internal functions

create_auth_data(ContextFragment, Metadata) ->
    tk_authdata:create_prototype(undefined, ContextFragment, Metadata).

%%

create_token_data(Claims, #{token := TokenOpts}) ->
    #{
        id => unique_id(),
        type => maps:get(type, TokenOpts),
        authority_id => maps:get(authority_id, TokenOpts),
        expiration => unlimited,
        payload => Claims
    }.

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

encode_auth_data(
    #{
        token := Token,
        status := Status,
        context := Context
    } = AuthData
) ->
    #token_keeper_AuthData{
        token = Token,
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{})
    }.

%%

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

encode_beat_op('Create') ->
    {ephemeral, create}.

handle_beat(Op, Event, #{pulse_metadata := PulseMetadata, pulse := Pulse}) ->
    tk_pulse:handle_beat({encode_beat_op(Op), Event}, PulseMetadata, Pulse).
