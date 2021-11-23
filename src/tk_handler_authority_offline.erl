-module(tk_handler_authority_offline).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% Woody handler

-behaviour(tk_handler).
-export([handle_function/4]).

%% Internal types

-type opts() :: #{
    authority_id := tk_authdata:authority_id()
}.

%%

-spec handle_function(woody:func(), woody:args(), opts(), tk_handler:state()) -> {ok, woody:result()} | no_return().
handle_function('Create' = Op, {ID, ContextFragment, Metadata}, #{authority_id := AuthorityID}, State) ->
    %% Create - создает новую AuthData, используя переданные в качестве
    %% аргументов данные и сохраняет их в хранилище, после чего выписывает
    %% новый JWT-токен, в котором содержится AuthDataID (на данный момент
    %% предполагается, что AuthDataID == jwt-клейму “JTI”). По умолчанию
    %% status токена - active; authority - id выписывающей authority.
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    AuthDataPrototype = create_auth_data(ID, ContextFragment, Metadata, AuthorityID),
    case store(AuthDataPrototype, State1) of
        ok ->
            {ok, Token} = tk_token_jwt:issue(create_token_data(ID), AuthorityID),
            EncodedAuthData = encode_auth_data(AuthDataPrototype#{token => Token}),
            _ = pulse_op_succeeded(Op, State1),
            {ok, EncodedAuthData};
        {error, exists} ->
            _ = pulse_op_failed(Op, exists, State1),
            woody_error:raise(business, #token_keeper_AuthDataAlreadyExists{})
    end;
handle_function('Get' = Op, {ID}, _Opts, State) ->
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    case get_authdata(ID, State1) of
        {ok, AuthDataPrototype} ->
            %% The initial token is not recoverable at this point
            EncodedAuthData = encode_auth_data(AuthDataPrototype),
            _ = pulse_op_succeeded(Op, State1),
            {ok, EncodedAuthData};
        {error, Reason} ->
            _ = pulse_op_failed(Op, Reason, State1),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end;
handle_function('Revoke' = Op, {ID}, _Opts, State) ->
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    case revoke(ID, State1) of
        ok ->
            _ = pulse_op_succeeded(Op, State1),
            {ok, ok};
        {error, notfound = Reason} ->
            _ = pulse_op_failed(Op, Reason, State1),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end.

%% Internal functions

create_auth_data(ID, ContextFragment, Metadata, AuthorityID) ->
    tk_authdata:create_prototype(ID, ContextFragment, Metadata, AuthorityID).

create_token_data(ID) ->
    #{
        id => ID,
        expiration => unlimited,
        payload => #{}
    }.

%%

get_authdata(ID, #{context := Context}) ->
    tk_storage:get(ID, Context).

store(AuthData, #{context := Context}) ->
    tk_storage:store(AuthData, Context).

revoke(ID, #{context := Context}) ->
    tk_storage:revoke(ID, Context).

%%

encode_auth_data(
    #{
        id := ID,
        status := Status,
        context := Context
    } = AuthData
) ->
    #token_keeper_AuthData{
        id = ID,
        token = maps:get(token, AuthData, undefined),
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{})
    }.

%%

save_pulse_metadata(Metadata, State = #{pulse_metadata := PulseMetadata}) ->
    State#{pulse_metadata => maps:merge(Metadata, PulseMetadata)}.

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

pulse_op_failed(Op, Reason, State) ->
    handle_beat(Op, {failed, Reason}, State).

encode_beat_op('Create') ->
    create;
encode_beat_op('Get') ->
    get;
encode_beat_op('Revoke') ->
    revoke.

handle_beat(Op, Event, #{pulse_metadata := PulseMetadata, pulse := Pulse}) ->
    tk_pulse:handle_beat({encode_beat_op(Op), Event}, PulseMetadata, Pulse).
