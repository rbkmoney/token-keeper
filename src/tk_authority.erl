-module(tk_authority).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([get_id/1]).
-export([get_authdata_id/1]).
-export([get_signer/1]).
-export([create_authdata/4]).
-export([get_authdata_by_token/3]).
-export([get_authdata_by_id/3]).
-export([store/3]).
-export([revoke/3]).
-export([get_value/2]).

%% API Types

-type authority() :: #{
    id := autority_id(),
    signer => tk_token_jwt:keyname(),
    authdata_sources := authdata_sources()
}.

-type authdata_sources() :: [tk_authdata_source:authdata_source()].

-type autority_id() :: binary().

-type authdata() :: #{
    id => authdata_id(),
    status := status(),
    context := encoded_context_fragment(),
    authority := autority_id(),
    metadata => metadata()
}.

-type authdata_id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{binary() => binary()}.

-type authdata_fields() :: status | context | authority | metadata.
-type authdata_values() :: status() | encoded_context_fragment() | autority_id() | metadata().

-type source_opts() :: tk_authdata_source:source_opts().

-export_type([authority/0]).

-export_type([authdata/0]).
-export_type([authdata_id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).
-export_type([autority_id/0]).

%% API Functions

-spec get_id(authority()) -> autority_id().
get_id(Authority) ->
    maps:get(id, Authority).

-spec get_authdata_id(authdata()) -> authdata_id().
get_authdata_id(AuthData) ->
    maps:get(id, AuthData).

-spec get_signer(authority()) -> tk_token_jwt:keyname().
get_signer(Authority) ->
    maps:get(signer, Authority).

-spec create_authdata(authdata_id() | undefined, encoded_context_fragment(), metadata(), authority() | autority_id()) ->
    authdata().
create_authdata(ID, ContextFragment, Metadata, Authority) ->
    AuthData = #{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    },
    add_authority_id(add_id(AuthData, ID), Authority).

-spec get_authdata_by_token(tk_token_jwt:t(), authority(), source_opts()) ->
    {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
get_authdata_by_token(Token, Authority, GOpts) ->
    AuthDataSources = get_auth_data_sources(Authority),
    case get_authdata_from_sources(AuthDataSources, Token, GOpts) of
        #{} = AuthData ->
            {ok, maybe_add_authority_id(AuthData, Authority)};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

-spec get_authdata_by_id(authdata_id(), authority(), source_opts()) -> {ok, authdata()} | {error, _Reason}.
get_authdata_by_id(ID, Authority, GOpts) ->
    do_storage_call(ID, Authority, fun tk_storage:get/2, GOpts).

-spec store(authdata(), authority(), source_opts()) -> ok | {error, _Reason}.
store(AuthData, Authority, GOpts) ->
    do_storage_call(AuthData, Authority, fun tk_storage:store/2, GOpts).

-spec revoke(authdata_id(), authority(), source_opts()) -> ok | {error, notfound}.
revoke(ID, Authority, GOpts) ->
    do_storage_call(ID, Authority, fun tk_storage:revoke/2, GOpts).

-spec get_value(authdata_fields(), authdata()) -> authdata_values().
get_value(Field, AuthData) ->
    maps:get(Field, AuthData).

%%-------------------------------------
%% private functions

-spec get_auth_data_sources(authority()) -> authdata_sources().
get_auth_data_sources(Authority) ->
    case maps:get(authdata_sources, Authority, undefined) of
        Sources when is_list(Sources) ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authdata_from_sources([], _Token, _GOpts) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], Token, GOpts) ->
    case tk_authdata_source:get_authdata(SourceOpts, Token, GOpts) of
        undefined ->
            get_authdata_from_sources(Rest, Token, GOpts);
        AuthData ->
            AuthData
    end.

maybe_add_authority_id(AuthData = #{authority := _}, _Authority) ->
    AuthData;
maybe_add_authority_id(AuthData, Authority) ->
    add_authority_id(AuthData, Authority).

add_id(AuthData, undefined) ->
    AuthData;
add_id(AuthData, ID) ->
    AuthData#{id => ID}.

add_authority_id(AuthData, Authority) when is_map(Authority) ->
    AuthData#{authority => maps:get(id, Authority)};
add_authority_id(AuthData, Authority) when is_binary(Authority) ->
    AuthData#{authority => Authority}.

get_storage_opts(Authority) ->
    lists:keyfind(storage, 1, get_auth_data_sources(Authority)).

-spec do_storage_call(authdata() | authdata_id(), authority(), fun(), source_opts()) ->
    ok | {ok, authdata()} | {error, _Reason}.
do_storage_call(Operand, Authority, Func, GOpts) ->
    case get_storage_opts(Authority) of
        {_Source, Opts} ->
            Func(Operand, maps:merge(GOpts, Opts));
        false ->
            {error, {misconfiguration, {no_storage_options, Authority}}}
    end.
