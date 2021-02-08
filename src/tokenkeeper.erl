-module(tokenkeeper).

%% Application callbacks
-behaviour(application).

-export([start/2]).
-export([prep_stop/1]).
-export([stop/1]).

%% Supervisor callbacks
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

%% API Types

-type token() :: binary().
-type authority() :: tokenkeeper | keycloak.
-type token_type() :: api_key | user_session_token.
-type token_source() :: #{
    request_origin => binary()
}.

-export_type([token/0]).
-export_type([authority/0]).
-export_type([token_type/0]).
-export_type([token_source/0]).

%%

-define(SERVER, ?MODULE).

%%
%% Application callbacks
%%

-spec start(normal, any()) -> {ok, pid()} | {error, any()}.
start(_StartType, _StartArgs) ->
    tokenkeeper:start_link().

-spec prep_stop(State) -> State.
prep_stop(State) ->
    % NOTE
    % We have to do it in this magic `prep_stop/1` here because for some inexplicable reason the
    % usual `stop/1` callback doesn't get called in common_test runs.
    ok = tk_audit_log:stop(genlib_app:env(?MODULE, audit, #{})),
    State.

-spec stop(any()) -> ok.
stop(_State) ->
    ok.

%%
%% Supervisor callbacks
%%

-spec start_link() -> genlib_gen:start_ret().
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec init(Args :: term()) -> genlib_gen:supervisor_ret().
init([]) ->
    AuditPulse = tk_audit_log:init(genlib_app:env(?MODULE, audit, #{})),
    ServiceOpts = genlib_app:env(?MODULE, services, #{}),
    EventHandlers = genlib_app:env(?MODULE, woody_event_handlers, [woody_event_handler_default]),
    Healthcheck = enable_health_logging(genlib_app:env(?MODULE, health_check, #{})),
    HandlerChildSpec = woody_server:child_spec(
        ?MODULE,
        #{
            ip => get_ip_address(),
            port => get_port(),
            protocol_opts => get_protocol_opts(),
            transport_opts => get_transport_opts(),
            shutdown_timeout => get_shutdown_timeout(),
            event_handler => EventHandlers,
            handlers => get_handler_specs(ServiceOpts, AuditPulse),
            additional_routes => [erl_health_handle:get_route(Healthcheck)]
        }
    ),
    TokensOpts = genlib_app:env(?MODULE, tokens, #{}),
    TokensChildSpecs = get_tokens_specs(TokensOpts),
    {ok,
        {
            #{strategy => one_for_all, intensity => 6, period => 30},
            [HandlerChildSpec | TokensChildSpecs]
        }}.

-spec get_ip_address() -> inet:ip_address().

get_ip_address() ->
    {ok, Address} = inet:parse_address(genlib_app:env(?MODULE, ip, "::")),
    Address.

-spec get_port() -> inet:port_number().

get_port() ->
    genlib_app:env(?MODULE, port, 8022).

-spec get_protocol_opts() -> woody_server_thrift_http_handler:protocol_opts().

get_protocol_opts() ->
    genlib_app:env(?MODULE, protocol_opts, #{}).

-spec get_transport_opts() -> woody_server_thrift_http_handler:transport_opts().

get_transport_opts() ->
    genlib_app:env(?MODULE, transport_opts, #{}).

-spec get_shutdown_timeout() -> timeout().

get_shutdown_timeout() ->
    genlib_app:env(?MODULE, shutdown_timeout, 0).

-spec get_handler_specs(map(), tk_pulse:handlers()) -> [woody:http_handler(woody:th_handler())].

get_handler_specs(ServiceOpts, AuditPulse) ->
    TokenKeeperService = maps:get(tokenkeeper, ServiceOpts, #{}),
    TokenKeeperPulse = maps:get(pulse, TokenKeeperService, []),
    TokenKeeperOpts = #{pulse => AuditPulse ++ TokenKeeperPulse},
    [
        {
            maps:get(path, TokenKeeperService, <<"/v1/tokenkeeper">>),
            {{tk_token_keeper_thrift, 'TokenKeeper'}, {tk_handler, TokenKeeperOpts}}
        }
    ].

%%

-spec enable_health_logging(erl_health:check()) -> erl_health:check().

enable_health_logging(Check) ->
    EvHandler = {erl_health_event_handler, []},
    maps:map(
        fun(_, Runner) -> #{runner => Runner, event_handler => EvHandler} end,
        Check
    ).

%%

get_tokens_specs(TokensOpts) ->
    maps:fold(
        fun(K, V, Acc) ->
            [get_token_spec(K, V) | Acc]
        end,
        [],
        TokensOpts
    ).

get_token_spec(jwt, JWTOptions) ->
    tk_token_jwt:child_spec(JWTOptions).
