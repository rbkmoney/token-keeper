-module(token_keeper).

%% Application callbacks
-behaviour(application).

-export([start/2]).
-export([stop/1]).

%% Supervisor callbacks
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

%%

-define(SERVER, ?MODULE).

%%
%% Application callbacks
%%

-spec start(normal, any()) -> {ok, pid()} | {error, any()}.
start(_StartType, _StartArgs) ->
    token_keeper:start_link().

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
    {AuditChildSpecs, AuditPulse} = get_audit_specs(),
    EventHandlers = genlib_app:env(?MODULE, woody_event_handlers, [woody_event_handler_default]),
    TokenBlacklistSpec = tk_blacklist:child_spec(genlib_app:env(?MODULE, blacklist, #{})),
    TokensSpecs = tk_token:child_specs(genlib_app:env(?MODULE, tokens, #{})),
    StoragesSpecs = tk_storage:child_specs(genlib_app:env(?MODULE, storages, #{})),
    HandlerChildSpec = woody_server:child_spec(
        ?MODULE,
        #{
            ip => get_ip_address(),
            port => get_port(),
            protocol_opts => get_protocol_opts(),
            transport_opts => get_transport_opts(),
            shutdown_timeout => get_shutdown_timeout(),
            event_handler => EventHandlers,
            handlers => get_woody_handlers(AuditPulse),
            additional_routes => [get_health_route() | get_machinegun_processor_routes(EventHandlers)]
        }
    ),
    {ok, {
        #{strategy => one_for_all, intensity => 6, period => 30},
        lists:flatten([
            AuditChildSpecs,
            TokenBlacklistSpec,
            TokensSpecs,
            StoragesSpecs,
            HandlerChildSpec
        ])
    }}.

%%

-spec get_woody_handlers(tk_pulse:handlers()) -> [woody:http_handler(woody:th_handler())].
get_woody_handlers(AuditPulse) ->
    lists:flatten([
        get_authenticator_handler(genlib_app:env(?MODULE, authenticator, #{}), AuditPulse),
        get_authority_handler(genlib_app:env(?MODULE, authorities, #{}), AuditPulse)
    ]).

get_authenticator_handler(Config, AuditPulse) ->
    tk_handler:get_authenticator_handler(Config, AuditPulse).

get_authority_handler(Authorities, AuditPulse) ->
    maps:fold(
        fun(AuthorityID, AuthorityOpts, Acc) ->
            [tk_handler:get_authority_handler(AuthorityID, AuthorityOpts, AuditPulse) | Acc]
        end,
        [],
        Authorities
    ).

%%

-spec get_machinegun_processor_routes(woody:ev_handlers()) -> [woody_server_thrift_v2:route(_)].
get_machinegun_processor_routes(EventHandlers) ->
    case genlib_app:env(?MODULE, machinegun, #{}) of
        #{processor := ProcessorConf} ->
            tk_storage_machinegun:get_routes(ProcessorConf, #{event_handler => EventHandlers});
        #{} ->
            []
    end.

%%

-spec get_health_route() -> woody_server_thrift_v2:route(_).
get_health_route() ->
    Check = enable_health_logging(genlib_app:env(?MODULE, health_check, #{})),
    erl_health_handle:get_route(Check).

-spec enable_health_logging(erl_health:check()) -> erl_health:check().
enable_health_logging(Check) ->
    EvHandler = {erl_health_event_handler, []},
    maps:map(
        fun(_, Runner) -> #{runner => Runner, event_handler => EvHandler} end,
        Check
    ).

%%

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

-spec get_audit_specs() -> {[supervisor:child_spec()], tk_pulse:handlers()}.
get_audit_specs() ->
    Opts = genlib_app:env(?MODULE, audit, #{}),
    case maps:get(log, Opts, #{}) of
        LogOpts = #{} ->
            {ok, ChildSpec, Pulse} = tk_audit_log:child_spec(LogOpts),
            {[ChildSpec], [Pulse]};
        disable ->
            {[], []}
    end.
