-module(tk_handler).

-callback handle_function(woody:func(), woody:args(), handler_opts(), state()) -> {ok, woody:result()} | no_return().

%% Config API

-export([get_authenticator_handler/2]).
-export([get_authority_handler/3]).

%% Woody handler

-behaviour(woody_server_thrift_handler).
-export([handle_function/4]).

-type ctx() :: #{
    woody_context := woody_context:ctx()
}.

-type handler_opts() ::
    tk_handler_authenticator:handler_opts()
    | tk_handler_authority_ephemeral:handler_opts()
    | tk_handler_authority_offline:handler_opts().

-type opts() :: #{
    handler := {module(), handler_opts()},
    default_handling_timeout => timeout(),
    pulse => tk_pulse:handlers()
}.

-type state() :: #{
    context := ctx(),
    pulse := tk_pulse:handlers(),
    pulse_metadata := tk_pulse:metadata()
}.

-export_type([ctx/0]).
-export_type([opts/0]).
-export_type([state/0]).

-define(DEFAULT_HANDLING_TIMEOUT, 30000).

%%

-spec get_authenticator_handler(_, tk_pulse:handlers()) -> woody:http_handler(woody:th_handler()).
get_authenticator_handler(Opts, AuditPulse) ->
    get_http_handler(
        maps:get(service, Opts),
        get_authenticator_handler_spec(Opts),
        AuditPulse
    ).

-spec get_authority_handler(_, _, tk_pulse:handlers()) -> woody:http_handler(woody:th_handler()).
get_authority_handler(AuthorityID, Opts, AuditPulse) ->
    get_http_handler(
        maps:get(service, Opts),
        get_authority_handler_spec(AuthorityID, maps:get(type, Opts)),
        AuditPulse
    ).

%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), opts()) -> {ok, woody:result()} | no_return().
handle_function(Op, Args, WoodyContext0, #{handler := {Handler, HandlerOpts}} = Opts) ->
    WoodyContext = ensure_woody_deadline_set(WoodyContext0, Opts),
    Handler:handle_function(Op, Args, HandlerOpts, make_state(WoodyContext, Opts)).

%%

make_state(WoodyCtx, Opts) ->
    #{
        context => make_context(WoodyCtx),
        pulse => maps:get(pulse, Opts, []),
        pulse_metadata => #{woody_ctx => WoodyCtx}
    }.

make_context(WoodyCtx) ->
    #{woody_context => WoodyCtx}.

ensure_woody_deadline_set(WoodyContext, Opts) ->
    case woody_context:get_deadline(WoodyContext) of
        undefined ->
            DefaultTimeout = maps:get(default_handling_timeout, Opts, ?DEFAULT_HANDLING_TIMEOUT),
            Deadline = woody_deadline:from_timeout(DefaultTimeout),
            woody_context:set_deadline(Deadline, WoodyContext);
        _Other ->
            WoodyContext
    end.

get_http_handler(ServiceConf, HandlerSpec, AuditPulse) ->
    {maps:get(path, ServiceConf), wrap_handler_spec(HandlerSpec, AuditPulse)}.

wrap_handler_spec({ServiceName, Handler}, AuditPulse) ->
    {ServiceName, {tk_handler, #{handler => Handler, pulse => AuditPulse}}}.

get_authority_handler_spec(AuthorityID, {ephemeral, Opts}) ->
    tk_handler_authority_ephemeral:get_handler_spec(AuthorityID, Opts);
get_authority_handler_spec(AuthorityID, {offline, Opts}) ->
    tk_handler_authority_offline:get_handler_spec(AuthorityID, Opts).

get_authenticator_handler_spec(Opts) ->
    tk_handler_authenticator:get_handler_spec(maps:with([authorities], Opts)).
