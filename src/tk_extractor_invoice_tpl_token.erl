-module(tk_extractor_invoice_tpl_token).

%% NOTE:
%% This is here because of a historical decision to make InvoiceTemplateAccessToken(s) never expire,
%% therefore a lot of them do not have a standart bouncer context claim built-in.
%% It is advisable to get rid of this exctractor when this issue will be solved.

-behaviour(tk_extractor).

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    domain := binary(),
    metadata_ns := binary()
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_extractor:extracted_context().
get_context(Token, ExtractorOpts) ->
    UserID = tk_token_jwt:get_subject_id(Token),
    case extract_invoice_template_rights(Token, ExtractorOpts) of
        {ok, InvoiceTemplateID} ->
            BCtx = create_bouncer_ctx(tk_token_jwt:get_token_id(Token), UserID, InvoiceTemplateID),
            {BCtx, wrap_metadata(get_metadata(Token), ExtractorOpts)};
        {error, Reason} ->
            _ = logger:warning("Failed to extract invoice template rights: ~p", [Reason]),
            undefined
    end.

%%

get_metadata(Token) ->
    %% @TEMP: This is a temporary hack.
    %% When some external services will stop requiring woody user identity to be present it must be removed too
    case tk_token_jwt:get_subject_id(Token) of
        UserID when UserID =/= undefined ->
            #{<<"party_id">> => UserID};
        undefined ->
            undefined
    end.

extract_invoice_template_rights(TokenContext, ExtractorOpts) ->
    Domain = maps:get(domain, ExtractorOpts),
    case get_acl(Domain, get_resource_hierarchy(), TokenContext) of
        {ok, TokenACL} ->
            match_invoice_template_acl(TokenACL);
        {error, Reason} ->
            {error, {acl, Reason}}
    end.

match_invoice_template_acl(TokenACL) ->
    Patterns = [
        fun({[party, {invoice_templates, ID}], [read]}) -> ID end,
        fun({[party, {invoice_templates, ID}, invoice_template_invoices], [write]}) -> ID end
    ],
    case match_acl(Patterns, TokenACL) of
        [[InvoiceTemplateID], [InvoiceTemplateID]] ->
            {ok, InvoiceTemplateID};
        Matches ->
            {error, {acl_mismatch, Matches}}
    end.

match_acl(Patterns, TokenACL) ->
    [match_acl_pattern(TokenACL, Pat) || Pat <- Patterns].

match_acl_pattern(TokenACL, Pat) ->
    lists:usort([Match || Entry <- TokenACL, Match <- run_pattern(Entry, Pat)]).

run_pattern(Entry, Pat) when is_function(Pat, 1) ->
    try
        [Pat(Entry)]
    catch
        error:function_clause -> []
    end.

get_acl(Domain, Hierarchy, TokenContext) ->
    case tk_token_jwt:get_claim(<<"resource_access">>, TokenContext, undefined) of
        #{Domain := #{<<"roles">> := Roles}} ->
            try
                TokenACL = tk_token_legacy_acl:decode(Roles, Hierarchy),
                {ok, tk_token_legacy_acl:to_list(TokenACL)}
            catch
                error:Reason -> {error, {invalid, Reason}}
            end;
        _ ->
            {error, missing}
    end.

create_bouncer_ctx(TokenID, UserID, InvoiceTemplateID) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"InvoiceTemplateAccessToken">>,
            token => #{id => TokenID},
            scope => [
                #{
                    party => #{id => UserID},
                    invoice_template => #{id => InvoiceTemplateID}
                }
            ]
        },
        bouncer_context_helpers:empty()
    ).

wrap_metadata(Metadata, ExtractorOpts) ->
    MetadataNS = maps:get(metadata_ns, ExtractorOpts),
    #{MetadataNS => Metadata}.

get_resource_hierarchy() ->
    #{
        party => #{invoice_templates => #{invoice_template_invoices => #{}}}
    }.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-define(TEST_ACL, [
    {some_other_stuff, 123, <<"abc">>},
    {second, <<"abc">>},
    {doubles, 123},
    more_stuff,
    {test_acl, 123},
    {doubles, 456},
    {first, 123}
]).

-spec match_acl_base_test() -> _.

match_acl_base_test() ->
    [[123]] = match_acl(
        [
            fun({test_acl, Int}) -> Int end
        ],
        ?TEST_ACL
    ).

-spec match_acl_dupes_test() -> _.

match_acl_dupes_test() ->
    [[123, 456]] = match_acl(
        [
            fun({doubles, Int}) -> Int end
        ],
        ?TEST_ACL
    ).

-spec match_acl_order_test() -> _.

match_acl_order_test() ->
    [[123], [<<"abc">>]] = match_acl(
        [
            fun({first, Int}) -> Int end,
            fun({second, Bin}) -> Bin end
        ],
        ?TEST_ACL
    ).

-spec match_acl_no_match_test() -> _.

match_acl_no_match_test() ->
    [[], []] = match_acl(
        [
            fun({foo, _}) -> wait end,
            fun({bar, _, _}) -> no end
        ],
        ?TEST_ACL
    ).

-endif.
