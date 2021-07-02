-module(tk_extractor_invoice_tpl_token).

%% NOTE:
%% This is here because of a historical decision to make InvoiceTemplateAccessToken(s) never expire,
%% therefore a lot of them do not have a standart bouncer context claim built-in.
%% It is advisable to get rid of this exctractor when this issue will be solved.

-behaviour(tk_context_extractor).

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    domain := binary(),
    metadata_ns := binary()
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_context_extractor:extracted_context().
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

-define(MATCH(Item), fun
    (Item) -> true;
    (_) -> false
end).

match_invoice_template_acl(TokenACL) ->
    Matches = match_acl(
        [
            ?MATCH({[party, {invoice_templates, _}], [read]}),
            ?MATCH({[party, {invoice_templates, _}, invoice_template_invoices], [write]})
        ],
        TokenACL
    ),
    assert_acl_match(Matches).

assert_acl_match([
    {[party, {invoice_templates, InvoiceTemplateID}], [read]},
    {[party, {invoice_templates, InvoiceTemplateID}, invoice_template_invoices], [write]}
]) ->
    {ok, InvoiceTemplateID};
assert_acl_match(Mismatch) ->
    {error, {acl_mismatch, Mismatch}}.

match_acl(MatchFuns, TokenACL) ->
    match_acl(MatchFuns, TokenACL, [], []).

match_acl([], _TokenACL, _SearchedACL, Found) ->
    lists:reverse(Found);
match_acl(_MatchFuns, [], _SearchedACL, Found) ->
    lists:reverse(Found);
match_acl([MatchFun | MTail] = MatchFuns, [ACL | ATail], SearchedACL, Found) ->
    case MatchFun(ACL) of
        true -> match_acl(MTail, SearchedACL ++ ATail, [], [ACL | Found]);
        false -> match_acl(MatchFuns, ATail, [ACL | SearchedACL], Found)
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
    [
        {test_acl, 123}
    ] = match_acl(
        [
            ?MATCH({test_acl, _})
        ],
        ?TEST_ACL
    ).

-spec match_acl_dupes_test() -> _.

match_acl_dupes_test() ->
    [
        {doubles, 123}
    ] = match_acl(
        [
            ?MATCH({doubles, _})
        ],
        ?TEST_ACL
    ).

-spec match_acl_order_test() -> _.

match_acl_order_test() ->
    [
        {first, 123},
        {second, <<"abc">>}
    ] = match_acl(
        [
            ?MATCH({first, _}),
            ?MATCH({second, _})
        ],
        ?TEST_ACL
    ).

-spec match_acl_no_match_test() -> _.

match_acl_no_match_test() ->
    [] = match_acl(
        [
            ?MATCH({foo, _}),
            ?MATCH({bar, _, _})
        ],
        ?TEST_ACL
    ).

-endif.
