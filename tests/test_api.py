"""The client over a stand-in transport: a list read page after page, the account's own images asked with the reference's
X-Filter header, a count from one page's `results`, a rate limit waited out, a write never sent twice, an id checked before
it is put in a path, and only its own reads and free writes sent."""
from __future__ import annotations

import json

import pytest

from conftest import TOKEN, FakeLinode
from liminal_libs.machines.rest import RestError
from plugin_platform_linode.api import PAGE_SIZE, LinodeApi, path_of, template_of


class Answers:
    """Answers in order; keeps what was sent."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.sent = []

    def __call__(self, method, url, headers, body, timeout):
        self.sent.append((method, url, dict(headers), body))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        status, data, headers = (*a, {})[:3] if len(a) == 2 else a
        return status, {"Content-Type": "application/json", **headers}, json.dumps(data).encode()


def client(t, slept=None):
    return LinodeApi(TOKEN, transport=t, sleep=lambda s: (slept if slept is not None else []).append(s))


def test_a_list_is_read_page_after_page_with_the_token_borne():
    items = [{"id": i} for i in range(1, 1201)]
    t = Answers(*[(200, {"data": items[(n - 1) * PAGE_SIZE: n * PAGE_SIZE], "page": n, "pages": 3, "results": 1200})
                  for n in (1, 2, 3)])
    got = client(t).linodes()
    assert [x["id"] for x in got] == list(range(1, 1201))
    assert [url for _, url, _, _ in t.sent] == [f"https://api.linode.com/v4/linode/instances?page={n}&page_size=500"
                                                for n in (1, 2, 3)]
    assert t.sent[0][2]["Authorization"] == f"Bearer {TOKEN}" and t.sent[0][3] is None


def test_the_accounts_own_images_are_counted_with_the_references_filter():
    t = Answers((200, {"data": [{"id": "private/1"}], "page": 1, "pages": 3, "results": 61}))
    assert client(t).count("images") == 61
    method, url, headers, _ = t.sent[0]
    assert (method, url) == ("GET", "https://api.linode.com/v4/images?page_size=25")
    assert headers["X-Filter"] == '{"is_public":false}'
    with pytest.raises(ValueError, match="is not counted here"):
        client(Answers()).count("linodes")


def test_a_rate_limit_is_waited_out_and_a_write_never_sent_twice():
    slept = []
    t = Answers((429, {"errors": [{"reason": "Too Many Requests"}]}, {"Retry-After": "3"}), (200, {"username": "tester"}))
    assert client(t, slept).profile() == {"username": "tester"} and slept == [3.0]
    t = Answers(ConnectionError("reset by peer"), (200, {}))
    with pytest.raises(RestError, match="ConnectionError: reset by peer"):
        client(t).shutdown(11)
    assert len(t.sent) == 1  # a power change that may have been taken: sent once
    t = Answers((503, {"errors": [{"reason": "Service Unavailable"}]}), (200, {}))
    with pytest.raises(RestError, match="HTTP 503"):
        client(t).delete_record(1, 104)
    assert len(t.sent) == 1


def test_an_error_is_worded_with_what_to_do_and_the_token_taken_out():
    t = Answers((401, {"errors": [{"reason": f"Invalid Token {TOKEN}"}]}))
    with pytest.raises(RestError) as e:
        client(t).account()
    assert e.value.status == 401 and e.value.refused and TOKEN not in str(e.value)
    assert str(e.value) == ("GET /v4/account: HTTP 401: LINODE_TOKEN is refused (wrong, revoked or expired): make a new one "
                            "in Cloud Manager (your username > API Tokens) (Linode: Invalid Token •••)")
    t = Answers((400, {"errors": [{"reason": "Must be a valid IPv4 address", "field": "target"},
                                  {"reason": "ttl_sec is invalid", "field": "ttl_sec"}]}))
    with pytest.raises(RestError, match=r"HTTP 400: target: Must be a valid IPv4 address; ttl_sec: ttl_sec is invalid$"):
        client(t).create_record(1, {"type": "A", "name": "x", "target": "nope"})


def test_an_id_is_checked_before_it_is_put_in_a_path_and_only_the_clients_calls_are_sent():
    assert path_of("/domains/{domainId}/records/{recordId}", {"domainId": "1", "recordId": 104}) == "/domains/1/records/104"
    for bad in ("1/../2", "-3", 0, "abc", None):
        with pytest.raises(ValueError):
            path_of("/linode/instances/{linodeId}", {"linodeId": bad})
    with pytest.raises(ValueError, match="not one of this plugin's reads"):
        client(Answers())._get("/account/invoices")
    with pytest.raises(ValueError, match="a record's type is not changed"):
        client(Answers()).update_record(1, 104, {"type": "AAAA", "target": "::1"})
    assert template_of("GET", "/v4/domains/1/records?page=1") == "/domains/{domainId}/records"
    assert template_of("POST", "/v4/linode/instances/11/boot") == "/linode/instances/{linodeId}/boot"
    assert template_of("POST", "/v4/linode/instances") is None and template_of("DELETE", "/v4/linode/instances/11") is None


def test_what_the_answers_said_is_kept_for_the_plugins_facts():
    fake = FakeLinode()
    api = LinodeApi(TOKEN, transport=fake, sleep=lambda s: None)
    api.profile()
    facts = api.facts()
    assert facts["Requests"] == "1 made" and facts["Rate limit (this call's window)"] == "1600"
    assert facts["Left of it"] == "1599" and len(facts["Its window resets"]) == 8  # a time of day
