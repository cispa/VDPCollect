import requests
import json

url = "https://hackerone.com:443/graphql"

PROXIES = {"http": "http://localhost:8080", "https": "http://localhost:8080"}
PROXIES = {}
cookies = {}
headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0",
           "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
           "Referer": "https://hackerone.com/directory/programs", "Content-Type": "application/json",
           "X-Csrf-Token": "sE/uMROAIVmt+UxBEUUE1Jt8KjNXz5QfG3e7erg7sKWCXYkvLpchd5mJYOg5A/0/bMHI39pnDuTaMcnxeU5aAQ==",
           "Origin": "https://hackerone.com", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
           "Sec-Fetch-Site": "same-origin", "Te": "trailers"}

query = """
query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {
  teams(after: $cursor, secure_order_by: $secureOrderBy, where: $where) {
    pageInfo {
      endCursor
      hasNextPage
      __typename
    }
    edges {
      node {
        id
        bookmarked
				website
       	resolved_report_count
				name
				handle
				submission_state
				triage_active
				publicly_visible_retesting
				state
				allows_bounty_splitting
				launched_at
                triage_active
                submission_state
                state
				currency
				base_bounty
				average_bounty_lower_amount
				average_bounty_upper_amount
				top_bounty_lower_amount
				top_bounty_upper_amount
				external_program {
					id
					__typename
				}
        __typename
      }
      __typename
    }
    __typename
  }
}
"""

graphql = {
    "operationName": "DirectoryQuery",
    "query": query,
    "variables": {
        "cursor": "",
        "secureOrderBy": {
            "launched_at": {
                "_direction": "DESC"
            }
        }
    }
}

"""
,
        "where": {
            "_and": [
                {
                    "_not": {
                        "external_program": {}
                    }
                }
            ]
        }

"""
cnt = 0

while 1:
    # RESPONSE 422?
    res = requests.post(url, json=graphql, headers=headers, cookies=cookies)
    print(res.status_code)
    data = res.json()
    has_next = data["data"]["teams"]["pageInfo"]["hasNextPage"]
    if not has_next:
        break

    cursor = data["data"]["teams"]["pageInfo"]["endCursor"]
    graphql["variables"]["cursor"] = cursor
    edges = data["data"]["teams"]["edges"]
    edges = [e for e in edges if e["node"]["external_program"] == None]
    if len(edges) == 0:
        continue

    cnt += len(edges)
    print(f"We count {len(edges)} edges. {cnt} total. First: {edges[0]['node']['handle']}")
    for e in edges:
        handle = e["node"]["handle"]
        with open(f"./data/h1_{handle}.json", "w") as f:
            f.write(json.dumps(e["node"]))
        exit(1)
