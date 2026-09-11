import os

import requests


def parameterized_coupon(request, cursor):
    coupon_request_body = request.data
    cursor.execute(
        "SELECT coupon_code FROM coupons WHERE coupon_code = %s",
        (coupon_request_body["coupon_code"],),
    )


def contained_report(request):
    filename = request.body
    base = os.path.abspath("/srv/reports")
    full_path = os.path.abspath(os.path.join(base, filename))
    if os.path.commonpath([base, full_path]) == base:
        return open(full_path, "rb")
    raise ValueError("path escapes report directory")


def verified_service_call():
    return requests.get("https://inventory.internal/api", verify=True)
