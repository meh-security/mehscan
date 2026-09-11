import os
from urllib.parse import unquote

import httpx
import requests


def contact_mechanic(request):
    request_data = request.data
    request_url = request_data["mechanic_api"]
    return requests.get(request_url, verify=False)


def apply_coupon(request, cursor):
    coupon_request_body = request.data
    cursor.execute(
        "SELECT coupon_code FROM coupons WHERE coupon_code = '"
        + coupon_request_body["coupon_code"]
        + "'"
    )


def download_report(request):
    filename_from_user = request.body
    filename_from_user = unquote(filename_from_user)
    full_path = os.path.abspath(os.path.join("/srv/reports", filename_from_user))
    return open(full_path, "rb")


def disabled_httpx_client():
    return httpx.AsyncClient(verify=False)
