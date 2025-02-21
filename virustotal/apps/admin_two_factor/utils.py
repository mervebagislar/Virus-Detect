import datetime
import time

from apps.admin_two_factor import settings


def str_to_date(timestamp):
    date_time = datetime.datetime.fromtimestamp(timestamp)
    return date_time


def str_to_time(_date):
    result = int(time.mktime(_date.timetuple()))
    return result


def set_expire(interval=settings.SESSION_COOKIE_AGE):
    _date = datetime.datetime.now()
    expire_time = (interval * 60 * 60) + str_to_time(_date)
    expire_date = str_to_date(expire_time)
    return dict(date=expire_date, time=expire_time)


def is_expired(ex_time, now=None):
    now = datetime.datetime.now() if not now else now
    if ex_time <= str_to_time(now):
        return True
    return False
