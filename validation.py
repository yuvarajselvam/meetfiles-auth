import re
import datetime


DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

URL_REGEX = re.compile(
        u"^"
        u"(?:(?:https?|ftp)://)"
        u"(?:\S+(?::\S*)?@)?"
        u"(?:"
        u"(?!(?:10|127)(?:\.\d{1,3}){3})"
        u"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})"
        u"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
        u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
        u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}"
        u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
        u"|"
        u"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
        u"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
        u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
        u")"
        u"(?::\d{2,5})?"
        u"(?:/\S*)?"
        u"$"
        , re.UNICODE)

EMAIL_REGEX = re.compile('^[a-z0-9]+[._]?[a-z0-9]+[@]\w+[.]\w+$')
PHONE_REGEX = re.compile("^[+]*[(]?[0-9]{1,4}[)]?[-\s./0-9]*$")


def check_min_length(field, value, length):
    if len(value) < length:
        raise ValueError(f"{field.title()} field should be at least {length} character(s) long.")


def check_max_length(field, value, length):
    if len(value) > length:
        raise ValueError(f"{field.title()} field should be at least {length} character(s) long.")


def check_instance_type(field, value, typ):
    if value and not isinstance(value, typ):
        raise ValueError(f"{field.title()} field should be of {typ}, not {type(value)}.")


def check_regex_match(field, value, regex):
    if value:
        if isinstance(regex, str):
            if not re.compile(regex).match(value):
                raise ValueError(f"Invalid {field.title()}")
        else:
            if not regex.match(value):
                raise ValueError(f"Invalid {field.title()}")


def check_date(field, value):
    check_instance_type(field, value, str)

    if "T" not in value:
        value += "T00:00:00"

    try:
        datetime.datetime.strptime(value, DATE_FORMAT)
    except ValueError as e:
        raise ValueError(f"{field.title()} should be of format '{DATE_FORMAT}'.")


def check_choices(field, value, allowed_values):
    if value.upper() not in allowed_values:
        raise AttributeError(f"{field.title()} must be one of {repr(allowed_values)}")
