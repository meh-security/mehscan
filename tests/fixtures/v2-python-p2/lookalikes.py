class LocalRequest:
    def value(self, name):
        return name


def calculate(payload):
    return payload.value("name")
