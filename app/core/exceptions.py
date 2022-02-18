class UzenError(Exception):
    pass


class TakeSnapshotError(UzenError):
    pass


class InvalidIPAddressError(UzenError):
    pass


class InvalidDomainError(UzenError):
    pass


class JobExecutionError(UzenError):
    pass


class JobNotFoundError(UzenError):
    pass
