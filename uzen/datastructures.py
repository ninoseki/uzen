from starlette.datastructures import URL


class DatabaseURL(URL):
    @property
    def database(self) -> str:
        path = self.components.path
        if len(path) == 0:
            return self.hostname

        if path.startswith("/"):
            path = path[1:]
        return path
