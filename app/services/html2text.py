import html2text as h2t


def html2text(html: str) -> str:
    h = h2t.HTML2Text()
    h.ignore_links = True
    h.ignore_images = True
    return h.handle(html).strip()
