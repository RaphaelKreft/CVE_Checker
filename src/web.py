from urllib.request import urlopen


def get_page_html(url: str):
    try:
        responseObject = urlopen(url)
        hypertext = responseObject.read()
        return hypertext
    except IOError as ex:
        logging.error(str(ex))

