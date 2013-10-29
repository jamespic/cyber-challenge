from BaseHTTPServer import *
from SocketServer import *
from urlparse import *
from HTMLParser import HTMLParser
from httplib import HTTPConnection
import gzip, io, urllib, random


def proxy_handler(hostname, port):
    class CSRFProxyHandler(BaseHTTPRequestHandler):
        def proxy_request(self, method):
            self.generate_csrf_cookie()
            if "content-length" in self.headers:
                data = self.rfile.read(int(self.headers["content-length"]))
            else:
                data = None
            headers = dict(self.headers)
            orig_host = headers["host"]
            headers["host"] = "{}:{}".format(hostname, port)
            headers["X-Forwarded-For"] = self.client_address[0]
            conn = HTTPConnection(hostname, port)
            conn.connect()
            conn.request(method,self.path, data, headers)
            response = conn.getresponse()
            self.send_response(response.status, response.reason)
            response_headers = response.getheaders()
            for i in xrange(len(response_headers)):
                header = response_headers[i]
                if header[0].upper() == "LOCATION":
                    url = urlparse(header[1])
                    fixed_url = urlunparse((
                        url.scheme,
                        orig_host,
                        url.path,
                        url.params,
                        url.query,
                        url.fragment))
                    response_headers[i] = ("location", fixed_url)
            for key, value in response_headers:
                self.send_header(key, value)
            self.send_header("set-cookie","csrfProxyCookie={}".format(self._csrf_cookie))
            self.end_headers()
            response_data = response.read()
            use_gzip = any(key.lower() == "content-encoding" and value == "gzip"
                           for key, value in response_headers)
            if any(key.lower() == "content-type" and "html" in value
                   for key, value in response_headers):
                if use_gzip:
                    response_data = self.gzip_decode(response_data)
                # Let's hope it really is UTF-8!
                response_data = response_data.decode("UTF-8")
                response_data = self.insert_csrf_queries(response_data)
                response_data = response_data.encode("UTF-8")
                if use_gzip:
                    response_data = self.gzip_encode(response_data)
            self.wfile.write(response_data)
            self.wfile.close()

        def do_POST(self):
            url = self.path
            parsed = urlparse(url)
            query_dict = parse_qs(parsed.query)
            token = query_dict.get("csrfProxyCookie", ["NOTFOUND"])[0]
            query_list = parse_qsl(parsed.query)
            query_list = [(key, value) for key, value in query_list if key != "csrfProxyCookie"]
            tidied_query = urllib.urlencode(query_list)
            self.path = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                tidied_query,
                parsed.fragment))
            cookie = "csrfProxyCookie={}".format(token)
            if any(cookie in header for header in self.headers.getallmatchingheaders("cookie")):
                self.proxy_request("POST")
            else:
                print "CSRF attempt caught!"
                print "Cookie was {}".format(self.headers.getallmatchingheaders("cookie"))
                print "Token was {}".format(token)
                self.send_response(401, "Unauthorized")
                self.end_headers()
                self.wfile.write("401 - CSRF attempt detected")
                self.wfile.close()
            
        def do_GET(self):
            self.proxy_request("GET")

        def insert_csrf_queries(self, data):
            class ModifyingParser(HTMLParser):
                def __init__(self, csrf_token):
                    self.data = []
                    self.csrf_token = csrf_token
                    HTMLParser.__init__(self)
                def write(self, data):
                    self.data.append(data)
                def value(self):
                    return "".join(self.data)

                def fix_url(self, url):
                    parsed = urlparse(url)
                    parsed_query = parse_qsl(parsed.query)
                    parsed_query.append(("csrfProxyCookie", self.csrf_token))
                    repaired_query = urllib.urlencode(parsed_query)
                    repaired_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        repaired_query,
                        parsed.fragment))
                    return repaired_url
                def handle_starttag(self, tag, attrs):
                    if tag == "form":
                        attr_dict = dict(attrs)
                        if attr_dict["method"].lower() == "post":
                            attr_dict["action"] = self.fix_url(attr_dict["action"])
                        attrs = attr_dict.items()
                    attr_data = u"".join([u' {}="{}"'.format(k, v) for k, v in attrs])
                    self.write(u"<{}{}>".format(tag, attr_data))
                def handle_endtag(self, tag):
                    self.write(u"</{}>".format(tag))
                def handle_startendtag(self, tag, attrs):
                    attr_data = u"".join([u' {}="{}"'.format(k, v) for k, v in attrs])
                    self.write(u"<{}{} />".format(tag, attr_data))
                def handle_data(self, data):
                    self.write(data)
                def handle_entityref(self, name):
                    self.write(u"&{};".format(name))
                def handle_charref(self, name):
                    self.write(u"&{};".format(name))
                def handle_comment(self, name):
                    self.write(u"<!--{}-->".format(name))
                def handle_decl(self, decl):
                    self.write(u"<!{}>".format(decl))
                def handle_pi(self, decl):
                    self.write(u"<?{}>".format(decl))
                def unknown_decl(self, decl):
                    self.write(u"<![{}]>".format(decl))
            parser = ModifyingParser(self._csrf_cookie)
            parser.feed(data)
            return parser.value()

        def generate_csrf_cookie(self):
            self._csrf_cookie = str(random.randint(0, 1000000000000))

        def gzip_decode(self, data):
            bio = io.BytesIO(data)
            gzf = gzip.GzipFile(fileobj = bio)
            return gzf.read()

        def gzip_encode(self, data):
            bio = io.BytesIO()
            gzf = gzip.GzipFile(mode="w",fileobj=bio)
            gzf.write(data)
            gzf.close()
            return bio.getvalue()

    return CSRFProxyHandler

if __name__ == "__main__":
    class ThreadedServer(ThreadingMixIn, HTTPServer):
        pass
    class ForkedServer(ForkingMixIn, HTTPServer):
        pass
    handler = proxy_handler("10.200.42.13",80)
    httpd = ThreadedServer(("",8001),handler)
    httpd.serve_forever()
