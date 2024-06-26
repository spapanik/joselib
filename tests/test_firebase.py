import json

from joselib import jwt

firebase_certs = {
    "6f83ab6e516e718fba9ddeb6647fd5fb752a151b": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIP5V2bjX2bXUwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTYw\nODMxMDA0NTI2WhcNMTYwOTAzMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAKHHtOMXBD+0YTtZHuzFrERiiwa+D6Ybq4SUHlicgRPV3Uk2\nvnTOqg1EhxshEXqjkAQbbRop9hhHTc+p8rBxgYGuLcZsBhGrnRqU6FnTTiWB1x5V\nvOfCkPE60W07gi8p+HyB8cqw1Tz2LnRUw/15888CrspVeumtNUkhXSRKzeS2BI4l\nkuOMkqmsMSu1yB5IZm5meMyta1uhJnP93jKmdar19RkZXOlFcT+fsSY2FPuqvDvX\nssChgZgNV5qtk0CIzexmFJaUFzpKE/RxqdIJooB1H83fUBGVK+9v3Ko+BI+GEvUc\nxIGAEWu2KrbjwPNzzC3/UV9aSfHEOJxQoutPviECAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAIHOiqxXm1IcuXE87ELyKYDG0/gZPzCHz98h/x0LExrs\nd0bOYOIA08rt6qllmP24oT3hQt86HmDb932pm/fjaLL68x81TjYq6cFO0JxOzts+\nY+9XxkdP8Qu7UJ8Dx+rRvDN1MUxLTvBVXdamhkhDusx7PB5kK1ixWtf91qrl/J9e\nUYQBnJ4E9wI8U5HVkW3IBWvsFt/+gMO1EcoNBdB2cY/4N3l3oxm5PSNDS4DTEs2f\nAYZDqo6PJt2tTRGSmvLBKSCqcT7eWBbIwBht3Uw8CvOMbVYGBWjbFeua3Q3fe+p7\n7UbFOLIvSGR516kyZqxy9pLoA9+2TvbpYwWu6mLCZtg=\n-----END CERTIFICATE-----\n",
    "fc2da7fa53d92e3bcba8a17e74b34da9dd585065": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIINfZYQW9uekMwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTYw\nODI5MDA0NTI2WhcNMTYwOTAxMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAMvfJ5DY7lV4txW0zn9ayMxwAp5BzUhyIbuZkmsmMLRrNl+i\nid4lawojB846YtcTPZLD/5QpXRumAAUI5NA023fxaUdriM25zewpSnZWs6eUf0O6\nONES8Xk4WD2fbyPz6cgnsFEfMslNd3NypRiB9fVG6LFj6TFHC64o/YEeQB2dwkJZ\nXknKSEkFJSRC83TiHUlWzaRjmTdGRrvGEWHxr+xJltP8tPPlJUKu2VadgMbGlkKU\n5dBRhvWwZZW0zJupuKzd27O2lPkxfbx9vrUbsfqZcN4OY5Xg+ijQJVTv0/qcplsd\nPZ9Uui0QsBOPbrIO+5/Tq9FIBqxzUlpWwetv6pMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBALqWwzIQSK94hxTmxlA+RoyMvb8fyTcECM2qY+n+PDb5\nMvt8zqM6AwGjK1hvcUg08BEsnqqRqC81dkSEReS9KCoTY/oQ0sCCpwL3QP3puoxp\nfZU9CSwvnrFTJjC2Q/b8BlWta4CSDwpxpy/K3wm6tRn5ED4rPcP4FRqWU5jyHiug\nRrNkKiG7TeBBvQ3ZlF9K4JSx1yn9g7EvPBcmygop5FIKI1uS+URxeyavtlwfnTTs\nDtRVV/x0LDkHoJ2Agy7l2MqT7eoRKh5VNucQONLrcZT1AY02eZi/WVSjgpzC48eP\nV9xlcgIaRbS/JDULYgW5h0uVdRNqSVGJ6yBLXT2uaBA=\n-----END CERTIFICATE-----\n",
    "8226146523a1b8894ba03ad525667b9475d393f5": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIWAKW/IRYcAwwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTYw\nODMwMDA0NTI2WhcNMTYwOTAyMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBALJAt+ws+XNdDnDSYFp0YnQ5e8QqfMFrwp1l1r/mNSUF840I\nsbm50Z89aNpQgFOsORS/TYyHOeasiBhsJ5HWmfxo0PBTFifKI/OedLlltxZZCHa+\nEO/75Fbeydexokvfq6thT7C+xL45kJzbvKKNAw4WCAW6vwzyz+d/IrWCs9Iqa2ZX\nSiKnMPzPxZj6s+AhHPVxsR8dBMZ+NdK/wh9OcPWjLAxLEWBvd0Gp315bIVjVc9pV\neYcTapu/s4DSwgz4twovAyUziwsa+HJ+2FFNDZExf/XQUVBW5le8gGEdfl3kW1yu\nzdO6e1LwVTDAXULydPBL5lb6vTX2/ICmMzHXzIUCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAHyACbK1WfP9WspLfxvgJaNvwvygnP6cggLMvqq/dRxP\nlemvxfVaHK19sIXI6p0H4RBjI9FID5otzuyV54p1LBKgLIMTWcMYdL0wieeBg4Ud\nwgLEutIERpJU5oRMpSuZZYW75d0o+U1qOEhDswliqW1xofxNjRgNyrOYc6hMJzIS\ng9U4C4fplT/m3x5uQNjfzN/0CxfQf54WaD15w1lPGQAMJSWQDaxDTi41bW0Jwp4N\ndshOVn+btUUwL5TXDKaVkg1IHfG57FwvPJ5hKs4pbP5SIm+Sc1utIMMTBsRDRJVK\nyHaB5Bj9KcpQk7FvdT/KtzetPowhnxu9ow+KJcnP+7w=\n-----END CERTIFICATE-----\n",
    "dd694b16c1b0ce31878a72dfa6c0cd4db3dd7edf": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIffru9igojE4wDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTYw\nOTAxMDA0NTI2WhcNMTYwOTA0MDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBALaxpG4i7EgYpzaJsykaZzKmTTnm+kIPJBKb6t41ByUWt7J+\nnoUmlMiAVkXj7GAmc3usroJdYNZ8iMSpAWsIMgg7HLrqv/hMDY6+33rCqsvXD2tF\nCtJbRKzSMKu+AIc1uirkX3L3aHfKRzFbsr+8JqOigY3sVAb42FeATVHB0uCRyoE5\nfqxbt8nIPCFR/lFP51L0Wf5hGIH5kHJEuXx/7GOUQPN196P3sRI9jLv6nrWqGTAR\nVhuY9KXRz0jlVQeKZV5mWstcIXgxn2MfzfoHx4nuSNknJdrfHNp0r2XPf9Fre7Jd\n73slrVUwL2VWyZJdIBxJuYz2QjEQLzz+eJGyWcMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAFTpRr9/cEkFHSbP5c7gr926kSxe1e9u9JjzR7l9Zv5l\nfskkLxIZcGlx/FoccWCwDPYl2Nh0Pr++TJ2hWVe/LpjppUxl4QVqfbVzyJezn2UR\nhLnGASQ0ckPoNTJhxjA6PVGtyXWB67oCDEgz/Pl6jjKEMtilyXh93rBmOpt6jq9e\nlwiZaa5wTUwIhHI972rLveYkssVkspmp4RIWHoh1nxUjYPMtcTCf9GFjEMLNdDBj\nYldCEzL34V60ObBSkzV3Zx7UNwoa80+SEJc9gQsBHVJbjXl7V9ODL52OHnciiEA8\n+d/xy2tBzdCD5EUR3aaYZYqQ16VV6LeU8FoxFn6/nxw=\n-----END CERTIFICATE-----\n",
    "f4b0a5c73ad85a5da09f0e7f76463631339e0bbf": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIWDhBeVUilCcwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTYw\nNzAxMDA0NTI2WhcNMTYwNzA0MDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBALRWaRmoi5EFyj5TBrUGKFI6uBJ4x9wSHq9tlRL1qmnwzdNb\nlDoeoh6Gw3H54IqM0XqjZZwgV5KXOQDOaoUpMBRH93x7Ma7NjhiDtpQr0JSbFIQL\nsIay/VxQ9gfa/I83HViEAbF1FXjhBKniwFKUv26mU30upZfsDQkHM8OLc/iXRvhA\nYn7S732Oefdv0kJ9t3h+WOGKGVkYfDaAGn5Uyzx+9oyyLY33borKOBBzphSQlZCr\nL569zTXvvLgvdStrsPGaiRGj64DGXD6LCg6acLJcMUvlVUO6THHJHVgp8pzlrPQG\n3B1rZk61lZqJyjK/nTi2tY9GPLfdxOfDAMjNoz8CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAIlFwO3C+X2+na0nLjR+zQYGHzZYqFe4V67P6ugFJxun\nxP8pyDCYAGer1mkDcIyDacdQ3natNp0xv61a0yk5tSmDYZbXZRTFdLkf/GzH+VmH\nEMl5W4TvxjAe/x2opm3QUaPC+jVlvndcP99FF5ULFp7/PwSTp8uzyrd/fhSFaxhq\nuIW4syNzDSpDItzUsiKCtsKGYX/qvd/cNP8cXlPd5rWTM4Sic9Baf2nXuHaZRkBr\nSJYcxdh8xbGsY1tC8TIgWot6GXtldNvXDLqRUwb2t6Rr3Tqhbc0CcHndTCuHXf0i\n0s9jU/UCrNhhmaD0rZLHQ2tuN6W/xpOHKtO0a8Lys7c=\n-----END CERTIFICATE-----\n",
}

firebase_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0YjBhNWM3M2FkODVhNWRhMDlmMGU3Zjc2NDYzNjMxMzM5ZTBiYmYifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vd2Vkb3RyYW5zZmVyLTIwMTYiLCJhdWQiOiJ3ZWRvdHJhbnNmZXItMjAxNiIsImF1dGhfdGltZSI6MTQ2NzM0NjI3MCwidXNlcl9pZCI6IjRjemVXVllIekNNVnN0WEZOYldHVXBKYmJTZzEiLCJzdWIiOiI0Y3plV1ZZSHpDTVZzdFhGTmJXR1VwSmJiU2cxIiwiaWF0IjoxNDY3MzQ2MjcwLCJleHAiOjE0NjczNDk4NzAsImVtYWlsIjoic2V1bkBjbXUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7InBhc3N3b3JkIjpbInNldW5AY211LmNvbSJdLCJlbWFpbCI6WyJzZXVuQGNtdS5jb20iXX19fQ.U-fYjx8rMm5tYV24r0uEcNQtIe3UKULxsHecLdGzTbi1v-VKzKDk_QPL26SPDoU8JUMY3nJQ1hOE9AapBrQck8NVUZSKFMD49XdtsyoN2kKdinpFR1hSxIE0L2dRStS7OZ8sGiX866lNa52Cr6TXSsnMD6N2P0OtVE5EeD1Nf-AiJ-gsaLrP4tBnmj1MNYhEYVHb6sAUrT3nEI9gWmeKcPWPfn76FGTdGWZ2mjdaeAG4RbuFL4cHdOISA_0HVLGJxuNyEHAHybDX8mVdNW_F4yzL3H-SmPFY5Kv3tCdBzpzhUKfNOnFFmf2ggFOJnDsqMp-TZaIPk6ce_ltqhQ0dnQ"


class TestFirebase:
    @staticmethod
    def test_individual_cert() -> None:
        jwt.decode(
            firebase_token,
            firebase_certs["f4b0a5c73ad85a5da09f0e7f76463631339e0bbf"],
            algorithms="RS256",
            options={"verify_exp": False, "verify_aud": False},
        )

    @staticmethod
    def test_certs_dict() -> None:
        jwt.decode(
            firebase_token,
            firebase_certs,
            algorithms="RS256",
            options={"verify_exp": False, "verify_aud": False},
        )

    @staticmethod
    def test_certs_string() -> None:
        certs = json.dumps(firebase_certs)
        jwt.decode(
            firebase_token,
            certs,
            algorithms="RS256",
            options={"verify_exp": False, "verify_aud": False},
        )
