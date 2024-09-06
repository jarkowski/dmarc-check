import re
import dns.resolver
import datetime


def extract_fqdns_from_file(filename):
    with open(filename, "r") as file:
        text = file.read()
    fqdns = set(
        re.findall(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
            text,
            re.IGNORECASE,
        )
    )
    return fqdns


def check_spf_record(fqdn):
    try:
        answers = dns.resolver.resolve(fqdn, "TXT")
        for rdata in answers:
            txt_record = rdata.to_text()
            if "v=spf1" in txt_record:
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    return None


def check_dkim_record(fqdn, selector="ram2024"):
    dkim_domain = f"{selector}._domainkey.{fqdn}"
    try:
        answers = dns.resolver.resolve(dkim_domain, "TXT")
        for rdata in answers:
            return rdata.to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    return None


def check_dmarc_record(fqdn):
    dmarc_domain = f"_dmarc.{fqdn}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt_record = rdata.to_text()
            if "v=DMARC1" in txt_record:
                return txt_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    return None


def get_status(spf_record):
    if spf_record is None:
        return "NO SPF", "MISSING"
    elif "include:_spf.ram24.net" in spf_record:
        return spf_record, "OK"
    else:
        return spf_record, "WRONG"


def check_itce(spf_record):
    if spf_record is None:
        return "NO SPF"
    elif "itce" in spf_record:
        return "FOUND"
    else:
        return "OK"


def main():
    filename = "urls.txt"
    fqdns = extract_fqdns_from_file(filename)

    current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H%M")
    output_filename = f"{current_time}.txt"

    with open(output_filename, "w") as output_file:
        for fqdn in fqdns:
            spf_record = check_spf_record(fqdn)
            spf, status = get_status(spf_record)
            itce_status = check_itce(spf_record)

            # DKIM Check
            dkim_record = check_dkim_record(fqdn)
            dkim_status = dkim_record if dkim_record else "NO DKIM"

            # DMARC Check
            dmarc_record = check_dmarc_record(fqdn)
            dmarc_status = dmarc_record if dmarc_record else "NO DMARC"

            # Write results to the output file
            output_file.write(f"FQDN: {fqdn}\n")
            output_file.write(f"SPF: {spf}\n")
            output_file.write(f"ITCE: {itce_status}\n")
            output_file.write(f"STATUS: {status}\n")
            output_file.write(f"DKIM: {dkim_status}\n")
            output_file.write(f"DMARC: {dmarc_status}\n")
            output_file.write("\n")

    print(f"Results written to {output_filename}")


if __name__ == "__main__":
    main()
