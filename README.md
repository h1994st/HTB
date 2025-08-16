# OSCP Preparation

> References
>
> - <https://0xdf.gitlab.io/cheatsheets/offsec>

## Best Practice

### Initial Inspection

- Port scanning

    ```bash
    sudo nmap -vv -sC -sV -T4 -A <your IP>
    ```

- Subdomain discovery

    ```bash
    ffuf -u http://target.website -H "Host: FUZZ.target.website" -w /path/to/wordlist/subdomains-top1million-20000.txt -ac
    ```
