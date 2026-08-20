# SecretsDump Reporter

Parses the output of [Impacket](https://github.com/fortra/impacket)'s `secretsdump.py` (run with `-user-status`) and produces a self-contained HTML report and a CSV file for further analysis.

![SecretsDump Reporter screenshot](https://raw.githubusercontent.com/yepskotch/SecretsDumpReporter/main/screenshot.png)

## Features

- **Account summary** — enabled/disabled counts for users and computers
- **Password reuse analysis** — groups accounts sharing the same NT hash, with enabled accounts highlighted
- **Blank password detection** — flags accounts with no password set
- **LM hash detection** — flags accounts with LM hashing enabled (trivially crackable)
- **Potfile integration** — match a hashcat `.potfile` to surface cracked passwords in the report
- **Two HTML reports** — full report with clickable hashes/passwords and a redacted version safe to share
- **CSV export** — full account list with reuse group, cracked password, blank password and LM hash flags
- **Self-contained output** — the HTML report embeds all assets (logo, CSS, JS); no internet connection required to view it
- No external Python dependencies — stdlib only

## Requirements

- Python 3.10+

## Installation

Install from PyPI:

```
pip install secretsdump-reporter
```

Or with pipx for an isolated, globally available command:

```
pipx install secretsdump-reporter
```

Or run directly from source without installing:

```
python3 sdr.py <secretsdump_output.txt>
```

## Usage

```
secretsdump-reporter <secretsdump_output.txt>
```

### Options

| Flag | Description |
|---|---|
| `input` | Path to the secretsdump output file |
| `-o / --output` | Base name for output files (default: input filename without extension) |
| `-p / --potfile` | Path to a hashcat `.potfile` to match cracked passwords |

### Example

```
secretsdump-reporter dump.txt
secretsdump-reporter dump.txt -o results/report
secretsdump-reporter dump.txt -p hashcat.potfile -o results/report
```

## Output files

| File | Description |
|---|---|
| `<base>.html` | Full HTML report — NT hashes and cracked passwords are clickable to copy |
| `<base>_redacted.html` | Redacted report — hashes partially obscured, passwords hidden; safe to share |
| `<base>.csv` | Full account list — domain, username, RID, NT hash, type, status, reuse group, cracked password |

## Input format

secretsdump must be run with `-user-status` to include account status in the output:

```
secretsdump.py -user-status -outputfile dump <target>
```

This writes the results to `dump.ntds` (among other files). Pass that file to `secretsdump-reporter`:

```
secretsdump-reporter dump.ntds
```

Expected line format:

```
domain\username:RID:LM_hash:NT_hash::: (status=Enabled|Disabled)
```

Computer accounts (ending in `$`) are automatically distinguished from user accounts.
