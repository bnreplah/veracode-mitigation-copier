# Veracode Mitigation Copier


![ Veracode SCA ](https://github.com/bnreplah/veracode-mitigation-copier/actions/workflows/sca.yml/badge.svg)
![ Veracode Static ](https://github.com/bnreplah/veracode-mitigation-copier/actions/workflows/pipeline-scan-py.yml/badge.svg)
![ Veracode Policy Scan ](https://github.com/bnreplah/veracode-mitigation-copier/actions/workflows/policyscan.yml/badge.svg)


[MitigationCopierv2](#mitigationcopierv2py)

Copies mitigations from one Veracode profile to another if it's the same flaw based on the following flaw attributes:

- **Static**: `cweid`, `type`, `sourcefile`, and `line` (see Note 1 below)
- **Static (no debug information)**: `cweid`, `type`, `procedure` and `relative_location`
- **Dynamic**: `cweid`, `path` and `vulnerable_parameter`

The script will copy all proposed and accepted mitigations for the flaw. The script will skip a flaw in the `copy_to` build if it already has an accepted mitigation.

*Note*: This script requires Python 3!

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-mitigation-copier

Install dependencies:

    cd veracode-mitigation-copier
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python MitigationCopier.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python MitigationCopier.py (arguments)

Arguments supported include:

- `-f`, `--fromapp` - Application GUID that you want to copy mitigations from.
- `-fs`, `--fromsandbox` (optional) - Sandbox GUID that you want to copy mitigations from. Ignored if `--prompt` is set.
- `-t`, `--toapp` - Application GUID that you want to copy mitigations to.
- `-ts`, `--tosandbox` (optional) - Sandbox GUID that you want to copy mitigations to. Ignored if `--prompt` is set.
- `-p`, `--prompt` - Specify to prompt for the applications to copy from and to.
- `-d`, `--dry_run` (optional) - Specify to log potential copied mitigations rather than actually mitigating the findings.
- `-l`, `--legacy_ids` (optional) - Specify to use legacy Veracode application IDs rather than application GUIDs.
- `-po`, `--propose-only` (optional) - If specified, only propose mitigations; do not approve the copied mitigations.
- `-i`, `--id_list` (optional) - If specified, only copy mitigations from the `fromapp` for the flaw IDs in `id_list`.

## Logging

The script creates a `MitigationCopier.log` file. All actions are logged.

## Usage examples

### Copy from one application profile to another with prompts

    python MitigationCopier.py --prompt

### Copy from one application profile to another, specifying the profiles

    python MitigationCopier.py --fromapp abcdefgh-1234-abcd-1234-123456789012 --toapp 12345678-abcd-1234-abcd-abcdefghijkl

### Copy mitigations for a subset of findings

    python MitigationCopier.py --fromapp abcdefgh-1234-abcd-1234-123456789012 --toapp 12345678-abcd-1234-abcd-abcdefghijkl --id_list 1 2 3

You must provide the application GUID values for both application profiles. You can look these up by calling the [Veracode Applications API](https://help.veracode.com/r/c_apps_intro) (or use the `--prompt` argument and copy the GUIDs from the console output).

### Copy from one application profile to another, specifying the profiles with legacy IDs

    python MitigationCopier.py --fromapp 1234567 --toapp 7654321

You must provide the legacy Veracode application ID values for both application profiles. These IDs are available from the Veracode XML APIs.

### See which findings are affected in a target profile, but don't copy the mitigations

    python MitigationCopier.py --prompt --dry_run


## Notes

1. For static findings, when matching by line number, we automatically look within a range of line numbers around the original finding line number to allow for drift. This is controlled by the constant `LINE_NUMBER_SLOP` declared at the top of the file.
2. For static findings when source file information is not available, we try to use procedure and relative location. This is less predictable so it is recommended that you perform a dry run when copying mitigations from non-debug code. Unlike when source file information is available, we do not use "sloppy matching" in this case -- we have observed that mitigations in non-debug code are most common when a binary dependency is being reused across teams and thus locations are less likely to change.


# MitigationCopierv2.py #

The mitigation copier 2 is an alternative python entry point to utilize the program in order to copy proposed mitigations between builds. This allows you to copy mitigations from a sandbox scan in one application profile to a scan in another application profile, or the same application profile. 
The mitigation copier 2 is originally the work of gilmore867. Current additions include the ability to read a csv providing the build id of the scan with the mitigations to be copied and the build id of the recipient scan to recieve the copied mitigations. 


## Setup ##

(2.0)
```
git clone https://github.com/gilmore867/veracode-mitigation-copier
```
with csv functionality: (2.1)
```
git clone https://github.com/bnreplah/veracode-mitigation-copier
```

> The remainder of the set up matches that described above. The MitigationCopier.py will still be availble to use. [Usage for MitigationCopier.py](#Veracode-Mitigation-Copier##Run)

The modification to the mitigation copier 2 in this repo, allows for the ability to pass a csv with the build ids mapped to and from in the first two columns.

```csv

fromBuildId, toBuildId
112313421, 133343421
112313421, 134353421
112313421, 133345421
112313421, 133452321 
```

## Run ##

```shell
MitigationCopierv2.py [-h] [-f FROMBUILD] [-t TOBUILD] [-v VID] [-k VKEY] [-c CSV] [-csv READFROMCSV]
Either --frombuild and --tobuild or --csv and --readfromcsv set to true must be provided
```

to copy mitigations from build `112313421` to build `133343421`
```
python MitigationCopierv2.py -f 112313421 -t 133343421 -v $VERACODE_API_KEY_ID -k $VERACODE_API_KEY_SECRET 
```
or to copy using the csv feature


```shell
python MitigationCopierv2.py -csv true -c tofrombuild.csv -v $VERACODE_API_KEY_ID -k $VERACODE_API_KEY_SECRET 
```



## Variations

1. Original: https://github.com/brian1917/veracode-mitigation-copier
2. tjarettveracode: https://github.com/tjarrettveracode/veracode-mitigation-copier
3. gilmor897: https://github.com/gilmore867/veracode-mitigation-copier

