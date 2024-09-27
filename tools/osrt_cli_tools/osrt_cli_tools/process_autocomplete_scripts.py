import sys
import shutil
import io
from importlib.metadata import entry_points

from pathlib import Path


def process_bash_complete():
    """Load bash complete scripts - as registered under the ``osrt_bash_complete`` entry point.
    Add source commands to provided target file.
    Optional PS1 prefix for dev environment can be passed as the 3rd argument. Any prefix is accepted.
    Also optional arg - shell type: for now bash and zsh are supported (default is bash)
    """
    if len(sys.argv) < 3:
        print("Must provide at least two arguments: source path for scripts and bashrc location")
        sys.exit(1)
    target_dir = Path(sys.argv[1])
    target_file_path = Path(sys.argv[2])
    prefix = sys.argv[3] if len(sys.argv) >= 4 else ""
    shell = sys.argv[4] if len(sys.argv) >= 5 else "bash"
    if shell not in ["bash", "zsh"]:
        raise RuntimeError(f"Not supported shell type: {shell}")
    complete_scripts = entry_points().select(group="osrt_bash_complete")
    with open(target_file_path, "at") as target_file:
        target_file.seek(0, io.SEEK_END)
        target_file.write("\n")
        for ep in complete_scripts:
            source_file_path = ep.load()()
            source_file_name = source_file_path.name
            # copy bash/zsh complete depending on the argument
            if shell == "zsh":
                source_file_name = source_file_path.name.rstrip(".bash") + ".zsh"
                source_file_path = source_file_path.parent / source_file_name
            target_completion_script = target_dir / source_file_name
            if source_file_path.exists():
                shutil.copyfile(source_file_path, target_completion_script)
                target_file.write(f". {target_completion_script}\n")

        target_file.write(
            rf"""
red=$(tput setaf 1)
yellow=$(tput setaf 3)            
cyan=$(tput setaf 6)
green=$(tput setaf 2)
blue=$(tput setaf 4)
bold=$(tput bold)
reset=$(tput sgr0)


export OPENSYNC_RES_TIMER=""

prompt_command() {{
    if [[ $OPENSYNC_TESTBED && $FRAMEWORK_CACHE_DIR ]]; then
        local_reserve_file="$FRAMEWORK_CACHE_DIR/.reserve_$OPENSYNC_TESTBED"
        export TMP_OPENSYNC_RES_TIMER=""
        if [[ -f $local_reserve_file ]]; then
            res_end=$(date --date "$(flock -x $local_reserve_file cat $local_reserve_file)" +%s 2>&1)
            if [ $? -eq 0 ]; then
                now=$(date +%s)
                delta=$((res_end - now))
                if (( $delta < 0 )); then
                    TMP_OPENSYNC_RES_TIMER="${{red}}[EXPIRED]${{reset}}"
                else
                    TMP_OPENSYNC_RES_TIMER="[$(printf '%d:%02d:%02d' $((delta/3600)) $((delta%3600/60)) $((delta%60)))]"
                
                    if (( $delta < 1800 )); then
                        TMP_OPENSYNC_RES_TIMER="${{yellow}}[$(printf '%d:%02d:%02d' $((delta/3600)) $((delta%3600/60)) $((delta%60)))]${{reset}}"
                    fi
                    if (( $delta < 900 )); then
                        TMP_OPENSYNC_RES_TIMER="${{red}}[$(printf '%d:%02d:%02d' $((delta/3600)) $((delta%3600/60)) $((delta%60)))]${{reset}}"
                    fi
                fi
                OPENSYNC_RES_TIMER=$TMP_OPENSYNC_RES_TIMER
            fi
        else
            OPENSYNC_RES_TIMER=""
        fi
    fi
}}
PROMPT_COMMAND='prompt_command'; $PROMPT_COMMAND

if [ $OPENSYNC_TESTBED ]; then
    PS1="{prefix}\$OPENSYNC_RES_TIMER\\[$bold\\]\\[$cyan\\][$OPENSYNC_TESTBED]\\[$green\\]\\u@\\h:\\[$blue\\]\\w\\[$reset\\]\$ "
fi
"""
        )
