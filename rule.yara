rule cs_job_pipe
{
    meta:
        description = "Detects CobaltStrike Post Exploitation Named Pipes"
        author = "Riccardo Ancarani & Jon Cave"
        date = "2020-10-04"
    strings:
        $pipe = /msagent_ce/ ascii wide fullword
    condition:
        $pipe
}
