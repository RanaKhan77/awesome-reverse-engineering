rule duckcfg
{
    strings:
        $cfg = "DKCFG1"
    condition:
        $cfg
}
