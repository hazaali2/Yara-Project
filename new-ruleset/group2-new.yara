rule candidateRule04 {
  strings:
    $a = { FE C3 [0-12] B0 51 }
  condition:
    $a
}

rule candidateRule10 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { B8 CA }
  condition:
    $a at 0 and $b
}

rule candidateRule26 {
  strings:
    $a = "FILE"
    $b = { DA C4 [0-24] 24 }
  condition:
    $a at 0 and $b
}

rule candidateRule30 {
  strings:
    $a = "FILE"
    $b = { DC }
  condition:
    $a in (0..200) and $b in (filesize-200..filesize)
}

rule newRuleOne {
  strings:
    $a = { 46494c45fa }
    $b = { 0c00bbbb79 }
    $c = { 41414141d3 }
    $d = { 7265642127 }
  condition:
    $a or $b or $c or $d
}

rule newRuleTwo {
    strings:
        $a = { 44 B2 E5 E1 }
        $b = { B5 D8 83 D2 }
        $c = { 0C 00 BB BB 34 01 }
        $d = { 90 8E A3 }
    condition:
        $a or $b or $c or $d
}
