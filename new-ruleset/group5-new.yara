rule candidateRule02 {
  strings:
    $a = "red!"
    $b = { FE C3 9C F4  85 F5 14 5C  B0 51 F5 B9 }
  condition:
    $a at 0 and $b
}

rule candidateRule17 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { C4 79 D1 }
  condition:
    $a at 0 and $b
}

rule candidateRule08 {
  strings:
    $a = "red!"
    $b = { FB 8E 8D }
  condition:
    $a at 0 and $b
}

rule candidateRule09 {
  strings:
    $a = { 0C 00 BB BB }
    $b = { 8E 8D }
  condition:
    $a at 0 and $b
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
