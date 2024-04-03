rule candidateRule16 {
  strings:
    $a = { 41 41 41 41 }
    $b = { BA CE [0-100] D1 }
  condition:
    $a at 0 and $b
}
