rule candidateRule15 {
  strings:
    $a = { 41 41 41 41 }
    $b = { F9 69 [0-500] ED }
  condition:
    $a at 0 and $b
}
