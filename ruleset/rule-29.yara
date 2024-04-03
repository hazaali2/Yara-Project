rule candidateRule29 {
  strings:
    $a = "FILE"
    $b = { F7 87 }
  condition:
    $a in (0..200) and $b in (filesize-200..filesize)
}
