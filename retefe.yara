rule retefe_encoded_buffer
{
    meta:
        description = "Find Retefe encoded buffer"
    strings:
        $a = {48 8b 44 24 20 8b 40 08 48 8b 4c 24 20 48 8d 15}
    condition:
        $a
}

rule retefe_xor_seed
{
    meta:
        description = "Find Retefe xor seed for decryption which actually is the encoded buffer length - 1"
    strings:
        $a = {24 20 48 8b 44 24 20 C7 40 08 }
    condition:
        $a
}

rule retefe_xor_seed_2ndarg
{
    meta:
        description = "Find power of that will be applied to XOR seed"
    strings:
        $a = {89 54 24 10 48 89 4c 24 08 48 83 ec 58 ba}
    condition:
        $a
}

rule retefe_shift_and_sub_match
{
    meta:
        description = "Find shifts and subtraction values used after power of seed has been applied"
    strings:
        $a = {c1 e0 ?? b9}
    condition:
        $a
}