.class public abstract Llp/qd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B
    .locals 8

    .line 1
    const-string v0, "AesGcmImpl: "

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    :try_start_0
    array-length v3, p0

    .line 6
    const/16 v4, 0x1c

    .line 7
    .line 8
    if-ge v3, v4, :cond_0

    .line 9
    .line 10
    new-instance p0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string p1, ": Ciphertext is too short."

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    new-array p1, v2, [Ljava/lang/Object;

    .line 28
    .line 29
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    return-object v1

    .line 33
    :catch_0
    move-exception p0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {p2, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    new-instance v4, Ljavax/crypto/spec/GCMParameterSpec;

    .line 44
    .line 45
    const/16 v5, 0x80

    .line 46
    .line 47
    const/16 v6, 0xc

    .line 48
    .line 49
    invoke-direct {v4, v5, p0, v2, v6}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[BII)V

    .line 50
    .line 51
    .line 52
    const-string v5, "AES/GCM/NoPadding"

    .line 53
    .line 54
    invoke-static {v5}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    const/4 v7, 0x2

    .line 59
    invoke-virtual {v5, v7, p1, v4}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v5, v3}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 63
    .line 64
    .line 65
    array-length p1, p0

    .line 66
    sub-int/2addr p1, v6

    .line 67
    invoke-virtual {v5, p0, v6, p1}, Ljavax/crypto/Cipher;->doFinal([BII)[B

    .line 68
    .line 69
    .line 70
    move-result-object p0
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/NoSuchPaddingException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/InvalidAlgorithmParameterException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/InvalidKeyException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/BadPaddingException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/IllegalBlockSizeException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/ProviderException; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    return-object p0

    .line 72
    :goto_0
    const-string p1, ": Failed to decrypt keychain value. Exception: "

    .line 73
    .line 74
    invoke-static {v0, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    new-array p1, v2, [Ljava/lang/Object;

    .line 90
    .line 91
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    return-object v1
.end method

.method public static b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B
    .locals 10

    .line 1
    const-string v1, "AesGcmImpl: "

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v3, 0x0

    .line 5
    :try_start_0
    array-length v0, p0

    .line 6
    const v4, 0x7fffffe3

    .line 7
    .line 8
    .line 9
    if-le v0, v4, :cond_0

    .line 10
    .line 11
    new-instance p0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string p1, ": Plaintext is too long."

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-array p1, v3, [Ljava/lang/Object;

    .line 29
    .line 30
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-object v2

    .line 34
    :catch_0
    move-exception v0

    .line 35
    move-object p0, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    array-length v0, p0

    .line 38
    add-int/lit8 v0, v0, 0x1c

    .line 39
    .line 40
    new-array v8, v0, [B

    .line 41
    .line 42
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p2, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v4, "AES/GCM/NoPadding"

    .line 51
    .line 52
    invoke-static {v4}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x1

    .line 57
    invoke-virtual {v4, v5, p1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v4, v0}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 61
    .line 62
    .line 63
    array-length v7, p0

    .line 64
    const/16 v9, 0xc

    .line 65
    .line 66
    const/4 v6, 0x0

    .line 67
    move-object v5, p0

    .line 68
    invoke-virtual/range {v4 .. v9}, Ljavax/crypto/Cipher;->doFinal([BII[BI)I

    .line 69
    .line 70
    .line 71
    invoke-virtual {v4}, Ljavax/crypto/Cipher;->getIV()[B

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    const/16 p1, 0xc

    .line 76
    .line 77
    invoke-static {p0, v3, v8, v3, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/NoSuchPaddingException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/InvalidKeyException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/BadPaddingException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/IllegalBlockSizeException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljavax/crypto/ShortBufferException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/ProviderException; {:try_start_0 .. :try_end_0} :catch_0

    .line 78
    .line 79
    .line 80
    return-object v8

    .line 81
    :goto_0
    const-string p1, ": Failed to encrypt keychain value. Exception: "

    .line 82
    .line 83
    invoke-static {v1, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    new-array p1, v3, [Ljava/lang/Object;

    .line 99
    .line 100
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    return-object v2
.end method
