.class public final Lzq0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lzq0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lzq0/f;

    .line 7
    .line 8
    iget v1, v0, Lzq0/f;->j:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lzq0/f;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzq0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lzq0/f;-><init>(Lzq0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lzq0/f;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lzq0/f;->j:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget p1, v0, Lzq0/f;->g:I

    .line 37
    .line 38
    iget-object p2, v0, Lzq0/f;->f:Ljavax/crypto/Cipher;

    .line 39
    .line 40
    iget-object v1, v0, Lzq0/f;->e:Ljavax/crypto/Cipher;

    .line 41
    .line 42
    iget-object v0, v0, Lzq0/f;->d:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    const-string p0, "AES/GCM/NoPadding"

    .line 60
    .line 61
    invoke-static {p0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string v1, "getInstance(...)"

    .line 66
    .line 67
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iput-object p1, v0, Lzq0/f;->d:Ljava/lang/String;

    .line 71
    .line 72
    iput-object p0, v0, Lzq0/f;->e:Ljavax/crypto/Cipher;

    .line 73
    .line 74
    iput-object p0, v0, Lzq0/f;->f:Ljavax/crypto/Cipher;

    .line 75
    .line 76
    const/4 v1, 0x2

    .line 77
    iput v1, v0, Lzq0/f;->g:I

    .line 78
    .line 79
    iput v2, v0, Lzq0/f;->j:I

    .line 80
    .line 81
    sget-object v2, Lge0/b;->c:Lcz0/d;

    .line 82
    .line 83
    new-instance v3, Lg1/d2;

    .line 84
    .line 85
    const/4 v4, 0x0

    .line 86
    const/4 v5, 0x6

    .line 87
    invoke-direct {v3, v1, v4, v5}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v2, v3, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    if-ne v0, p2, :cond_3

    .line 95
    .line 96
    return-object p2

    .line 97
    :cond_3
    move-object p2, p0

    .line 98
    move-object p0, v0

    .line 99
    move-object v0, p1

    .line 100
    move p1, v1

    .line 101
    move-object v1, p2

    .line 102
    :goto_1
    check-cast p0, Ljava/security/Key;

    .line 103
    .line 104
    new-instance v2, Ljavax/crypto/spec/GCMParameterSpec;

    .line 105
    .line 106
    sget-object v3, Lly0/a;->d:Ljava/nio/charset/Charset;

    .line 107
    .line 108
    invoke-virtual {v0, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    const-string v3, "getBytes(...)"

    .line 113
    .line 114
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const/16 v3, 0x80

    .line 118
    .line 119
    invoke-direct {v2, v3, v0}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p2, p1, p0, v2}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 123
    .line 124
    .line 125
    return-object v1
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lzq0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzq0/g;

    .line 7
    .line 8
    iget v1, v0, Lzq0/g;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lzq0/g;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzq0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lzq0/g;-><init>(Lzq0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lzq0/g;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lzq0/g;->i:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget v2, v0, Lzq0/g;->f:I

    .line 37
    .line 38
    iget-object p1, v0, Lzq0/g;->e:Ljavax/crypto/Cipher;

    .line 39
    .line 40
    iget-object v0, v0, Lzq0/g;->d:Ljavax/crypto/Cipher;

    .line 41
    .line 42
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    const-string p0, "AES/GCM/NoPadding"

    .line 58
    .line 59
    invoke-static {p0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string v1, "getInstance(...)"

    .line 64
    .line 65
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iput-object p0, v0, Lzq0/g;->d:Ljavax/crypto/Cipher;

    .line 69
    .line 70
    iput-object p0, v0, Lzq0/g;->e:Ljavax/crypto/Cipher;

    .line 71
    .line 72
    iput v2, v0, Lzq0/g;->f:I

    .line 73
    .line 74
    iput v2, v0, Lzq0/g;->i:I

    .line 75
    .line 76
    sget-object v1, Lge0/b;->c:Lcz0/d;

    .line 77
    .line 78
    new-instance v3, Lg1/d2;

    .line 79
    .line 80
    const/4 v4, 0x2

    .line 81
    const/4 v5, 0x6

    .line 82
    const/4 v6, 0x0

    .line 83
    invoke-direct {v3, v4, v6, v5}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 84
    .line 85
    .line 86
    invoke-static {v1, v3, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-ne v0, p1, :cond_3

    .line 91
    .line 92
    return-object p1

    .line 93
    :cond_3
    move-object p1, p0

    .line 94
    move-object p0, v0

    .line 95
    move-object v0, p1

    .line 96
    :goto_1
    check-cast p0, Ljava/security/Key;

    .line 97
    .line 98
    invoke-virtual {p1, v2, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 99
    .line 100
    .line 101
    return-object v0
.end method
