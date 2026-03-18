.class public final Lg1/d2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lg1/d2;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p0, p0, Lg1/d2;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lg1/d2;

    .line 7
    .line 8
    const/4 p1, 0x2

    .line 9
    const/4 v0, 0x6

    .line 10
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_0
    new-instance p0, Lg1/d2;

    .line 15
    .line 16
    const/4 p1, 0x2

    .line 17
    const/4 v0, 0x5

    .line 18
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    new-instance p0, Lg1/d2;

    .line 23
    .line 24
    const/4 p1, 0x2

    .line 25
    const/4 v0, 0x4

    .line 26
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_2
    new-instance p0, Lg1/d2;

    .line 31
    .line 32
    const/4 p1, 0x2

    .line 33
    const/4 v0, 0x3

    .line 34
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_3
    new-instance p0, Lg1/d2;

    .line 39
    .line 40
    const/4 p1, 0x2

    .line 41
    const/4 v0, 0x2

    .line 42
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_4
    new-instance p0, Lg1/d2;

    .line 47
    .line 48
    const/4 p1, 0x2

    .line 49
    const/4 v0, 0x1

    .line 50
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_5
    new-instance p0, Lg1/d2;

    .line 55
    .line 56
    const/4 p1, 0x2

    .line 57
    const/4 v0, 0x0

    .line 58
    invoke-direct {p0, p1, p2, v0}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/d2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/d2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg1/d2;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lg1/d2;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    return-object p1

    .line 56
    :pswitch_2
    check-cast p1, Lyy0/j;

    .line 57
    .line 58
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 59
    .line 60
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Lg1/d2;

    .line 65
    .line 66
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    :pswitch_3
    check-cast p1, Lyy0/j;

    .line 73
    .line 74
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 75
    .line 76
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lg1/d2;

    .line 81
    .line 82
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    return-object p1

    .line 88
    :pswitch_4
    check-cast p1, Lg1/e2;

    .line 89
    .line 90
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 91
    .line 92
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Lg1/d2;

    .line 97
    .line 98
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    return-object p1

    .line 104
    :pswitch_5
    check-cast p1, Lg1/e2;

    .line 105
    .line 106
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 107
    .line 108
    invoke-virtual {p0, p1, p2}, Lg1/d2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    check-cast p0, Lg1/d2;

    .line 113
    .line 114
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    invoke-virtual {p0, p1}, Lg1/d2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    return-object p1

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lg1/d2;->d:I

    .line 2
    .line 3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    const-string p0, "AndroidKeyStore"

    .line 14
    .line 15
    invoke-static {p0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-virtual {p1, v0}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 21
    .line 22
    .line 23
    const-string v1, "SPIN_KEY"

    .line 24
    .line 25
    invoke-virtual {p1, v1, v0}, Ljava/security/KeyStore;->getKey(Ljava/lang/String;[C)Ljava/security/Key;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    check-cast p1, Ljavax/crypto/SecretKey;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance p1, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 35
    .line 36
    const/4 v0, 0x3

    .line 37
    invoke-direct {p1, v1, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    const-string v0, "GCM"

    .line 41
    .line 42
    filled-new-array {v0}, [Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p1, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setBlockModes([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 47
    .line 48
    .line 49
    const-string v0, "NoPadding"

    .line 50
    .line 51
    filled-new-array {v0}, [Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {p1, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 56
    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    invoke-virtual {p1, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setUserAuthenticationRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 60
    .line 61
    .line 62
    const/4 v0, 0x0

    .line 63
    invoke-virtual {p1, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setInvalidatedByBiometricEnrollment(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    const-string v0, "build(...)"

    .line 71
    .line 72
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const-string v0, "AES"

    .line 76
    .line 77
    invoke-static {v0, p0}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-virtual {p0, p1}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    const-string p0, "generateKey(...)"

    .line 89
    .line 90
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :goto_0
    return-object p1

    .line 94
    :pswitch_0
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 95
    .line 96
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :pswitch_1
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    return-object v0

    .line 110
    :pswitch_2
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_3
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    return-object v0

    .line 122
    :pswitch_4
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 123
    .line 124
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    return-object v0

    .line 128
    :pswitch_5
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    return-object v0

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
