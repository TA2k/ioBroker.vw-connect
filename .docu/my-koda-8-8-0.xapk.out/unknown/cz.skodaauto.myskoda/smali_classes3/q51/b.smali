.class public final Lq51/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/security/KeyStore;

.field public final b:Lay0/n;


# direct methods
.method public constructor <init>(Ljava/security/KeyStore;)V
    .locals 2

    .line 1
    new-instance v0, Lpd0/a;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpd0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "keyStore"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lq51/b;->a:Ljava/security/KeyStore;

    .line 17
    .line 18
    iput-object v0, p0, Lq51/b;->b:Lay0/n;

    .line 19
    .line 20
    return-void
.end method

.method public static c(Lkp/r8;Ljavax/crypto/Cipher;)Lkp/r8;
    .locals 2

    .line 1
    instance-of v0, p0, Lg91/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lg91/b;

    .line 6
    .line 7
    iget-object p0, p0, Lg91/b;->a:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Llx0/l;

    .line 10
    .line 11
    iget-object v0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/security/Key;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-virtual {p1, v1, v0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Lg91/b;

    .line 20
    .line 21
    new-instance v1, Llx0/l;

    .line 22
    .line 23
    iget-object p0, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-direct {v1, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {v0, v1}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_0
    instance-of p1, p0, Lg91/a;

    .line 33
    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    check-cast p0, Lg91/a;

    .line 37
    .line 38
    new-instance p1, Lg91/a;

    .line 39
    .line 40
    iget-object p0, p0, Lg91/a;->a:Lq51/p;

    .line 41
    .line 42
    invoke-direct {p1, p0}, Lg91/a;-><init>(Lq51/p;)V

    .line 43
    .line 44
    .line 45
    return-object p1

    .line 46
    :cond_1
    new-instance p0, La8/r0;

    .line 47
    .line 48
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 49
    .line 50
    .line 51
    throw p0
.end method


# virtual methods
.method public final a(Lq51/e;J)Lkp/r8;
    .locals 2

    .line 1
    invoke-static {p1}, Lq51/r;->c(Lq51/e;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    const-string v0, "technology.cariad.cat.keychain.a_"

    .line 7
    .line 8
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object p2, p0, Lq51/b;->a:Ljava/security/KeyStore;

    .line 19
    .line 20
    invoke-static {p1, p2}, Lq51/r;->d(Ljava/lang/String;Ljava/security/KeyStore;)Lkp/r8;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    instance-of p3, p2, Lg91/b;

    .line 25
    .line 26
    if-eqz p3, :cond_2

    .line 27
    .line 28
    check-cast p2, Lg91/b;

    .line 29
    .line 30
    iget-object p2, p2, Lg91/b;->a:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p2, Ljavax/crypto/SecretKey;

    .line 33
    .line 34
    const/4 p3, 0x0

    .line 35
    if-eqz p2, :cond_1

    .line 36
    .line 37
    invoke-interface {p2}, Ljavax/security/auth/Destroyable;->isDestroyed()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-nez v0, :cond_0

    .line 42
    .line 43
    move-object v0, p2

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    move-object v0, p3

    .line 46
    :goto_0
    if-eqz v0, :cond_1

    .line 47
    .line 48
    new-instance p0, Lg91/b;

    .line 49
    .line 50
    invoke-direct {p0, v0}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_1
    sget-object v0, Lh91/e;->a:Lh91/e;

    .line 55
    .line 56
    new-instance v0, Lc41/b;

    .line 57
    .line 58
    const/16 v1, 0x15

    .line 59
    .line 60
    invoke-direct {v0, p2, p0, p1, v1}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v0}, Lh91/e;->a(Lay0/a;)V

    .line 64
    .line 65
    .line 66
    new-instance p0, Lg91/a;

    .line 67
    .line 68
    new-instance p1, Lq51/k;

    .line 69
    .line 70
    invoke-direct {p1, p3}, Lq51/k;-><init>(Ljava/security/UnrecoverableEntryException;)V

    .line 71
    .line 72
    .line 73
    invoke-direct {p0, p1}, Lg91/a;-><init>(Lq51/p;)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :cond_2
    instance-of p0, p2, Lg91/a;

    .line 78
    .line 79
    if-eqz p0, :cond_3

    .line 80
    .line 81
    check-cast p2, Lg91/a;

    .line 82
    .line 83
    new-instance p0, Lg91/a;

    .line 84
    .line 85
    iget-object p1, p2, Lg91/a;->a:Lq51/p;

    .line 86
    .line 87
    invoke-direct {p0, p1}, Lg91/a;-><init>(Lq51/p;)V

    .line 88
    .line 89
    .line 90
    return-object p0

    .line 91
    :cond_3
    new-instance p0, La8/r0;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 94
    .line 95
    .line 96
    throw p0
.end method

.method public final b(Lq51/e;)Lkp/r8;
    .locals 7

    .line 1
    iget-object v0, p0, Lq51/b;->a:Ljava/security/KeyStore;

    .line 2
    .line 3
    invoke-static {p1}, Lq51/r;->c(Lq51/e;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {v0}, Ljava/security/KeyStore;->aliases()Ljava/util/Enumeration;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "aliases(...)"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v1}, Ljava/util/Collections;->list(Ljava/util/Enumeration;)Ljava/util/ArrayList;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "list(...)"

    .line 20
    .line 21
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    const/4 v3, 0x0

    .line 33
    const/4 v4, 0x0

    .line 34
    const-string v5, "technology.cariad.cat.keychain.a_"

    .line 35
    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    :try_start_1
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    move-object v6, v2

    .line 43
    check-cast v6, Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-static {v6, v5, v3}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    move-object v2, v4

    .line 56
    :goto_0
    check-cast v2, Ljava/lang/String;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 57
    .line 58
    if-eqz v2, :cond_5

    .line 59
    .line 60
    invoke-static {v2, v0}, Lq51/r;->d(Ljava/lang/String;Ljava/security/KeyStore;)Lkp/r8;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    instance-of v1, v0, Lg91/b;

    .line 65
    .line 66
    if-eqz v1, :cond_2

    .line 67
    .line 68
    move-object v1, v0

    .line 69
    check-cast v1, Lg91/b;

    .line 70
    .line 71
    iget-object v1, v1, Lg91/b;->a:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v1, Ljavax/crypto/SecretKey;

    .line 74
    .line 75
    if-eqz v1, :cond_2

    .line 76
    .line 77
    invoke-interface {v1}, Ljavax/security/auth/Destroyable;->isDestroyed()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_2

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    move-object v0, v4

    .line 85
    :goto_1
    instance-of v1, v0, Lg91/b;

    .line 86
    .line 87
    if-eqz v1, :cond_3

    .line 88
    .line 89
    check-cast v0, Lg91/b;

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_3
    move-object v0, v4

    .line 93
    :goto_2
    if-eqz v0, :cond_4

    .line 94
    .line 95
    iget-object v0, v0, Lg91/b;->a:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v0, Ljavax/crypto/SecretKey;

    .line 98
    .line 99
    if-eqz v0, :cond_4

    .line 100
    .line 101
    new-instance v4, Lg91/b;

    .line 102
    .line 103
    new-instance v1, Llx0/l;

    .line 104
    .line 105
    const-string v6, ""

    .line 106
    .line 107
    invoke-static {v3, v2, v5, v6}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-static {v2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 112
    .line 113
    .line 114
    move-result-wide v2

    .line 115
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    invoke-direct {v1, v2, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-direct {v4, v1}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_4
    if-eqz v4, :cond_5

    .line 126
    .line 127
    return-object v4

    .line 128
    :cond_5
    invoke-virtual {p0, p1}, Lq51/b;->d(Lq51/e;)Lkp/r8;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0

    .line 133
    :catch_0
    invoke-virtual {p0, p1}, Lq51/b;->d(Lq51/e;)Lkp/r8;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0
.end method

.method public final d(Lq51/e;)Lkp/r8;
    .locals 4

    .line 1
    const-string v0, "technology.cariad.cat.keychain.a_"

    .line 2
    .line 3
    :try_start_0
    invoke-static {p1}, Lq51/r;->c(Lq51/e;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 7
    .line 8
    .line 9
    move-result-wide v1

    .line 10
    new-instance p1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance v0, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 23
    .line 24
    const/4 v3, 0x3

    .line 25
    invoke-direct {v0, p1, v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    const/16 p1, 0x100

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    const-string v3, "CTR"

    .line 35
    .line 36
    filled-new-array {v3}, [Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {p1, v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setBlockModes([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    const-string v3, "NoPadding"

    .line 45
    .line 46
    filled-new-array {v3}, [Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-virtual {p1, v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    const/4 v3, 0x1

    .line 55
    invoke-virtual {p1, v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setRandomizedEncryptionRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 56
    .line 57
    .line 58
    const/4 p1, 0x0

    .line 59
    invoke-virtual {v0, p1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setUserAuthenticationRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Lq51/b;->b:Lay0/n;

    .line 63
    .line 64
    const-string v3, "AES"

    .line 65
    .line 66
    iget-object p0, p0, Lq51/b;->a:Ljava/security/KeyStore;

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/security/KeyStore;->getProvider()Ljava/security/Provider;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-interface {p1, v3, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    check-cast p0, Ljavax/crypto/KeyGenerator;

    .line 77
    .line 78
    invoke-virtual {v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p0, p1}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 83
    .line 84
    .line 85
    new-instance p1, Lg91/b;

    .line 86
    .line 87
    new-instance v0, Llx0/l;

    .line 88
    .line 89
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {p0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-direct {v0, v1, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    invoke-direct {p1, v0}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 101
    .line 102
    .line 103
    return-object p1

    .line 104
    :catch_0
    move-exception p0

    .line 105
    new-instance p1, Lg91/a;

    .line 106
    .line 107
    new-instance v0, Lq51/l;

    .line 108
    .line 109
    invoke-static {p0}, Lkp/y5;->e(Ljava/lang/Exception;)Le91/b;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-direct {v0, p0}, Lq51/p;-><init>(Le91/b;)V

    .line 114
    .line 115
    .line 116
    invoke-direct {p1, v0}, Lg91/a;-><init>(Lq51/p;)V

    .line 117
    .line 118
    .line 119
    return-object p1
.end method
