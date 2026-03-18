.class public final Lor/c;
.super Leb/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lor/c;->h:I

    .line 2
    new-instance v0, Lor/a;

    const/4 v1, 0x1

    .line 3
    invoke-direct {v0, v1}, Lor/a;-><init>(I)V

    .line 4
    filled-new-array {v0}, [Lor/a;

    move-result-object v0

    const-class v1, Lqr/j;

    invoke-direct {p0, v1, v0}, Leb/j0;-><init>(Ljava/lang/Class;[Lor/a;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Class;[Lor/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lor/c;->h:I

    invoke-direct {p0, p1, p2}, Leb/j0;-><init>(Ljava/lang/Class;[Lor/a;)V

    return-void
.end method

.method public static final J()Lh6/e;
    .locals 5

    .line 1
    invoke-static {}, Lqr/n;->r()Lqr/m;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 9
    .line 10
    check-cast v1, Lqr/n;

    .line 11
    .line 12
    invoke-static {v1}, Lqr/n;->m(Lqr/n;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 16
    .line 17
    .line 18
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 19
    .line 20
    check-cast v1, Lqr/n;

    .line 21
    .line 22
    invoke-static {v1}, Lqr/n;->n(Lqr/n;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lqr/n;

    .line 30
    .line 31
    invoke-static {}, Lqr/l;->q()Lqr/k;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v1}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 36
    .line 37
    .line 38
    iget-object v2, v1, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 39
    .line 40
    check-cast v2, Lqr/l;

    .line 41
    .line 42
    invoke-static {v2, v0}, Lqr/l;->m(Lqr/l;Lqr/n;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 46
    .line 47
    .line 48
    iget-object v0, v1, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 49
    .line 50
    check-cast v0, Lqr/l;

    .line 51
    .line 52
    invoke-static {v0}, Lqr/l;->n(Lqr/l;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Lqr/l;

    .line 60
    .line 61
    new-instance v1, Lor/c;

    .line 62
    .line 63
    invoke-direct {v1}, Lor/c;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/a;->c()[B

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    new-instance v1, Lh6/e;

    .line 71
    .line 72
    invoke-static {}, Lqr/t;->s()Lqr/s;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 77
    .line 78
    .line 79
    iget-object v3, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 80
    .line 81
    check-cast v3, Lqr/t;

    .line 82
    .line 83
    invoke-static {v3}, Lqr/t;->m(Lqr/t;)V

    .line 84
    .line 85
    .line 86
    const/4 v3, 0x0

    .line 87
    array-length v4, v0

    .line 88
    invoke-static {v0, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 93
    .line 94
    .line 95
    iget-object v3, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 96
    .line 97
    check-cast v3, Lqr/t;

    .line 98
    .line 99
    invoke-static {v3, v0}, Lqr/t;->n(Lqr/t;Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 103
    .line 104
    .line 105
    iget-object v0, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 106
    .line 107
    check-cast v0, Lqr/t;

    .line 108
    .line 109
    sget-object v3, Lqr/d0;->f:Lqr/d0;

    .line 110
    .line 111
    invoke-static {v0, v3}, Lqr/t;->o(Lqr/t;Lqr/d0;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    check-cast v0, Lqr/t;

    .line 119
    .line 120
    const/16 v2, 0x16

    .line 121
    .line 122
    invoke-direct {v1, v0, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 123
    .line 124
    .line 125
    return-object v1
.end method

.method public static K(Lqr/e;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lqr/e;->n()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    if-lt v0, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Lqr/e;->n()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/16 v0, 0x10

    .line 14
    .line 15
    if-gt p0, v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 19
    .line 20
    const-string v0, "tag size too long"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 27
    .line 28
    const-string v0, "tag size too short"

    .line 29
    .line 30
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public static L(Lqr/n;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lqr/n;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    if-lt v0, v1, :cond_6

    .line 8
    .line 9
    invoke-virtual {p0}, Lqr/n;->p()Lqr/h;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x1

    .line 18
    const-string v2, "tag size too big"

    .line 19
    .line 20
    if-eq v0, v1, :cond_4

    .line 21
    .line 22
    const/4 v1, 0x3

    .line 23
    if-eq v0, v1, :cond_2

    .line 24
    .line 25
    const/4 v1, 0x4

    .line 26
    if-ne v0, v1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Lqr/n;->q()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    const/16 v0, 0x40

    .line 33
    .line 34
    if-gt p0, v0, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 38
    .line 39
    invoke-direct {p0, v2}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 44
    .line 45
    const-string v0, "unknown hash type"

    .line 46
    .line 47
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-virtual {p0}, Lqr/n;->q()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    const/16 v0, 0x20

    .line 56
    .line 57
    if-gt p0, v0, :cond_3

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_3
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 61
    .line 62
    invoke-direct {p0, v2}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_4
    invoke-virtual {p0}, Lqr/n;->q()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    const/16 v0, 0x14

    .line 71
    .line 72
    if-gt p0, v0, :cond_5

    .line 73
    .line 74
    :goto_0
    return-void

    .line 75
    :cond_5
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 76
    .line 77
    invoke-direct {p0, v2}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_6
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 82
    .line 83
    const-string v0, "tag size too small"

    .line 84
    .line 85
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0
.end method


# virtual methods
.method public final A(Lcom/google/crypto/tink/shaded/protobuf/i;)Lcom/google/crypto/tink/shaded/protobuf/a;
    .locals 0

    .line 1
    iget p0, p0, Lor/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p1, p0}, Lqr/j;->t(Lcom/google/crypto/tink/shaded/protobuf/i;Lcom/google/crypto/tink/shaded/protobuf/p;)Lqr/j;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p1, p0}, Lqr/b;->t(Lcom/google/crypto/tink/shaded/protobuf/i;Lcom/google/crypto/tink/shaded/protobuf/p;)Lqr/b;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final I(Lcom/google/crypto/tink/shaded/protobuf/a;)V
    .locals 3

    .line 1
    iget p0, p0, Lor/c;->h:I

    .line 2
    .line 3
    const-string v0, "key has version %d; only keys with version in range [0..%d] are supported"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    packed-switch p0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    check-cast p1, Lqr/j;

    .line 10
    .line 11
    invoke-virtual {p1}, Lqr/j;->r()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    sget v2, Lrr/f;->a:I

    .line 16
    .line 17
    if-ltz p0, :cond_1

    .line 18
    .line 19
    if-gtz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p1}, Lqr/j;->p()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    const/16 v0, 0x10

    .line 30
    .line 31
    if-lt p0, v0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p1}, Lqr/j;->q()Lqr/n;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-static {p0}, Lor/c;->L(Lqr/n;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 42
    .line 43
    const-string p1, "key too short"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    new-instance p1, Ljava/security/GeneralSecurityException;

    .line 50
    .line 51
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    filled-new-array {p0, v1}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-direct {p1, p0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p1

    .line 71
    :pswitch_0
    check-cast p1, Lqr/b;

    .line 72
    .line 73
    invoke-virtual {p1}, Lqr/b;->r()I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    sget v2, Lrr/f;->a:I

    .line 78
    .line 79
    if-ltz p0, :cond_3

    .line 80
    .line 81
    if-gtz p0, :cond_3

    .line 82
    .line 83
    invoke-virtual {p1}, Lqr/b;->p()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    const/16 v0, 0x20

    .line 92
    .line 93
    if-ne p0, v0, :cond_2

    .line 94
    .line 95
    invoke-virtual {p1}, Lqr/b;->q()Lqr/e;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-static {p0}, Lor/c;->K(Lqr/e;)V

    .line 100
    .line 101
    .line 102
    return-void

    .line 103
    :cond_2
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 104
    .line 105
    const-string p1, "AesCmacKey size wrong, must be 32 bytes"

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_3
    new-instance p1, Ljava/security/GeneralSecurityException;

    .line 112
    .line 113
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    filled-new-array {p0, v1}, [Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-direct {p1, p0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p1

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final t()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lor/c;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "type.googleapis.com/google.crypto.tink.HmacKey"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "type.googleapis.com/google.crypto.tink.AesCmacKey"

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final w()Lmr/a;
    .locals 1

    .line 1
    iget v0, p0, Lor/c;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lor/b;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lor/b;-><init>(Lor/c;)V

    .line 9
    .line 10
    .line 11
    return-object v0

    .line 12
    :pswitch_0
    new-instance p0, Lor/b;

    .line 13
    .line 14
    invoke-direct {p0}, Lor/b;-><init>()V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
