.class public final Lor/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lor/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/crypto/tink/shaded/protobuf/a;)Lrr/d;
    .locals 4

    .line 1
    iget p0, p0, Lor/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lqr/j;

    .line 7
    .line 8
    invoke-virtual {p1}, Lqr/j;->q()Lqr/n;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Lqr/n;->p()Lqr/h;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p1}, Lqr/j;->p()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/b0;->b:[B

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-array v2, v1, [B

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/i;->i(I[B)V

    .line 32
    .line 33
    .line 34
    move-object v0, v2

    .line 35
    :goto_0
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;

    .line 36
    .line 37
    const-string v2, "HMAC"

    .line 38
    .line 39
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1}, Lqr/j;->q()Lqr/n;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-virtual {p1}, Lqr/n;->q()I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    const/4 v0, 0x1

    .line 55
    if-eq p0, v0, :cond_3

    .line 56
    .line 57
    const/4 v0, 0x3

    .line 58
    if-eq p0, v0, :cond_2

    .line 59
    .line 60
    const/4 v0, 0x4

    .line 61
    if-ne p0, v0, :cond_1

    .line 62
    .line 63
    new-instance p0, Lrr/d;

    .line 64
    .line 65
    new-instance v0, Lio/o;

    .line 66
    .line 67
    const-string v2, "HMACSHA512"

    .line 68
    .line 69
    invoke-direct {v0, v2, v1}, Lio/o;-><init>(Ljava/lang/String;Ljavax/crypto/spec/SecretKeySpec;)V

    .line 70
    .line 71
    .line 72
    invoke-direct {p0, v0, p1}, Lrr/d;-><init>(Lpr/a;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 77
    .line 78
    const-string p1, "unknown hash"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_2
    new-instance p0, Lrr/d;

    .line 85
    .line 86
    new-instance v0, Lio/o;

    .line 87
    .line 88
    const-string v2, "HMACSHA256"

    .line 89
    .line 90
    invoke-direct {v0, v2, v1}, Lio/o;-><init>(Ljava/lang/String;Ljavax/crypto/spec/SecretKeySpec;)V

    .line 91
    .line 92
    .line 93
    invoke-direct {p0, v0, p1}, Lrr/d;-><init>(Lpr/a;I)V

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_3
    new-instance p0, Lrr/d;

    .line 98
    .line 99
    new-instance v0, Lio/o;

    .line 100
    .line 101
    const-string v2, "HMACSHA1"

    .line 102
    .line 103
    invoke-direct {v0, v2, v1}, Lio/o;-><init>(Ljava/lang/String;Ljavax/crypto/spec/SecretKeySpec;)V

    .line 104
    .line 105
    .line 106
    invoke-direct {p0, v0, p1}, Lrr/d;-><init>(Lpr/a;I)V

    .line 107
    .line 108
    .line 109
    :goto_1
    return-object p0

    .line 110
    :pswitch_0
    check-cast p1, Lqr/b;

    .line 111
    .line 112
    new-instance p0, Lrr/d;

    .line 113
    .line 114
    new-instance v0, Lrn/i;

    .line 115
    .line 116
    invoke-virtual {p1}, Lqr/b;->p()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {v1}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    if-nez v2, :cond_4

    .line 125
    .line 126
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/b0;->b:[B

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_4
    new-array v3, v2, [B

    .line 130
    .line 131
    invoke-virtual {v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/i;->i(I[B)V

    .line 132
    .line 133
    .line 134
    move-object v1, v3

    .line 135
    :goto_2
    invoke-direct {v0, v1}, Lrn/i;-><init>([B)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1}, Lqr/b;->q()Lqr/e;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-virtual {p1}, Lqr/e;->n()I

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    invoke-direct {p0, v0, p1}, Lrr/d;-><init>(Lpr/a;I)V

    .line 147
    .line 148
    .line 149
    return-object p0

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
