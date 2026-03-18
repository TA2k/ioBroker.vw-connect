.class public final Lec0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lac0/z;


# instance fields
.field public final a:Lzo0/o;


# direct methods
.method public constructor <init>(Lzo0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lec0/d;->a:Lzo0/o;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lec0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lec0/c;

    .line 7
    .line 8
    iget v1, v0, Lec0/c;->f:I

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
    iput v1, v0, Lec0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lec0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lec0/c;-><init>(Lec0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lec0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lec0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lec0/c;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lec0/d;->a:Lzo0/o;

    .line 61
    .line 62
    check-cast p0, Lxo0/a;

    .line 63
    .line 64
    invoke-virtual {p0}, Lxo0/a;->a()Lyy0/h2;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lyy0/i;

    .line 72
    .line 73
    iput v3, v0, Lec0/c;->f:I

    .line 74
    .line 75
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    if-ne p1, v1, :cond_5

    .line 80
    .line 81
    :goto_2
    return-object v1

    .line 82
    :cond_5
    :goto_3
    check-cast p1, Ljava/lang/String;

    .line 83
    .line 84
    if-eqz p1, :cond_6

    .line 85
    .line 86
    sget-object p0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 87
    .line 88
    const-string v0, "UTF_8"

    .line 89
    .line 90
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1, p0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const-string p1, "getBytes(...)"

    .line 98
    .line 99
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const-string p1, "SHA-256"

    .line 103
    .line 104
    invoke-static {p1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-virtual {p1, p0}, Ljava/security/MessageDigest;->digest([B)[B

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    const-string p1, "digest(...)"

    .line 113
    .line 114
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-virtual {p1}, Ljava/time/Instant;->getEpochSecond()J

    .line 122
    .line 123
    .line 124
    move-result-wide v0

    .line 125
    const-wide/16 v2, 0x1e

    .line 126
    .line 127
    div-long/2addr v0, v2

    .line 128
    const/16 p1, 0x8

    .line 129
    .line 130
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-virtual {v2, v0, v1}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;

    .line 143
    .line 144
    const-string v2, "HmacSHA256"

    .line 145
    .line 146
    invoke-direct {v1, p0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-static {v2}, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-virtual {p0, v1}, Ljavax/crypto/Mac;->init(Ljava/security/Key;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {p0, v0}, Ljavax/crypto/Mac;->doFinal([B)[B

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    array-length v0, p0

    .line 161
    sub-int/2addr v0, v4

    .line 162
    aget-byte v0, p0, v0

    .line 163
    .line 164
    and-int/lit8 v0, v0, 0xf

    .line 165
    .line 166
    aget-byte v1, p0, v0

    .line 167
    .line 168
    and-int/lit8 v1, v1, 0x7f

    .line 169
    .line 170
    shl-int/lit8 v1, v1, 0x18

    .line 171
    .line 172
    add-int/lit8 v2, v0, 0x1

    .line 173
    .line 174
    aget-byte v2, p0, v2

    .line 175
    .line 176
    and-int/lit16 v2, v2, 0xff

    .line 177
    .line 178
    shl-int/lit8 v2, v2, 0x10

    .line 179
    .line 180
    or-int/2addr v1, v2

    .line 181
    add-int/lit8 v2, v0, 0x2

    .line 182
    .line 183
    aget-byte v2, p0, v2

    .line 184
    .line 185
    and-int/lit16 v2, v2, 0xff

    .line 186
    .line 187
    shl-int/lit8 p1, v2, 0x8

    .line 188
    .line 189
    or-int/2addr p1, v1

    .line 190
    add-int/lit8 v0, v0, 0x3

    .line 191
    .line 192
    aget-byte p0, p0, v0

    .line 193
    .line 194
    and-int/lit16 p0, p0, 0xff

    .line 195
    .line 196
    or-int/2addr p0, p1

    .line 197
    const-wide/high16 v0, 0x4024000000000000L    # 10.0

    .line 198
    .line 199
    const/4 p1, 0x6

    .line 200
    int-to-double v2, p1

    .line 201
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 202
    .line 203
    .line 204
    move-result-wide v0

    .line 205
    double-to-int v0, v0

    .line 206
    rem-int/2addr p0, v0

    .line 207
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object p0

    .line 211
    invoke-static {p1, p0}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    return-object p0

    .line 216
    :cond_6
    const/4 p0, 0x0

    .line 217
    return-object p0
.end method
