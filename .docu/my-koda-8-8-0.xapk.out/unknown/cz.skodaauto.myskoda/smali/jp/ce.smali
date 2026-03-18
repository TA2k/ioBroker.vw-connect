.class public abstract Ljp/ce;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lpx0/g;Lpx0/g;)Lpx0/g;
    .locals 2

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 7
    .line 8
    if-ne p1, v0, :cond_0

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    new-instance v0, Lpd0/a;

    .line 12
    .line 13
    const/16 v1, 0x12

    .line 14
    .line 15
    invoke-direct {v0, v1}, Lpd0/a;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-interface {p1, p0, v0}, Lpx0/g;->fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lpx0/g;

    .line 23
    .line 24
    return-object p0
.end method

.method public static b([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 2

    .line 1
    invoke-static {p0, p1, p2}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget v0, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 6
    .line 7
    if-ltz v0, :cond_2

    .line 8
    .line 9
    array-length v1, p0

    .line 10
    sub-int/2addr v1, p1

    .line 11
    if-gt v0, v1, :cond_1

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 16
    .line 17
    iput-object p0, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 18
    .line 19
    return p1

    .line 20
    :cond_0
    invoke-static {p0, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    iput-object p0, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 25
    .line 26
    add-int/2addr p1, v0

    .line 27
    return p1

    .line 28
    :cond_1
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 29
    .line 30
    const-string p1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 37
    .line 38
    const-string p1, "CodedInputStream encountered an embedded string or message which claimed to have negative size."

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public static c(I[B)I
    .locals 3

    .line 1
    aget-byte v0, p1, p0

    .line 2
    .line 3
    and-int/lit16 v0, v0, 0xff

    .line 4
    .line 5
    add-int/lit8 v1, p0, 0x1

    .line 6
    .line 7
    aget-byte v1, p1, v1

    .line 8
    .line 9
    and-int/lit16 v1, v1, 0xff

    .line 10
    .line 11
    add-int/lit8 v2, p0, 0x2

    .line 12
    .line 13
    aget-byte v2, p1, v2

    .line 14
    .line 15
    and-int/lit16 v2, v2, 0xff

    .line 16
    .line 17
    add-int/lit8 p0, p0, 0x3

    .line 18
    .line 19
    aget-byte p0, p1, p0

    .line 20
    .line 21
    and-int/lit16 p0, p0, 0xff

    .line 22
    .line 23
    shl-int/lit8 p1, v1, 0x8

    .line 24
    .line 25
    or-int/2addr p1, v0

    .line 26
    shl-int/lit8 v0, v2, 0x10

    .line 27
    .line 28
    or-int/2addr p1, v0

    .line 29
    shl-int/lit8 p0, p0, 0x18

    .line 30
    .line 31
    or-int/2addr p0, p1

    .line 32
    return p0
.end method

.method public static d(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 7

    .line 1
    invoke-interface {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, p0

    .line 6
    move-object v2, p2

    .line 7
    move v3, p3

    .line 8
    move v4, p4

    .line 9
    move-object v5, p6

    .line 10
    invoke-static/range {v0 .. v5}, Ljp/ce;->l(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-interface {v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 18
    .line 19
    invoke-interface {p5, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    :goto_0
    if-ge p0, v4, :cond_1

    .line 23
    .line 24
    move-object v6, v5

    .line 25
    move v5, v4

    .line 26
    invoke-static {v2, p0, v6}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    iget p2, v6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 31
    .line 32
    if-eq p1, p2, :cond_0

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    move-object v3, v2

    .line 36
    move-object v2, v1

    .line 37
    invoke-interface {v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->k()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-static/range {v1 .. v6}, Ljp/ce;->l(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    move-object p2, v1

    .line 46
    move-object v1, v2

    .line 47
    move-object v2, v3

    .line 48
    move v4, v5

    .line 49
    move-object v5, v6

    .line 50
    invoke-interface {v1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->b(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p2, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 54
    .line 55
    invoke-interface {p5, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    :goto_1
    return p0
.end method

.method public static e([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 2

    .line 1
    check-cast p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 2
    .line 3
    invoke-static {p0, p1, p3}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iget v0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 8
    .line 9
    add-int/2addr v0, p1

    .line 10
    :goto_0
    if-ge p1, v0, :cond_0

    .line 11
    .line 12
    invoke-static {p0, p1, p3}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    iget v1, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 17
    .line 18
    invoke-virtual {p2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    if-ne p1, v0, :cond_1

    .line 23
    .line 24
    return p1

    .line 25
    :cond_1
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 26
    .line 27
    const-string p1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public static f(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 9

    .line 1
    ushr-int/lit8 v0, p0, 0x3

    .line 2
    .line 3
    const-string v1, "Protocol message contained an invalid tag (zero)."

    .line 4
    .line 5
    if-eqz v0, :cond_c

    .line 6
    .line 7
    and-int/lit8 v0, p0, 0x7

    .line 8
    .line 9
    if-eqz v0, :cond_b

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eq v0, v2, :cond_a

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    if-eq v0, v3, :cond_6

    .line 16
    .line 17
    const/4 v3, 0x3

    .line 18
    if-eq v0, v3, :cond_1

    .line 19
    .line 20
    const/4 p3, 0x5

    .line 21
    if-ne v0, p3, :cond_0

    .line 22
    .line 23
    invoke-static {p2, p1}, Ljp/ce;->c(I[B)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p4, p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    add-int/lit8 p2, p2, 0x4

    .line 35
    .line 36
    return p2

    .line 37
    :cond_0
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 38
    .line 39
    invoke-direct {p0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    and-int/lit8 v0, p0, -0x8

    .line 44
    .line 45
    or-int/lit8 v0, v0, 0x4

    .line 46
    .line 47
    invoke-static {}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->b()Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    iget v1, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 52
    .line 53
    add-int/2addr v1, v2

    .line 54
    iput v1, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 55
    .line 56
    const/16 v2, 0x64

    .line 57
    .line 58
    if-ge v1, v2, :cond_5

    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    :goto_0
    if-ge p2, p3, :cond_2

    .line 62
    .line 63
    invoke-static {p1, p2, p5}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    iget v3, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 68
    .line 69
    if-ne v3, v0, :cond_3

    .line 70
    .line 71
    move v1, v3

    .line 72
    move p2, v5

    .line 73
    :cond_2
    move v6, p3

    .line 74
    move-object v8, p5

    .line 75
    goto :goto_1

    .line 76
    :cond_3
    move-object v4, p1

    .line 77
    move v6, p3

    .line 78
    move-object v8, p5

    .line 79
    invoke-static/range {v3 .. v8}, Ljp/ce;->f(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    move v1, v3

    .line 84
    goto :goto_0

    .line 85
    :goto_1
    iget p1, v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 86
    .line 87
    add-int/lit8 p1, p1, -0x1

    .line 88
    .line 89
    iput p1, v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 90
    .line 91
    if-gt p2, v6, :cond_4

    .line 92
    .line 93
    if-ne v1, v0, :cond_4

    .line 94
    .line 95
    invoke-virtual {p4, p0, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return p2

    .line 99
    :cond_4
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 100
    .line 101
    const-string p1, "Failed to parse the message."

    .line 102
    .line 103
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_5
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 108
    .line 109
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_6
    move-object v4, p1

    .line 116
    move-object v8, p5

    .line 117
    invoke-static {v4, p2, v8}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    iget p2, v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 122
    .line 123
    if-ltz p2, :cond_9

    .line 124
    .line 125
    array-length p3, v4

    .line 126
    sub-int/2addr p3, p1

    .line 127
    if-gt p2, p3, :cond_8

    .line 128
    .line 129
    if-nez p2, :cond_7

    .line 130
    .line 131
    sget-object p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->e:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 132
    .line 133
    invoke-virtual {p4, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_7
    invoke-static {v4, p1, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/s0;->x([BII)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/r0;

    .line 138
    .line 139
    .line 140
    move-result-object p3

    .line 141
    invoke-virtual {p4, p0, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :goto_2
    add-int/2addr p1, p2

    .line 145
    return p1

    .line 146
    :cond_8
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 147
    .line 148
    const-string p1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 149
    .line 150
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :cond_9
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 155
    .line 156
    const-string p1, "CodedInputStream encountered an embedded string or message which claimed to have negative size."

    .line 157
    .line 158
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_a
    move-object v4, p1

    .line 163
    invoke-static {p2, v4}, Ljp/ce;->n(I[B)J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-virtual {p4, p0, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    add-int/lit8 p2, p2, 0x8

    .line 175
    .line 176
    return p2

    .line 177
    :cond_b
    move-object v4, p1

    .line 178
    move-object v8, p5

    .line 179
    invoke-static {v4, p2, v8}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    iget-wide p2, v8, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 184
    .line 185
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 186
    .line 187
    .line 188
    move-result-object p2

    .line 189
    invoke-virtual {p4, p0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/q2;->c(ILjava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    return p1

    .line 193
    :cond_c
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 194
    .line 195
    invoke-direct {p0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw p0
.end method

.method public static g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 1

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    aget-byte p1, p0, p1

    .line 4
    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    iput p1, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 8
    .line 9
    return v0

    .line 10
    :cond_0
    invoke-static {p1, p0, v0, p2}, Ljp/ce;->h(I[BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public static h(I[BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 2

    .line 1
    aget-byte v0, p1, p2

    .line 2
    .line 3
    add-int/lit8 v1, p2, 0x1

    .line 4
    .line 5
    and-int/lit8 p0, p0, 0x7f

    .line 6
    .line 7
    if-ltz v0, :cond_0

    .line 8
    .line 9
    shl-int/lit8 p1, v0, 0x7

    .line 10
    .line 11
    or-int/2addr p0, p1

    .line 12
    iput p0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 13
    .line 14
    return v1

    .line 15
    :cond_0
    and-int/lit8 v0, v0, 0x7f

    .line 16
    .line 17
    shl-int/lit8 v0, v0, 0x7

    .line 18
    .line 19
    or-int/2addr p0, v0

    .line 20
    add-int/lit8 v0, p2, 0x2

    .line 21
    .line 22
    aget-byte v1, p1, v1

    .line 23
    .line 24
    if-ltz v1, :cond_1

    .line 25
    .line 26
    shl-int/lit8 p1, v1, 0xe

    .line 27
    .line 28
    or-int/2addr p0, p1

    .line 29
    iput p0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 30
    .line 31
    return v0

    .line 32
    :cond_1
    and-int/lit8 v1, v1, 0x7f

    .line 33
    .line 34
    shl-int/lit8 v1, v1, 0xe

    .line 35
    .line 36
    or-int/2addr p0, v1

    .line 37
    add-int/lit8 v1, p2, 0x3

    .line 38
    .line 39
    aget-byte v0, p1, v0

    .line 40
    .line 41
    if-ltz v0, :cond_2

    .line 42
    .line 43
    shl-int/lit8 p1, v0, 0x15

    .line 44
    .line 45
    or-int/2addr p0, p1

    .line 46
    iput p0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 47
    .line 48
    return v1

    .line 49
    :cond_2
    and-int/lit8 v0, v0, 0x7f

    .line 50
    .line 51
    shl-int/lit8 v0, v0, 0x15

    .line 52
    .line 53
    or-int/2addr p0, v0

    .line 54
    add-int/lit8 p2, p2, 0x4

    .line 55
    .line 56
    aget-byte v0, p1, v1

    .line 57
    .line 58
    if-ltz v0, :cond_3

    .line 59
    .line 60
    shl-int/lit8 p1, v0, 0x1c

    .line 61
    .line 62
    or-int/2addr p0, p1

    .line 63
    iput p0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 64
    .line 65
    return p2

    .line 66
    :cond_3
    and-int/lit8 v0, v0, 0x7f

    .line 67
    .line 68
    shl-int/lit8 v0, v0, 0x1c

    .line 69
    .line 70
    or-int/2addr p0, v0

    .line 71
    :goto_0
    add-int/lit8 v0, p2, 0x1

    .line 72
    .line 73
    aget-byte p2, p1, p2

    .line 74
    .line 75
    if-gez p2, :cond_4

    .line 76
    .line 77
    move p2, v0

    .line 78
    goto :goto_0

    .line 79
    :cond_4
    iput p0, p3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 80
    .line 81
    return v0
.end method

.method public static i(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m1;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 2

    .line 1
    check-cast p4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;

    .line 2
    .line 3
    invoke-static {p1, p2, p5}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    iget v0, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 8
    .line 9
    invoke-virtual {p4, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 10
    .line 11
    .line 12
    :goto_0
    if-ge p2, p3, :cond_1

    .line 13
    .line 14
    invoke-static {p1, p2, p5}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget v1, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 19
    .line 20
    if-eq p0, v1, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-static {p1, v0, p5}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 24
    .line 25
    .line 26
    move-result p2

    .line 27
    iget v0, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 28
    .line 29
    invoke-virtual {p4, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/h1;->g(I)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    :goto_1
    return p2
.end method

.method public static j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 9

    .line 1
    aget-byte v0, p0, p1

    .line 2
    .line 3
    int-to-long v0, v0

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v2, v0, v2

    .line 7
    .line 8
    add-int/lit8 v3, p1, 0x1

    .line 9
    .line 10
    if-ltz v2, :cond_0

    .line 11
    .line 12
    iput-wide v0, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 13
    .line 14
    return v3

    .line 15
    :cond_0
    add-int/lit8 p1, p1, 0x2

    .line 16
    .line 17
    aget-byte v2, p0, v3

    .line 18
    .line 19
    and-int/lit8 v3, v2, 0x7f

    .line 20
    .line 21
    const-wide/16 v4, 0x7f

    .line 22
    .line 23
    and-long/2addr v0, v4

    .line 24
    int-to-long v3, v3

    .line 25
    const/4 v5, 0x7

    .line 26
    shl-long/2addr v3, v5

    .line 27
    or-long/2addr v0, v3

    .line 28
    move v3, v5

    .line 29
    :goto_0
    if-gez v2, :cond_1

    .line 30
    .line 31
    add-int/lit8 v2, p1, 0x1

    .line 32
    .line 33
    aget-byte p1, p0, p1

    .line 34
    .line 35
    add-int/2addr v3, v5

    .line 36
    and-int/lit8 v4, p1, 0x7f

    .line 37
    .line 38
    int-to-long v6, v4

    .line 39
    shl-long/2addr v6, v3

    .line 40
    or-long/2addr v0, v6

    .line 41
    move v8, v2

    .line 42
    move v2, p1

    .line 43
    move p1, v8

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    iput-wide v0, p2, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->b:J

    .line 46
    .line 47
    return p1
.end method

.method public static k(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 3

    .line 1
    check-cast p1, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;

    .line 2
    .line 3
    iget v0, p6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    iput v0, p6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 8
    .line 9
    const/16 v1, 0x64

    .line 10
    .line 11
    if-ge v0, v1, :cond_0

    .line 12
    .line 13
    move-object v2, p1

    .line 14
    move-object p1, p0

    .line 15
    move-object p0, v2

    .line 16
    invoke-virtual/range {p0 .. p6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/c2;->t(Ljava/lang/Object;[BIIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    iget p2, p6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 21
    .line 22
    add-int/lit8 p2, p2, -0x1

    .line 23
    .line 24
    iput p2, p6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 25
    .line 26
    iput-object p1, p6, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 27
    .line 28
    return p0

    .line 29
    :cond_0
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 30
    .line 31
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public static l(Ljava/lang/Object;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 6

    .line 1
    add-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    aget-byte p3, p2, p3

    .line 4
    .line 5
    if-gez p3, :cond_0

    .line 6
    .line 7
    invoke-static {p3, p2, v0, p5}, Ljp/ce;->h(I[BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget p3, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 12
    .line 13
    :cond_0
    move v3, v0

    .line 14
    if-ltz p3, :cond_2

    .line 15
    .line 16
    sub-int/2addr p4, v3

    .line 17
    if-gt p3, p4, :cond_2

    .line 18
    .line 19
    iget p4, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 20
    .line 21
    add-int/lit8 p4, p4, 0x1

    .line 22
    .line 23
    iput p4, p5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 24
    .line 25
    const/16 v0, 0x64

    .line 26
    .line 27
    if-ge p4, v0, :cond_1

    .line 28
    .line 29
    add-int v4, v3, p3

    .line 30
    .line 31
    move-object v1, p0

    .line 32
    move-object v0, p1

    .line 33
    move-object v2, p2

    .line 34
    move-object v5, p5

    .line 35
    invoke-interface/range {v0 .. v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l2;->f(Ljava/lang/Object;[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)V

    .line 36
    .line 37
    .line 38
    iget p0, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 39
    .line 40
    add-int/lit8 p0, p0, -0x1

    .line 41
    .line 42
    iput p0, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->e:I

    .line 43
    .line 44
    iput-object v1, v5, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->c:Ljava/lang/Object;

    .line 45
    .line 46
    return v4

    .line 47
    :cond_1
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 48
    .line 49
    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 56
    .line 57
    const-string p1, "While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length."

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public static m(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I
    .locals 3

    .line 1
    ushr-int/lit8 v0, p0, 0x3

    .line 2
    .line 3
    const-string v1, "Protocol message contained an invalid tag (zero)."

    .line 4
    .line 5
    if-eqz v0, :cond_7

    .line 6
    .line 7
    and-int/lit8 v0, p0, 0x7

    .line 8
    .line 9
    if-eqz v0, :cond_6

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eq v0, v2, :cond_5

    .line 13
    .line 14
    const/4 v2, 0x2

    .line 15
    if-eq v0, v2, :cond_4

    .line 16
    .line 17
    const/4 v2, 0x3

    .line 18
    if-eq v0, v2, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x5

    .line 21
    if-ne v0, p0, :cond_0

    .line 22
    .line 23
    add-int/lit8 p2, p2, 0x4

    .line 24
    .line 25
    return p2

    .line 26
    :cond_0
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 27
    .line 28
    invoke-direct {p0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    and-int/lit8 p0, p0, -0x8

    .line 33
    .line 34
    or-int/lit8 p0, p0, 0x4

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    :goto_0
    if-ge p2, p3, :cond_2

    .line 38
    .line 39
    invoke-static {p1, p2, p4}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    iget v0, p4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 44
    .line 45
    if-eq v0, p0, :cond_2

    .line 46
    .line 47
    invoke-static {v0, p1, p2, p3, p4}, Ljp/ce;->m(I[BIILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    if-gt p2, p3, :cond_3

    .line 53
    .line 54
    if-ne v0, p0, :cond_3

    .line 55
    .line 56
    return p2

    .line 57
    :cond_3
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 58
    .line 59
    const-string p1, "Failed to parse the message."

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_4
    invoke-static {p1, p2, p4}, Ljp/ce;->g([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    iget p1, p4, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;->a:I

    .line 70
    .line 71
    add-int/2addr p0, p1

    .line 72
    return p0

    .line 73
    :cond_5
    add-int/lit8 p2, p2, 0x8

    .line 74
    .line 75
    return p2

    .line 76
    :cond_6
    invoke-static {p1, p2, p4}, Ljp/ce;->j([BILcom/google/android/gms/internal/mlkit_vision_barcode_bundled/m0;)I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    return p0

    .line 81
    :cond_7
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/p1;

    .line 82
    .line 83
    invoke-direct {p0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0
.end method

.method public static n(I[B)J
    .locals 18

    .line 1
    aget-byte v0, p1, p0

    .line 2
    .line 3
    int-to-long v0, v0

    .line 4
    add-int/lit8 v2, p0, 0x1

    .line 5
    .line 6
    aget-byte v2, p1, v2

    .line 7
    .line 8
    int-to-long v2, v2

    .line 9
    add-int/lit8 v4, p0, 0x2

    .line 10
    .line 11
    aget-byte v4, p1, v4

    .line 12
    .line 13
    int-to-long v4, v4

    .line 14
    add-int/lit8 v6, p0, 0x3

    .line 15
    .line 16
    aget-byte v6, p1, v6

    .line 17
    .line 18
    int-to-long v6, v6

    .line 19
    add-int/lit8 v8, p0, 0x4

    .line 20
    .line 21
    aget-byte v8, p1, v8

    .line 22
    .line 23
    int-to-long v8, v8

    .line 24
    add-int/lit8 v10, p0, 0x5

    .line 25
    .line 26
    aget-byte v10, p1, v10

    .line 27
    .line 28
    int-to-long v10, v10

    .line 29
    add-int/lit8 v12, p0, 0x6

    .line 30
    .line 31
    aget-byte v12, p1, v12

    .line 32
    .line 33
    int-to-long v12, v12

    .line 34
    add-int/lit8 v14, p0, 0x7

    .line 35
    .line 36
    aget-byte v14, p1, v14

    .line 37
    .line 38
    int-to-long v14, v14

    .line 39
    const-wide/16 v16, 0xff

    .line 40
    .line 41
    and-long v2, v2, v16

    .line 42
    .line 43
    and-long v4, v4, v16

    .line 44
    .line 45
    and-long v6, v6, v16

    .line 46
    .line 47
    and-long v8, v8, v16

    .line 48
    .line 49
    and-long v10, v10, v16

    .line 50
    .line 51
    and-long v12, v12, v16

    .line 52
    .line 53
    and-long v14, v14, v16

    .line 54
    .line 55
    and-long v0, v0, v16

    .line 56
    .line 57
    const/16 v16, 0x8

    .line 58
    .line 59
    shl-long v2, v2, v16

    .line 60
    .line 61
    or-long/2addr v0, v2

    .line 62
    const/16 v2, 0x10

    .line 63
    .line 64
    shl-long v2, v4, v2

    .line 65
    .line 66
    or-long/2addr v0, v2

    .line 67
    const/16 v2, 0x18

    .line 68
    .line 69
    shl-long v2, v6, v2

    .line 70
    .line 71
    or-long/2addr v0, v2

    .line 72
    const/16 v2, 0x20

    .line 73
    .line 74
    shl-long v2, v8, v2

    .line 75
    .line 76
    or-long/2addr v0, v2

    .line 77
    const/16 v2, 0x28

    .line 78
    .line 79
    shl-long v2, v10, v2

    .line 80
    .line 81
    or-long/2addr v0, v2

    .line 82
    const/16 v2, 0x30

    .line 83
    .line 84
    shl-long v2, v12, v2

    .line 85
    .line 86
    or-long/2addr v0, v2

    .line 87
    const/16 v2, 0x38

    .line 88
    .line 89
    shl-long v2, v14, v2

    .line 90
    .line 91
    or-long/2addr v0, v2

    .line 92
    return-wide v0
.end method
