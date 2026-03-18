.class public final Lc8/d0;
.super Lu7/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/high16 v0, 0x7fc00000    # Float.NaN

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sput v0, Lc8/d0;->i:I

    .line 8
    .line 9
    return-void
.end method

.method public static l(ILjava/nio/ByteBuffer;)V
    .locals 4

    .line 1
    const-wide v0, 0x3e00000000200000L    # 4.656612875245797E-10

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    int-to-double v2, p0

    .line 7
    mul-double/2addr v2, v0

    .line 8
    double-to-float p0, v2

    .line 9
    invoke-static {p0}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    sget v0, Lc8/d0;->i:I

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    invoke-static {p0}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    :cond_0
    invoke-virtual {p1, p0}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final d(Ljava/nio/ByteBuffer;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/nio/Buffer;->position()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Ljava/nio/Buffer;->limit()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    sub-int v2, v1, v0

    .line 10
    .line 11
    iget-object v3, p0, Lu7/g;->b:Lu7/d;

    .line 12
    .line 13
    iget v3, v3, Lu7/d;->c:I

    .line 14
    .line 15
    const/16 v4, 0x15

    .line 16
    .line 17
    if-eq v3, v4, :cond_3

    .line 18
    .line 19
    const/16 v4, 0x16

    .line 20
    .line 21
    if-eq v3, v4, :cond_2

    .line 22
    .line 23
    const/high16 v4, 0x50000000

    .line 24
    .line 25
    if-eq v3, v4, :cond_1

    .line 26
    .line 27
    const/high16 v4, 0x60000000

    .line 28
    .line 29
    if-ne v3, v4, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0, v2}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    if-ge v0, v1, :cond_4

    .line 36
    .line 37
    add-int/lit8 v2, v0, 0x3

    .line 38
    .line 39
    invoke-virtual {p1, v2}, Ljava/nio/ByteBuffer;->get(I)B

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    and-int/lit16 v2, v2, 0xff

    .line 44
    .line 45
    add-int/lit8 v3, v0, 0x2

    .line 46
    .line 47
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    and-int/lit16 v3, v3, 0xff

    .line 52
    .line 53
    shl-int/lit8 v3, v3, 0x8

    .line 54
    .line 55
    or-int/2addr v2, v3

    .line 56
    add-int/lit8 v3, v0, 0x1

    .line 57
    .line 58
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    and-int/lit16 v3, v3, 0xff

    .line 63
    .line 64
    shl-int/lit8 v3, v3, 0x10

    .line 65
    .line 66
    or-int/2addr v2, v3

    .line 67
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->get(I)B

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    and-int/lit16 v3, v3, 0xff

    .line 72
    .line 73
    shl-int/lit8 v3, v3, 0x18

    .line 74
    .line 75
    or-int/2addr v2, v3

    .line 76
    invoke-static {v2, p0}, Lc8/d0;->l(ILjava/nio/ByteBuffer;)V

    .line 77
    .line 78
    .line 79
    add-int/lit8 v0, v0, 0x4

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_1
    div-int/lit8 v2, v2, 0x3

    .line 89
    .line 90
    mul-int/lit8 v2, v2, 0x4

    .line 91
    .line 92
    invoke-virtual {p0, v2}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    :goto_1
    if-ge v0, v1, :cond_4

    .line 97
    .line 98
    add-int/lit8 v2, v0, 0x2

    .line 99
    .line 100
    invoke-virtual {p1, v2}, Ljava/nio/ByteBuffer;->get(I)B

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    and-int/lit16 v2, v2, 0xff

    .line 105
    .line 106
    shl-int/lit8 v2, v2, 0x8

    .line 107
    .line 108
    add-int/lit8 v3, v0, 0x1

    .line 109
    .line 110
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    and-int/lit16 v3, v3, 0xff

    .line 115
    .line 116
    shl-int/lit8 v3, v3, 0x10

    .line 117
    .line 118
    or-int/2addr v2, v3

    .line 119
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->get(I)B

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    and-int/lit16 v3, v3, 0xff

    .line 124
    .line 125
    shl-int/lit8 v3, v3, 0x18

    .line 126
    .line 127
    or-int/2addr v2, v3

    .line 128
    invoke-static {v2, p0}, Lc8/d0;->l(ILjava/nio/ByteBuffer;)V

    .line 129
    .line 130
    .line 131
    add-int/lit8 v0, v0, 0x3

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_2
    invoke-virtual {p0, v2}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    :goto_2
    if-ge v0, v1, :cond_4

    .line 139
    .line 140
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->get(I)B

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    and-int/lit16 v2, v2, 0xff

    .line 145
    .line 146
    add-int/lit8 v3, v0, 0x1

    .line 147
    .line 148
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    and-int/lit16 v3, v3, 0xff

    .line 153
    .line 154
    shl-int/lit8 v3, v3, 0x8

    .line 155
    .line 156
    or-int/2addr v2, v3

    .line 157
    add-int/lit8 v3, v0, 0x2

    .line 158
    .line 159
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    and-int/lit16 v3, v3, 0xff

    .line 164
    .line 165
    shl-int/lit8 v3, v3, 0x10

    .line 166
    .line 167
    or-int/2addr v2, v3

    .line 168
    add-int/lit8 v3, v0, 0x3

    .line 169
    .line 170
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 171
    .line 172
    .line 173
    move-result v3

    .line 174
    and-int/lit16 v3, v3, 0xff

    .line 175
    .line 176
    shl-int/lit8 v3, v3, 0x18

    .line 177
    .line 178
    or-int/2addr v2, v3

    .line 179
    invoke-static {v2, p0}, Lc8/d0;->l(ILjava/nio/ByteBuffer;)V

    .line 180
    .line 181
    .line 182
    add-int/lit8 v0, v0, 0x4

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_3
    div-int/lit8 v2, v2, 0x3

    .line 186
    .line 187
    mul-int/lit8 v2, v2, 0x4

    .line 188
    .line 189
    invoke-virtual {p0, v2}, Lu7/g;->k(I)Ljava/nio/ByteBuffer;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    :goto_3
    if-ge v0, v1, :cond_4

    .line 194
    .line 195
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->get(I)B

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    and-int/lit16 v2, v2, 0xff

    .line 200
    .line 201
    shl-int/lit8 v2, v2, 0x8

    .line 202
    .line 203
    add-int/lit8 v3, v0, 0x1

    .line 204
    .line 205
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 206
    .line 207
    .line 208
    move-result v3

    .line 209
    and-int/lit16 v3, v3, 0xff

    .line 210
    .line 211
    shl-int/lit8 v3, v3, 0x10

    .line 212
    .line 213
    or-int/2addr v2, v3

    .line 214
    add-int/lit8 v3, v0, 0x2

    .line 215
    .line 216
    invoke-virtual {p1, v3}, Ljava/nio/ByteBuffer;->get(I)B

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    and-int/lit16 v3, v3, 0xff

    .line 221
    .line 222
    shl-int/lit8 v3, v3, 0x18

    .line 223
    .line 224
    or-int/2addr v2, v3

    .line 225
    invoke-static {v2, p0}, Lc8/d0;->l(ILjava/nio/ByteBuffer;)V

    .line 226
    .line 227
    .line 228
    add-int/lit8 v0, v0, 0x3

    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_4
    invoke-virtual {p1}, Ljava/nio/Buffer;->limit()I

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 236
    .line 237
    .line 238
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 239
    .line 240
    .line 241
    return-void
.end method

.method public final g(Lu7/d;)Lu7/d;
    .locals 2

    .line 1
    iget p0, p1, Lu7/d;->c:I

    .line 2
    .line 3
    const/16 v0, 0x15

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    if-eq p0, v0, :cond_1

    .line 7
    .line 8
    const/high16 v0, 0x50000000

    .line 9
    .line 10
    if-eq p0, v0, :cond_1

    .line 11
    .line 12
    const/16 v0, 0x16

    .line 13
    .line 14
    if-eq p0, v0, :cond_1

    .line 15
    .line 16
    const/high16 v0, 0x60000000

    .line 17
    .line 18
    if-eq p0, v0, :cond_1

    .line 19
    .line 20
    if-ne p0, v1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Lu7/e;

    .line 24
    .line 25
    invoke-direct {p0, p1}, Lu7/e;-><init>(Lu7/d;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    :goto_0
    if-eq p0, v1, :cond_2

    .line 30
    .line 31
    new-instance p0, Lu7/d;

    .line 32
    .line 33
    iget v0, p1, Lu7/d;->a:I

    .line 34
    .line 35
    iget p1, p1, Lu7/d;->b:I

    .line 36
    .line 37
    invoke-direct {p0, v0, p1, v1}, Lu7/d;-><init>(III)V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_2
    sget-object p0, Lu7/d;->e:Lu7/d;

    .line 42
    .line 43
    return-object p0
.end method
