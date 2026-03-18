.class public final Landroidx/collection/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[J

.field public b:[Ljava/lang/Object;

.field public c:I

.field public d:I

.field public e:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x6

    .line 7
    invoke-direct {p0, v0}, Landroidx/collection/r0;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Landroidx/collection/y0;->a:[J

    iput-object v0, p0, Landroidx/collection/r0;->a:[J

    .line 3
    sget-object v0, La1/a;->c:[Ljava/lang/Object;

    iput-object v0, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    if-ltz p1, :cond_0

    .line 4
    invoke-static {p1}, Landroidx/collection/y0;->d(I)I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/collection/r0;->f(I)V

    return-void

    .line 5
    :cond_0
    const-string p0, "Capacity must be a positive value."

    .line 6
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/r0;->d:I

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/collection/r0;->d(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object v2, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 8
    .line 9
    aput-object p1, v2, v1

    .line 10
    .line 11
    iget p0, p0, Landroidx/collection/r0;->d:I

    .line 12
    .line 13
    if-eq p0, v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final b()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Landroidx/collection/r0;->d:I

    .line 3
    .line 4
    iget-object v1, p0, Landroidx/collection/r0;->a:[J

    .line 5
    .line 6
    sget-object v2, Landroidx/collection/y0;->a:[J

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    const-wide v2, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v2, v3, v1}, Lmx0/n;->r(J[J)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Landroidx/collection/r0;->a:[J

    .line 19
    .line 20
    iget v2, p0, Landroidx/collection/r0;->c:I

    .line 21
    .line 22
    shr-int/lit8 v3, v2, 0x3

    .line 23
    .line 24
    and-int/lit8 v2, v2, 0x7

    .line 25
    .line 26
    shl-int/lit8 v2, v2, 0x3

    .line 27
    .line 28
    aget-wide v4, v1, v3

    .line 29
    .line 30
    const-wide/16 v6, 0xff

    .line 31
    .line 32
    shl-long/2addr v6, v2

    .line 33
    not-long v8, v6

    .line 34
    and-long/2addr v4, v8

    .line 35
    or-long/2addr v4, v6

    .line 36
    aput-wide v4, v1, v3

    .line 37
    .line 38
    :cond_0
    iget-object v1, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    iget v3, p0, Landroidx/collection/r0;->c:I

    .line 42
    .line 43
    invoke-static {v0, v3, v2, v1}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget v0, p0, Landroidx/collection/r0;->c:I

    .line 47
    .line 48
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v1, p0, Landroidx/collection/r0;->d:I

    .line 53
    .line 54
    sub-int/2addr v0, v1

    .line 55
    iput v0, p0, Landroidx/collection/r0;->e:I

    .line 56
    .line 57
    return-void
.end method

.method public final c(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v3, v2

    .line 14
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 15
    .line 16
    .line 17
    mul-int/2addr v3, v4

    .line 18
    shl-int/lit8 v4, v3, 0x10

    .line 19
    .line 20
    xor-int/2addr v3, v4

    .line 21
    and-int/lit8 v4, v3, 0x7f

    .line 22
    .line 23
    iget v5, v0, Landroidx/collection/r0;->c:I

    .line 24
    .line 25
    ushr-int/lit8 v3, v3, 0x7

    .line 26
    .line 27
    and-int/2addr v3, v5

    .line 28
    move v6, v2

    .line 29
    :goto_1
    iget-object v7, v0, Landroidx/collection/r0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v8, v3, 0x3

    .line 32
    .line 33
    and-int/lit8 v9, v3, 0x7

    .line 34
    .line 35
    shl-int/lit8 v9, v9, 0x3

    .line 36
    .line 37
    aget-wide v10, v7, v8

    .line 38
    .line 39
    ushr-long/2addr v10, v9

    .line 40
    const/4 v12, 0x1

    .line 41
    add-int/2addr v8, v12

    .line 42
    aget-wide v7, v7, v8

    .line 43
    .line 44
    rsub-int/lit8 v13, v9, 0x40

    .line 45
    .line 46
    shl-long/2addr v7, v13

    .line 47
    int-to-long v13, v9

    .line 48
    neg-long v13, v13

    .line 49
    const/16 v9, 0x3f

    .line 50
    .line 51
    shr-long/2addr v13, v9

    .line 52
    and-long/2addr v7, v13

    .line 53
    or-long/2addr v7, v10

    .line 54
    int-to-long v9, v4

    .line 55
    const-wide v13, 0x101010101010101L

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    mul-long/2addr v9, v13

    .line 61
    xor-long/2addr v9, v7

    .line 62
    sub-long v13, v9, v13

    .line 63
    .line 64
    not-long v9, v9

    .line 65
    and-long/2addr v9, v13

    .line 66
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    and-long/2addr v9, v13

    .line 72
    :goto_2
    const-wide/16 v15, 0x0

    .line 73
    .line 74
    cmp-long v11, v9, v15

    .line 75
    .line 76
    if-eqz v11, :cond_2

    .line 77
    .line 78
    invoke-static {v9, v10}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    shr-int/lit8 v11, v11, 0x3

    .line 83
    .line 84
    add-int/2addr v11, v3

    .line 85
    and-int/2addr v11, v5

    .line 86
    iget-object v15, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 87
    .line 88
    aget-object v15, v15, v11

    .line 89
    .line 90
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v15

    .line 94
    if-eqz v15, :cond_1

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_1
    const-wide/16 v15, 0x1

    .line 98
    .line 99
    sub-long v15, v9, v15

    .line 100
    .line 101
    and-long/2addr v9, v15

    .line 102
    goto :goto_2

    .line 103
    :cond_2
    not-long v9, v7

    .line 104
    const/4 v11, 0x6

    .line 105
    shl-long/2addr v9, v11

    .line 106
    and-long/2addr v7, v9

    .line 107
    and-long/2addr v7, v13

    .line 108
    cmp-long v7, v7, v15

    .line 109
    .line 110
    if-eqz v7, :cond_4

    .line 111
    .line 112
    const/4 v11, -0x1

    .line 113
    :goto_3
    if-ltz v11, :cond_3

    .line 114
    .line 115
    return v12

    .line 116
    :cond_3
    return v2

    .line 117
    :cond_4
    add-int/lit8 v6, v6, 0x8

    .line 118
    .line 119
    add-int/2addr v3, v6

    .line 120
    and-int/2addr v3, v5

    .line 121
    goto :goto_1
.end method

.method public final d(Ljava/lang/Object;)I
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v3, 0x0

    .line 13
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 14
    .line 15
    .line 16
    mul-int/2addr v3, v4

    .line 17
    shl-int/lit8 v5, v3, 0x10

    .line 18
    .line 19
    xor-int/2addr v3, v5

    .line 20
    ushr-int/lit8 v5, v3, 0x7

    .line 21
    .line 22
    and-int/lit8 v3, v3, 0x7f

    .line 23
    .line 24
    iget v6, v0, Landroidx/collection/r0;->c:I

    .line 25
    .line 26
    and-int v7, v5, v6

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    :goto_1
    iget-object v9, v0, Landroidx/collection/r0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v10, v7, 0x3

    .line 32
    .line 33
    and-int/lit8 v11, v7, 0x7

    .line 34
    .line 35
    shl-int/lit8 v11, v11, 0x3

    .line 36
    .line 37
    aget-wide v12, v9, v10

    .line 38
    .line 39
    ushr-long/2addr v12, v11

    .line 40
    const/4 v14, 0x1

    .line 41
    add-int/2addr v10, v14

    .line 42
    aget-wide v9, v9, v10

    .line 43
    .line 44
    rsub-int/lit8 v15, v11, 0x40

    .line 45
    .line 46
    shl-long/2addr v9, v15

    .line 47
    move/from16 v16, v14

    .line 48
    .line 49
    int-to-long v14, v11

    .line 50
    neg-long v14, v14

    .line 51
    const/16 v11, 0x3f

    .line 52
    .line 53
    shr-long/2addr v14, v11

    .line 54
    and-long/2addr v9, v14

    .line 55
    or-long/2addr v9, v12

    .line 56
    int-to-long v11, v3

    .line 57
    const-wide v13, 0x101010101010101L

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    mul-long v17, v11, v13

    .line 63
    .line 64
    move/from16 v19, v3

    .line 65
    .line 66
    const/4 v15, 0x0

    .line 67
    xor-long v2, v9, v17

    .line 68
    .line 69
    sub-long v13, v2, v13

    .line 70
    .line 71
    not-long v2, v2

    .line 72
    and-long/2addr v2, v13

    .line 73
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    and-long/2addr v2, v13

    .line 79
    :goto_2
    const-wide/16 v17, 0x0

    .line 80
    .line 81
    cmp-long v20, v2, v17

    .line 82
    .line 83
    if-eqz v20, :cond_2

    .line 84
    .line 85
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 86
    .line 87
    .line 88
    move-result v17

    .line 89
    shr-int/lit8 v17, v17, 0x3

    .line 90
    .line 91
    add-int v17, v7, v17

    .line 92
    .line 93
    and-int v17, v17, v6

    .line 94
    .line 95
    move/from16 v20, v4

    .line 96
    .line 97
    iget-object v4, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 98
    .line 99
    aget-object v4, v4, v17

    .line 100
    .line 101
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-eqz v4, :cond_1

    .line 106
    .line 107
    return v17

    .line 108
    :cond_1
    const-wide/16 v17, 0x1

    .line 109
    .line 110
    sub-long v17, v2, v17

    .line 111
    .line 112
    and-long v2, v2, v17

    .line 113
    .line 114
    move/from16 v4, v20

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    move/from16 v20, v4

    .line 118
    .line 119
    not-long v2, v9

    .line 120
    const/4 v4, 0x6

    .line 121
    shl-long/2addr v2, v4

    .line 122
    and-long/2addr v2, v9

    .line 123
    and-long/2addr v2, v13

    .line 124
    cmp-long v2, v2, v17

    .line 125
    .line 126
    const/16 v3, 0x8

    .line 127
    .line 128
    if-eqz v2, :cond_12

    .line 129
    .line 130
    invoke-virtual {v0, v5}, Landroidx/collection/r0;->e(I)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    iget v2, v0, Landroidx/collection/r0;->e:I

    .line 135
    .line 136
    const-wide/16 v8, 0xff

    .line 137
    .line 138
    if-nez v2, :cond_3

    .line 139
    .line 140
    iget-object v2, v0, Landroidx/collection/r0;->a:[J

    .line 141
    .line 142
    shr-int/lit8 v10, v1, 0x3

    .line 143
    .line 144
    aget-wide v17, v2, v10

    .line 145
    .line 146
    and-int/lit8 v2, v1, 0x7

    .line 147
    .line 148
    shl-int/lit8 v2, v2, 0x3

    .line 149
    .line 150
    shr-long v17, v17, v2

    .line 151
    .line 152
    and-long v17, v17, v8

    .line 153
    .line 154
    const-wide/16 v21, 0xfe

    .line 155
    .line 156
    cmp-long v2, v17, v21

    .line 157
    .line 158
    if-nez v2, :cond_4

    .line 159
    .line 160
    :cond_3
    move-wide/from16 v25, v8

    .line 161
    .line 162
    move-wide/from16 v23, v11

    .line 163
    .line 164
    const/16 p1, 0x7

    .line 165
    .line 166
    const-wide/16 v17, 0x80

    .line 167
    .line 168
    goto/16 :goto_e

    .line 169
    .line 170
    :cond_4
    iget v1, v0, Landroidx/collection/r0;->c:I

    .line 171
    .line 172
    if-le v1, v3, :cond_d

    .line 173
    .line 174
    iget v2, v0, Landroidx/collection/r0;->d:I

    .line 175
    .line 176
    move v10, v3

    .line 177
    const/16 p1, 0x7

    .line 178
    .line 179
    int-to-long v3, v2

    .line 180
    const-wide/16 v17, 0x20

    .line 181
    .line 182
    mul-long v3, v3, v17

    .line 183
    .line 184
    int-to-long v1, v1

    .line 185
    const-wide/16 v17, 0x19

    .line 186
    .line 187
    mul-long v1, v1, v17

    .line 188
    .line 189
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-gtz v1, :cond_c

    .line 194
    .line 195
    iget-object v1, v0, Landroidx/collection/r0;->a:[J

    .line 196
    .line 197
    iget v2, v0, Landroidx/collection/r0;->c:I

    .line 198
    .line 199
    iget-object v3, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 200
    .line 201
    add-int/lit8 v4, v2, 0x7

    .line 202
    .line 203
    shr-int/lit8 v4, v4, 0x3

    .line 204
    .line 205
    move v6, v15

    .line 206
    const-wide/16 v17, 0x80

    .line 207
    .line 208
    :goto_3
    if-ge v6, v4, :cond_5

    .line 209
    .line 210
    aget-wide v23, v1, v6

    .line 211
    .line 212
    move-wide/from16 v25, v8

    .line 213
    .line 214
    and-long v8, v23, v13

    .line 215
    .line 216
    move-wide/from16 v23, v11

    .line 217
    .line 218
    move v12, v10

    .line 219
    not-long v10, v8

    .line 220
    ushr-long v7, v8, p1

    .line 221
    .line 222
    add-long/2addr v10, v7

    .line 223
    const-wide v7, -0x101010101010102L

    .line 224
    .line 225
    .line 226
    .line 227
    .line 228
    and-long/2addr v7, v10

    .line 229
    aput-wide v7, v1, v6

    .line 230
    .line 231
    add-int/lit8 v6, v6, 0x1

    .line 232
    .line 233
    move v10, v12

    .line 234
    move-wide/from16 v11, v23

    .line 235
    .line 236
    move-wide/from16 v8, v25

    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_5
    move-wide/from16 v25, v8

    .line 240
    .line 241
    move-wide/from16 v23, v11

    .line 242
    .line 243
    move v12, v10

    .line 244
    invoke-static {v1}, Lmx0/n;->A([J)I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    add-int/lit8 v6, v4, -0x1

    .line 249
    .line 250
    aget-wide v7, v1, v6

    .line 251
    .line 252
    const-wide v9, 0xffffffffffffffL

    .line 253
    .line 254
    .line 255
    .line 256
    .line 257
    and-long/2addr v7, v9

    .line 258
    const-wide/high16 v13, -0x100000000000000L

    .line 259
    .line 260
    or-long/2addr v7, v13

    .line 261
    aput-wide v7, v1, v6

    .line 262
    .line 263
    aget-wide v6, v1, v15

    .line 264
    .line 265
    aput-wide v6, v1, v4

    .line 266
    .line 267
    move v4, v15

    .line 268
    :goto_4
    if-eq v4, v2, :cond_b

    .line 269
    .line 270
    shr-int/lit8 v6, v4, 0x3

    .line 271
    .line 272
    aget-wide v7, v1, v6

    .line 273
    .line 274
    and-int/lit8 v11, v4, 0x7

    .line 275
    .line 276
    shl-int/lit8 v11, v11, 0x3

    .line 277
    .line 278
    shr-long/2addr v7, v11

    .line 279
    and-long v7, v7, v25

    .line 280
    .line 281
    cmp-long v13, v7, v17

    .line 282
    .line 283
    if-nez v13, :cond_6

    .line 284
    .line 285
    :goto_5
    add-int/lit8 v4, v4, 0x1

    .line 286
    .line 287
    goto :goto_4

    .line 288
    :cond_6
    cmp-long v7, v7, v21

    .line 289
    .line 290
    if-eqz v7, :cond_7

    .line 291
    .line 292
    goto :goto_5

    .line 293
    :cond_7
    aget-object v7, v3, v4

    .line 294
    .line 295
    if-eqz v7, :cond_8

    .line 296
    .line 297
    invoke-virtual {v7}, Ljava/lang/Object;->hashCode()I

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    goto :goto_6

    .line 302
    :cond_8
    move v7, v15

    .line 303
    :goto_6
    mul-int v7, v7, v20

    .line 304
    .line 305
    shl-int/lit8 v8, v7, 0x10

    .line 306
    .line 307
    xor-int/2addr v7, v8

    .line 308
    ushr-int/lit8 v8, v7, 0x7

    .line 309
    .line 310
    invoke-virtual {v0, v8}, Landroidx/collection/r0;->e(I)I

    .line 311
    .line 312
    .line 313
    move-result v13

    .line 314
    and-int/2addr v8, v2

    .line 315
    sub-int v14, v13, v8

    .line 316
    .line 317
    and-int/2addr v14, v2

    .line 318
    div-int/2addr v14, v12

    .line 319
    sub-int v8, v4, v8

    .line 320
    .line 321
    and-int/2addr v8, v2

    .line 322
    div-int/2addr v8, v12

    .line 323
    const-wide/high16 v27, -0x8000000000000000L

    .line 324
    .line 325
    if-ne v14, v8, :cond_9

    .line 326
    .line 327
    and-int/lit8 v7, v7, 0x7f

    .line 328
    .line 329
    int-to-long v7, v7

    .line 330
    aget-wide v13, v1, v6

    .line 331
    .line 332
    move-wide/from16 v29, v9

    .line 333
    .line 334
    shl-long v9, v25, v11

    .line 335
    .line 336
    not-long v9, v9

    .line 337
    and-long/2addr v9, v13

    .line 338
    shl-long/2addr v7, v11

    .line 339
    or-long/2addr v7, v9

    .line 340
    aput-wide v7, v1, v6

    .line 341
    .line 342
    array-length v6, v1

    .line 343
    add-int/lit8 v6, v6, -0x1

    .line 344
    .line 345
    aget-wide v7, v1, v15

    .line 346
    .line 347
    and-long v7, v7, v29

    .line 348
    .line 349
    or-long v7, v7, v27

    .line 350
    .line 351
    aput-wide v7, v1, v6

    .line 352
    .line 353
    add-int/lit8 v4, v4, 0x1

    .line 354
    .line 355
    move-wide/from16 v9, v29

    .line 356
    .line 357
    goto :goto_4

    .line 358
    :cond_9
    move-wide/from16 v29, v9

    .line 359
    .line 360
    shr-int/lit8 v8, v13, 0x3

    .line 361
    .line 362
    aget-wide v9, v1, v8

    .line 363
    .line 364
    and-int/lit8 v14, v13, 0x7

    .line 365
    .line 366
    shl-int/lit8 v14, v14, 0x3

    .line 367
    .line 368
    shr-long v31, v9, v14

    .line 369
    .line 370
    and-long v31, v31, v25

    .line 371
    .line 372
    cmp-long v19, v31, v17

    .line 373
    .line 374
    if-nez v19, :cond_a

    .line 375
    .line 376
    and-int/lit8 v7, v7, 0x7f

    .line 377
    .line 378
    move/from16 v31, v12

    .line 379
    .line 380
    move/from16 v19, v13

    .line 381
    .line 382
    int-to-long v12, v7

    .line 383
    move/from16 v32, v2

    .line 384
    .line 385
    move-object/from16 v33, v3

    .line 386
    .line 387
    shl-long v2, v25, v14

    .line 388
    .line 389
    not-long v2, v2

    .line 390
    and-long/2addr v2, v9

    .line 391
    shl-long v9, v12, v14

    .line 392
    .line 393
    or-long/2addr v2, v9

    .line 394
    aput-wide v2, v1, v8

    .line 395
    .line 396
    aget-wide v2, v1, v6

    .line 397
    .line 398
    shl-long v7, v25, v11

    .line 399
    .line 400
    not-long v7, v7

    .line 401
    and-long/2addr v2, v7

    .line 402
    shl-long v7, v17, v11

    .line 403
    .line 404
    or-long/2addr v2, v7

    .line 405
    aput-wide v2, v1, v6

    .line 406
    .line 407
    aget-object v2, v33, v4

    .line 408
    .line 409
    aput-object v2, v33, v19

    .line 410
    .line 411
    const/4 v2, 0x0

    .line 412
    aput-object v2, v33, v4

    .line 413
    .line 414
    goto :goto_7

    .line 415
    :cond_a
    move/from16 v32, v2

    .line 416
    .line 417
    move-object/from16 v33, v3

    .line 418
    .line 419
    move/from16 v31, v12

    .line 420
    .line 421
    move/from16 v19, v13

    .line 422
    .line 423
    and-int/lit8 v2, v7, 0x7f

    .line 424
    .line 425
    int-to-long v2, v2

    .line 426
    shl-long v6, v25, v14

    .line 427
    .line 428
    not-long v6, v6

    .line 429
    and-long/2addr v6, v9

    .line 430
    shl-long/2addr v2, v14

    .line 431
    or-long/2addr v2, v6

    .line 432
    aput-wide v2, v1, v8

    .line 433
    .line 434
    aget-object v2, v33, v19

    .line 435
    .line 436
    aget-object v3, v33, v4

    .line 437
    .line 438
    aput-object v3, v33, v19

    .line 439
    .line 440
    aput-object v2, v33, v4

    .line 441
    .line 442
    add-int/lit8 v4, v4, -0x1

    .line 443
    .line 444
    :goto_7
    array-length v2, v1

    .line 445
    add-int/lit8 v2, v2, -0x1

    .line 446
    .line 447
    aget-wide v6, v1, v15

    .line 448
    .line 449
    and-long v6, v6, v29

    .line 450
    .line 451
    or-long v6, v6, v27

    .line 452
    .line 453
    aput-wide v6, v1, v2

    .line 454
    .line 455
    add-int/lit8 v4, v4, 0x1

    .line 456
    .line 457
    move-wide/from16 v9, v29

    .line 458
    .line 459
    move/from16 v12, v31

    .line 460
    .line 461
    move/from16 v2, v32

    .line 462
    .line 463
    move-object/from16 v3, v33

    .line 464
    .line 465
    goto/16 :goto_4

    .line 466
    .line 467
    :cond_b
    iget v1, v0, Landroidx/collection/r0;->c:I

    .line 468
    .line 469
    invoke-static {v1}, Landroidx/collection/y0;->a(I)I

    .line 470
    .line 471
    .line 472
    move-result v1

    .line 473
    iget v2, v0, Landroidx/collection/r0;->d:I

    .line 474
    .line 475
    sub-int/2addr v1, v2

    .line 476
    iput v1, v0, Landroidx/collection/r0;->e:I

    .line 477
    .line 478
    goto/16 :goto_d

    .line 479
    .line 480
    :cond_c
    :goto_8
    move-wide/from16 v25, v8

    .line 481
    .line 482
    move-wide/from16 v23, v11

    .line 483
    .line 484
    const-wide/16 v17, 0x80

    .line 485
    .line 486
    goto :goto_9

    .line 487
    :cond_d
    const/16 p1, 0x7

    .line 488
    .line 489
    goto :goto_8

    .line 490
    :goto_9
    iget v1, v0, Landroidx/collection/r0;->c:I

    .line 491
    .line 492
    invoke-static {v1}, Landroidx/collection/y0;->b(I)I

    .line 493
    .line 494
    .line 495
    move-result v1

    .line 496
    iget-object v2, v0, Landroidx/collection/r0;->a:[J

    .line 497
    .line 498
    iget-object v3, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 499
    .line 500
    iget v4, v0, Landroidx/collection/r0;->c:I

    .line 501
    .line 502
    invoke-virtual {v0, v1}, Landroidx/collection/r0;->f(I)V

    .line 503
    .line 504
    .line 505
    iget-object v1, v0, Landroidx/collection/r0;->a:[J

    .line 506
    .line 507
    iget-object v6, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 508
    .line 509
    iget v7, v0, Landroidx/collection/r0;->c:I

    .line 510
    .line 511
    move v8, v15

    .line 512
    :goto_a
    if-ge v8, v4, :cond_10

    .line 513
    .line 514
    shr-int/lit8 v9, v8, 0x3

    .line 515
    .line 516
    aget-wide v9, v2, v9

    .line 517
    .line 518
    and-int/lit8 v11, v8, 0x7

    .line 519
    .line 520
    shl-int/lit8 v11, v11, 0x3

    .line 521
    .line 522
    shr-long/2addr v9, v11

    .line 523
    and-long v9, v9, v25

    .line 524
    .line 525
    cmp-long v9, v9, v17

    .line 526
    .line 527
    if-gez v9, :cond_f

    .line 528
    .line 529
    aget-object v9, v3, v8

    .line 530
    .line 531
    if-eqz v9, :cond_e

    .line 532
    .line 533
    invoke-virtual {v9}, Ljava/lang/Object;->hashCode()I

    .line 534
    .line 535
    .line 536
    move-result v10

    .line 537
    goto :goto_b

    .line 538
    :cond_e
    move v10, v15

    .line 539
    :goto_b
    mul-int v10, v10, v20

    .line 540
    .line 541
    shl-int/lit8 v11, v10, 0x10

    .line 542
    .line 543
    xor-int/2addr v10, v11

    .line 544
    ushr-int/lit8 v11, v10, 0x7

    .line 545
    .line 546
    invoke-virtual {v0, v11}, Landroidx/collection/r0;->e(I)I

    .line 547
    .line 548
    .line 549
    move-result v11

    .line 550
    and-int/lit8 v10, v10, 0x7f

    .line 551
    .line 552
    int-to-long v12, v10

    .line 553
    shr-int/lit8 v10, v11, 0x3

    .line 554
    .line 555
    and-int/lit8 v14, v11, 0x7

    .line 556
    .line 557
    shl-int/lit8 v14, v14, 0x3

    .line 558
    .line 559
    aget-wide v21, v1, v10

    .line 560
    .line 561
    move-object/from16 v27, v1

    .line 562
    .line 563
    move-object/from16 v19, v2

    .line 564
    .line 565
    shl-long v1, v25, v14

    .line 566
    .line 567
    not-long v1, v1

    .line 568
    and-long v1, v21, v1

    .line 569
    .line 570
    shl-long/2addr v12, v14

    .line 571
    or-long/2addr v1, v12

    .line 572
    aput-wide v1, v27, v10

    .line 573
    .line 574
    add-int/lit8 v10, v11, -0x7

    .line 575
    .line 576
    and-int/2addr v10, v7

    .line 577
    and-int/lit8 v12, v7, 0x7

    .line 578
    .line 579
    add-int/2addr v10, v12

    .line 580
    shr-int/lit8 v10, v10, 0x3

    .line 581
    .line 582
    aput-wide v1, v27, v10

    .line 583
    .line 584
    aput-object v9, v6, v11

    .line 585
    .line 586
    goto :goto_c

    .line 587
    :cond_f
    move-object/from16 v27, v1

    .line 588
    .line 589
    move-object/from16 v19, v2

    .line 590
    .line 591
    :goto_c
    add-int/lit8 v8, v8, 0x1

    .line 592
    .line 593
    move-object/from16 v2, v19

    .line 594
    .line 595
    move-object/from16 v1, v27

    .line 596
    .line 597
    goto :goto_a

    .line 598
    :cond_10
    :goto_d
    invoke-virtual {v0, v5}, Landroidx/collection/r0;->e(I)I

    .line 599
    .line 600
    .line 601
    move-result v1

    .line 602
    :goto_e
    iget v2, v0, Landroidx/collection/r0;->d:I

    .line 603
    .line 604
    add-int/lit8 v2, v2, 0x1

    .line 605
    .line 606
    iput v2, v0, Landroidx/collection/r0;->d:I

    .line 607
    .line 608
    iget v2, v0, Landroidx/collection/r0;->e:I

    .line 609
    .line 610
    iget-object v3, v0, Landroidx/collection/r0;->a:[J

    .line 611
    .line 612
    shr-int/lit8 v4, v1, 0x3

    .line 613
    .line 614
    aget-wide v5, v3, v4

    .line 615
    .line 616
    and-int/lit8 v7, v1, 0x7

    .line 617
    .line 618
    shl-int/lit8 v7, v7, 0x3

    .line 619
    .line 620
    shr-long v8, v5, v7

    .line 621
    .line 622
    and-long v8, v8, v25

    .line 623
    .line 624
    cmp-long v8, v8, v17

    .line 625
    .line 626
    if-nez v8, :cond_11

    .line 627
    .line 628
    move/from16 v15, v16

    .line 629
    .line 630
    :cond_11
    sub-int/2addr v2, v15

    .line 631
    iput v2, v0, Landroidx/collection/r0;->e:I

    .line 632
    .line 633
    iget v0, v0, Landroidx/collection/r0;->c:I

    .line 634
    .line 635
    shl-long v8, v25, v7

    .line 636
    .line 637
    not-long v8, v8

    .line 638
    and-long/2addr v5, v8

    .line 639
    shl-long v7, v23, v7

    .line 640
    .line 641
    or-long/2addr v5, v7

    .line 642
    aput-wide v5, v3, v4

    .line 643
    .line 644
    add-int/lit8 v2, v1, -0x7

    .line 645
    .line 646
    and-int/2addr v2, v0

    .line 647
    and-int/lit8 v0, v0, 0x7

    .line 648
    .line 649
    add-int/2addr v2, v0

    .line 650
    shr-int/lit8 v0, v2, 0x3

    .line 651
    .line 652
    aput-wide v5, v3, v0

    .line 653
    .line 654
    return v1

    .line 655
    :cond_12
    move/from16 v31, v3

    .line 656
    .line 657
    add-int/lit8 v8, v8, 0x8

    .line 658
    .line 659
    add-int/2addr v7, v8

    .line 660
    and-int/2addr v7, v6

    .line 661
    move/from16 v3, v19

    .line 662
    .line 663
    move/from16 v4, v20

    .line 664
    .line 665
    goto/16 :goto_1
.end method

.method public final e(I)I
    .locals 9

    .line 1
    iget v0, p0, Landroidx/collection/r0;->c:I

    .line 2
    .line 3
    and-int/2addr p1, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    iget-object v2, p0, Landroidx/collection/r0;->a:[J

    .line 6
    .line 7
    shr-int/lit8 v3, p1, 0x3

    .line 8
    .line 9
    and-int/lit8 v4, p1, 0x7

    .line 10
    .line 11
    shl-int/lit8 v4, v4, 0x3

    .line 12
    .line 13
    aget-wide v5, v2, v3

    .line 14
    .line 15
    ushr-long/2addr v5, v4

    .line 16
    add-int/lit8 v3, v3, 0x1

    .line 17
    .line 18
    aget-wide v2, v2, v3

    .line 19
    .line 20
    rsub-int/lit8 v7, v4, 0x40

    .line 21
    .line 22
    shl-long/2addr v2, v7

    .line 23
    int-to-long v7, v4

    .line 24
    neg-long v7, v7

    .line 25
    const/16 v4, 0x3f

    .line 26
    .line 27
    shr-long/2addr v7, v4

    .line 28
    and-long/2addr v2, v7

    .line 29
    or-long/2addr v2, v5

    .line 30
    not-long v4, v2

    .line 31
    const/4 v6, 0x7

    .line 32
    shl-long/2addr v4, v6

    .line 33
    and-long/2addr v2, v4

    .line 34
    const-wide v4, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v2, v4

    .line 40
    const-wide/16 v4, 0x0

    .line 41
    .line 42
    cmp-long v4, v2, v4

    .line 43
    .line 44
    if-eqz v4, :cond_0

    .line 45
    .line 46
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    shr-int/lit8 p0, p0, 0x3

    .line 51
    .line 52
    add-int/2addr p1, p0

    .line 53
    and-int p0, p1, v0

    .line 54
    .line 55
    return p0

    .line 56
    :cond_0
    add-int/lit8 v1, v1, 0x8

    .line 57
    .line 58
    add-int/2addr p1, v1

    .line 59
    and-int/2addr p1, v0

    .line 60
    goto :goto_0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 14

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/collection/r0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Landroidx/collection/r0;

    .line 12
    .line 13
    iget v1, p1, Landroidx/collection/r0;->d:I

    .line 14
    .line 15
    iget v3, p0, Landroidx/collection/r0;->d:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 21
    .line 22
    iget-object p0, p0, Landroidx/collection/r0;->a:[J

    .line 23
    .line 24
    array-length v3, p0

    .line 25
    add-int/lit8 v3, v3, -0x2

    .line 26
    .line 27
    if-ltz v3, :cond_6

    .line 28
    .line 29
    move v4, v2

    .line 30
    :goto_0
    aget-wide v5, p0, v4

    .line 31
    .line 32
    not-long v7, v5

    .line 33
    const/4 v9, 0x7

    .line 34
    shl-long/2addr v7, v9

    .line 35
    and-long/2addr v7, v5

    .line 36
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr v7, v9

    .line 42
    cmp-long v7, v7, v9

    .line 43
    .line 44
    if-eqz v7, :cond_5

    .line 45
    .line 46
    sub-int v7, v4, v3

    .line 47
    .line 48
    not-int v7, v7

    .line 49
    ushr-int/lit8 v7, v7, 0x1f

    .line 50
    .line 51
    const/16 v8, 0x8

    .line 52
    .line 53
    rsub-int/lit8 v7, v7, 0x8

    .line 54
    .line 55
    move v9, v2

    .line 56
    :goto_1
    if-ge v9, v7, :cond_4

    .line 57
    .line 58
    const-wide/16 v10, 0xff

    .line 59
    .line 60
    and-long/2addr v10, v5

    .line 61
    const-wide/16 v12, 0x80

    .line 62
    .line 63
    cmp-long v10, v10, v12

    .line 64
    .line 65
    if-gez v10, :cond_3

    .line 66
    .line 67
    shl-int/lit8 v10, v4, 0x3

    .line 68
    .line 69
    add-int/2addr v10, v9

    .line 70
    aget-object v10, v1, v10

    .line 71
    .line 72
    invoke-virtual {p1, v10}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    if-nez v10, :cond_3

    .line 77
    .line 78
    return v2

    .line 79
    :cond_3
    shr-long/2addr v5, v8

    .line 80
    add-int/lit8 v9, v9, 0x1

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_4
    if-ne v7, v8, :cond_6

    .line 84
    .line 85
    :cond_5
    if-eq v4, v3, :cond_6

    .line 86
    .line 87
    add-int/lit8 v4, v4, 0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_6
    return v0
.end method

.method public final f(I)V
    .locals 9

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Landroidx/collection/y0;->c(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x7

    .line 8
    invoke-static {v0, p1}, Ljava/lang/Math;->max(II)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    iput p1, p0, Landroidx/collection/r0;->c:I

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    add-int/lit8 v0, p1, 0xf

    .line 22
    .line 23
    and-int/lit8 v0, v0, -0x8

    .line 24
    .line 25
    shr-int/lit8 v0, v0, 0x3

    .line 26
    .line 27
    new-array v0, v0, [J

    .line 28
    .line 29
    const-wide v1, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    invoke-static {v1, v2, v0}, Lmx0/n;->r(J[J)V

    .line 35
    .line 36
    .line 37
    :goto_1
    iput-object v0, p0, Landroidx/collection/r0;->a:[J

    .line 38
    .line 39
    shr-int/lit8 v1, p1, 0x3

    .line 40
    .line 41
    and-int/lit8 v2, p1, 0x7

    .line 42
    .line 43
    shl-int/lit8 v2, v2, 0x3

    .line 44
    .line 45
    aget-wide v3, v0, v1

    .line 46
    .line 47
    const-wide/16 v5, 0xff

    .line 48
    .line 49
    shl-long/2addr v5, v2

    .line 50
    not-long v7, v5

    .line 51
    and-long v2, v3, v7

    .line 52
    .line 53
    or-long/2addr v2, v5

    .line 54
    aput-wide v2, v0, v1

    .line 55
    .line 56
    iget v0, p0, Landroidx/collection/r0;->c:I

    .line 57
    .line 58
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v1, p0, Landroidx/collection/r0;->d:I

    .line 63
    .line 64
    sub-int/2addr v0, v1

    .line 65
    iput v0, p0, Landroidx/collection/r0;->e:I

    .line 66
    .line 67
    if-nez p1, :cond_2

    .line 68
    .line 69
    sget-object p1, La1/a;->c:[Ljava/lang/Object;

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    new-array p1, p1, [Ljava/lang/Object;

    .line 73
    .line 74
    :goto_2
    iput-object p1, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 75
    .line 76
    return-void
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/r0;->d:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final h()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/r0;->d:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final hashCode()I
    .locals 15

    .line 1
    iget v0, p0, Landroidx/collection/r0;->c:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x1f

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/r0;->d:I

    .line 6
    .line 7
    add-int/2addr v0, v1

    .line 8
    iget-object v1, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 9
    .line 10
    iget-object v2, p0, Landroidx/collection/r0;->a:[J

    .line 11
    .line 12
    array-length v3, v2

    .line 13
    add-int/lit8 v3, v3, -0x2

    .line 14
    .line 15
    if-ltz v3, :cond_5

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    move v5, v4

    .line 19
    :goto_0
    aget-wide v6, v2, v5

    .line 20
    .line 21
    not-long v8, v6

    .line 22
    const/4 v10, 0x7

    .line 23
    shl-long/2addr v8, v10

    .line 24
    and-long/2addr v8, v6

    .line 25
    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    and-long/2addr v8, v10

    .line 31
    cmp-long v8, v8, v10

    .line 32
    .line 33
    if-eqz v8, :cond_4

    .line 34
    .line 35
    sub-int v8, v5, v3

    .line 36
    .line 37
    not-int v8, v8

    .line 38
    ushr-int/lit8 v8, v8, 0x1f

    .line 39
    .line 40
    const/16 v9, 0x8

    .line 41
    .line 42
    rsub-int/lit8 v8, v8, 0x8

    .line 43
    .line 44
    move v10, v4

    .line 45
    :goto_1
    if-ge v10, v8, :cond_2

    .line 46
    .line 47
    const-wide/16 v11, 0xff

    .line 48
    .line 49
    and-long/2addr v11, v6

    .line 50
    const-wide/16 v13, 0x80

    .line 51
    .line 52
    cmp-long v11, v11, v13

    .line 53
    .line 54
    if-gez v11, :cond_1

    .line 55
    .line 56
    shl-int/lit8 v11, v5, 0x3

    .line 57
    .line 58
    add-int/2addr v11, v10

    .line 59
    aget-object v11, v1, v11

    .line 60
    .line 61
    invoke-static {v11, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    if-nez v12, :cond_1

    .line 66
    .line 67
    if-eqz v11, :cond_0

    .line 68
    .line 69
    invoke-virtual {v11}, Ljava/lang/Object;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v11

    .line 73
    goto :goto_2

    .line 74
    :cond_0
    move v11, v4

    .line 75
    :goto_2
    add-int/2addr v0, v11

    .line 76
    :cond_1
    shr-long/2addr v6, v9

    .line 77
    add-int/lit8 v10, v10, 0x1

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    if-ne v8, v9, :cond_3

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_3
    return v0

    .line 84
    :cond_4
    :goto_3
    if-eq v5, v3, :cond_5

    .line 85
    .line 86
    add-int/lit8 v5, v5, 0x1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_5
    return v0
.end method

.method public final i(Ljava/lang/Object;)V
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    const v2, -0x3361d2af    # -8.2930312E7f

    .line 11
    .line 12
    .line 13
    mul-int/2addr v1, v2

    .line 14
    shl-int/lit8 v2, v1, 0x10

    .line 15
    .line 16
    xor-int/2addr v1, v2

    .line 17
    and-int/lit8 v2, v1, 0x7f

    .line 18
    .line 19
    iget v3, p0, Landroidx/collection/r0;->c:I

    .line 20
    .line 21
    ushr-int/lit8 v1, v1, 0x7

    .line 22
    .line 23
    :goto_1
    and-int/2addr v1, v3

    .line 24
    iget-object v4, p0, Landroidx/collection/r0;->a:[J

    .line 25
    .line 26
    shr-int/lit8 v5, v1, 0x3

    .line 27
    .line 28
    and-int/lit8 v6, v1, 0x7

    .line 29
    .line 30
    shl-int/lit8 v6, v6, 0x3

    .line 31
    .line 32
    aget-wide v7, v4, v5

    .line 33
    .line 34
    ushr-long/2addr v7, v6

    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    aget-wide v4, v4, v5

    .line 38
    .line 39
    rsub-int/lit8 v9, v6, 0x40

    .line 40
    .line 41
    shl-long/2addr v4, v9

    .line 42
    int-to-long v9, v6

    .line 43
    neg-long v9, v9

    .line 44
    const/16 v6, 0x3f

    .line 45
    .line 46
    shr-long/2addr v9, v6

    .line 47
    and-long/2addr v4, v9

    .line 48
    or-long/2addr v4, v7

    .line 49
    int-to-long v6, v2

    .line 50
    const-wide v8, 0x101010101010101L

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    mul-long/2addr v6, v8

    .line 56
    xor-long/2addr v6, v4

    .line 57
    sub-long v8, v6, v8

    .line 58
    .line 59
    not-long v6, v6

    .line 60
    and-long/2addr v6, v8

    .line 61
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v6, v8

    .line 67
    :goto_2
    const-wide/16 v10, 0x0

    .line 68
    .line 69
    cmp-long v12, v6, v10

    .line 70
    .line 71
    if-eqz v12, :cond_2

    .line 72
    .line 73
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    shr-int/lit8 v10, v10, 0x3

    .line 78
    .line 79
    add-int/2addr v10, v1

    .line 80
    and-int/2addr v10, v3

    .line 81
    iget-object v11, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 82
    .line 83
    aget-object v11, v11, v10

    .line 84
    .line 85
    invoke-static {v11, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    if-eqz v11, :cond_1

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_1
    const-wide/16 v10, 0x1

    .line 93
    .line 94
    sub-long v10, v6, v10

    .line 95
    .line 96
    and-long/2addr v6, v10

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    not-long v6, v4

    .line 99
    const/4 v12, 0x6

    .line 100
    shl-long/2addr v6, v12

    .line 101
    and-long/2addr v4, v6

    .line 102
    and-long/2addr v4, v8

    .line 103
    cmp-long v4, v4, v10

    .line 104
    .line 105
    if-eqz v4, :cond_4

    .line 106
    .line 107
    const/4 v10, -0x1

    .line 108
    :goto_3
    if-ltz v10, :cond_3

    .line 109
    .line 110
    invoke-virtual {p0, v10}, Landroidx/collection/r0;->m(I)V

    .line 111
    .line 112
    .line 113
    :cond_3
    return-void

    .line 114
    :cond_4
    add-int/lit8 v0, v0, 0x8

    .line 115
    .line 116
    add-int/2addr v1, v0

    .line 117
    goto :goto_1
.end method

.method public final j(Landroidx/collection/r0;)V
    .locals 13

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p1, p1, Landroidx/collection/r0;->a:[J

    .line 9
    .line 10
    array-length v1, p1

    .line 11
    add-int/lit8 v1, v1, -0x2

    .line 12
    .line 13
    if-ltz v1, :cond_3

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    move v3, v2

    .line 17
    :goto_0
    aget-wide v4, p1, v3

    .line 18
    .line 19
    not-long v6, v4

    .line 20
    const/4 v8, 0x7

    .line 21
    shl-long/2addr v6, v8

    .line 22
    and-long/2addr v6, v4

    .line 23
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    and-long/2addr v6, v8

    .line 29
    cmp-long v6, v6, v8

    .line 30
    .line 31
    if-eqz v6, :cond_2

    .line 32
    .line 33
    sub-int v6, v3, v1

    .line 34
    .line 35
    not-int v6, v6

    .line 36
    ushr-int/lit8 v6, v6, 0x1f

    .line 37
    .line 38
    const/16 v7, 0x8

    .line 39
    .line 40
    rsub-int/lit8 v6, v6, 0x8

    .line 41
    .line 42
    move v8, v2

    .line 43
    :goto_1
    if-ge v8, v6, :cond_1

    .line 44
    .line 45
    const-wide/16 v9, 0xff

    .line 46
    .line 47
    and-long/2addr v9, v4

    .line 48
    const-wide/16 v11, 0x80

    .line 49
    .line 50
    cmp-long v9, v9, v11

    .line 51
    .line 52
    if-gez v9, :cond_0

    .line 53
    .line 54
    shl-int/lit8 v9, v3, 0x3

    .line 55
    .line 56
    add-int/2addr v9, v8

    .line 57
    aget-object v9, v0, v9

    .line 58
    .line 59
    invoke-virtual {p0, v9}, Landroidx/collection/r0;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    :cond_0
    shr-long/2addr v4, v7

    .line 63
    add-int/lit8 v8, v8, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    if-ne v6, v7, :cond_3

    .line 67
    .line 68
    :cond_2
    if-eq v3, v1, :cond_3

    .line 69
    .line 70
    add-int/lit8 v3, v3, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    return-void
.end method

.method public final k(Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/r0;->d(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object p0, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 6
    .line 7
    aput-object p1, p0, v0

    .line 8
    .line 9
    return-void
.end method

.method public final l(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v3, v2

    .line 14
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 15
    .line 16
    .line 17
    mul-int/2addr v3, v4

    .line 18
    shl-int/lit8 v4, v3, 0x10

    .line 19
    .line 20
    xor-int/2addr v3, v4

    .line 21
    and-int/lit8 v4, v3, 0x7f

    .line 22
    .line 23
    iget v5, v0, Landroidx/collection/r0;->c:I

    .line 24
    .line 25
    ushr-int/lit8 v3, v3, 0x7

    .line 26
    .line 27
    and-int/2addr v3, v5

    .line 28
    move v6, v2

    .line 29
    :goto_1
    iget-object v7, v0, Landroidx/collection/r0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v8, v3, 0x3

    .line 32
    .line 33
    and-int/lit8 v9, v3, 0x7

    .line 34
    .line 35
    shl-int/lit8 v9, v9, 0x3

    .line 36
    .line 37
    aget-wide v10, v7, v8

    .line 38
    .line 39
    ushr-long/2addr v10, v9

    .line 40
    const/4 v12, 0x1

    .line 41
    add-int/2addr v8, v12

    .line 42
    aget-wide v7, v7, v8

    .line 43
    .line 44
    rsub-int/lit8 v13, v9, 0x40

    .line 45
    .line 46
    shl-long/2addr v7, v13

    .line 47
    int-to-long v13, v9

    .line 48
    neg-long v13, v13

    .line 49
    const/16 v9, 0x3f

    .line 50
    .line 51
    shr-long/2addr v13, v9

    .line 52
    and-long/2addr v7, v13

    .line 53
    or-long/2addr v7, v10

    .line 54
    int-to-long v9, v4

    .line 55
    const-wide v13, 0x101010101010101L

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    mul-long/2addr v9, v13

    .line 61
    xor-long/2addr v9, v7

    .line 62
    sub-long v13, v9, v13

    .line 63
    .line 64
    not-long v9, v9

    .line 65
    and-long/2addr v9, v13

    .line 66
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    and-long/2addr v9, v13

    .line 72
    :goto_2
    const-wide/16 v15, 0x0

    .line 73
    .line 74
    cmp-long v11, v9, v15

    .line 75
    .line 76
    if-eqz v11, :cond_2

    .line 77
    .line 78
    invoke-static {v9, v10}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    shr-int/lit8 v11, v11, 0x3

    .line 83
    .line 84
    add-int/2addr v11, v3

    .line 85
    and-int/2addr v11, v5

    .line 86
    iget-object v15, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 87
    .line 88
    aget-object v15, v15, v11

    .line 89
    .line 90
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v15

    .line 94
    if-eqz v15, :cond_1

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_1
    const-wide/16 v15, 0x1

    .line 98
    .line 99
    sub-long v15, v9, v15

    .line 100
    .line 101
    and-long/2addr v9, v15

    .line 102
    goto :goto_2

    .line 103
    :cond_2
    not-long v9, v7

    .line 104
    const/4 v11, 0x6

    .line 105
    shl-long/2addr v9, v11

    .line 106
    and-long/2addr v7, v9

    .line 107
    and-long/2addr v7, v13

    .line 108
    cmp-long v7, v7, v15

    .line 109
    .line 110
    if-eqz v7, :cond_5

    .line 111
    .line 112
    const/4 v11, -0x1

    .line 113
    :goto_3
    if-ltz v11, :cond_3

    .line 114
    .line 115
    move v2, v12

    .line 116
    :cond_3
    if-eqz v2, :cond_4

    .line 117
    .line 118
    invoke-virtual {v0, v11}, Landroidx/collection/r0;->m(I)V

    .line 119
    .line 120
    .line 121
    :cond_4
    return v2

    .line 122
    :cond_5
    add-int/lit8 v6, v6, 0x8

    .line 123
    .line 124
    add-int/2addr v3, v6

    .line 125
    and-int/2addr v3, v5

    .line 126
    goto :goto_1
.end method

.method public final m(I)V
    .locals 8

    .line 1
    iget v0, p0, Landroidx/collection/r0;->d:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Landroidx/collection/r0;->d:I

    .line 6
    .line 7
    iget-object v0, p0, Landroidx/collection/r0;->a:[J

    .line 8
    .line 9
    iget v1, p0, Landroidx/collection/r0;->c:I

    .line 10
    .line 11
    shr-int/lit8 v2, p1, 0x3

    .line 12
    .line 13
    and-int/lit8 v3, p1, 0x7

    .line 14
    .line 15
    shl-int/lit8 v3, v3, 0x3

    .line 16
    .line 17
    aget-wide v4, v0, v2

    .line 18
    .line 19
    const-wide/16 v6, 0xff

    .line 20
    .line 21
    shl-long/2addr v6, v3

    .line 22
    not-long v6, v6

    .line 23
    and-long/2addr v4, v6

    .line 24
    const-wide/16 v6, 0xfe

    .line 25
    .line 26
    shl-long/2addr v6, v3

    .line 27
    or-long v3, v4, v6

    .line 28
    .line 29
    aput-wide v3, v0, v2

    .line 30
    .line 31
    add-int/lit8 v2, p1, -0x7

    .line 32
    .line 33
    and-int/2addr v2, v1

    .line 34
    and-int/lit8 v1, v1, 0x7

    .line 35
    .line 36
    add-int/2addr v2, v1

    .line 37
    shr-int/lit8 v1, v2, 0x3

    .line 38
    .line 39
    aput-wide v3, v0, v1

    .line 40
    .line 41
    iget-object p0, p0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    aput-object v0, p0, p1

    .line 45
    .line 46
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, La3/f;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    invoke-direct {v1, v0, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    new-instance v2, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v3, "["

    .line 12
    .line 13
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v3, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 17
    .line 18
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 19
    .line 20
    array-length v4, v0

    .line 21
    add-int/lit8 v4, v4, -0x2

    .line 22
    .line 23
    if-ltz v4, :cond_5

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    move v6, v5

    .line 27
    move v7, v6

    .line 28
    :goto_0
    aget-wide v8, v0, v6

    .line 29
    .line 30
    not-long v10, v8

    .line 31
    const/4 v12, 0x7

    .line 32
    shl-long/2addr v10, v12

    .line 33
    and-long/2addr v10, v8

    .line 34
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v10, v12

    .line 40
    cmp-long v10, v10, v12

    .line 41
    .line 42
    if-eqz v10, :cond_4

    .line 43
    .line 44
    sub-int v10, v6, v4

    .line 45
    .line 46
    not-int v10, v10

    .line 47
    ushr-int/lit8 v10, v10, 0x1f

    .line 48
    .line 49
    const/16 v11, 0x8

    .line 50
    .line 51
    rsub-int/lit8 v10, v10, 0x8

    .line 52
    .line 53
    move v12, v5

    .line 54
    :goto_1
    if-ge v12, v10, :cond_3

    .line 55
    .line 56
    const-wide/16 v13, 0xff

    .line 57
    .line 58
    and-long/2addr v13, v8

    .line 59
    const-wide/16 v15, 0x80

    .line 60
    .line 61
    cmp-long v13, v13, v15

    .line 62
    .line 63
    if-gez v13, :cond_2

    .line 64
    .line 65
    shl-int/lit8 v13, v6, 0x3

    .line 66
    .line 67
    add-int/2addr v13, v12

    .line 68
    aget-object v13, v3, v13

    .line 69
    .line 70
    const/4 v14, -0x1

    .line 71
    if-ne v7, v14, :cond_0

    .line 72
    .line 73
    const-string v0, "..."

    .line 74
    .line 75
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_0
    if-eqz v7, :cond_1

    .line 80
    .line 81
    const-string v14, ", "

    .line 82
    .line 83
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    :cond_1
    invoke-virtual {v1, v13}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v13

    .line 90
    check-cast v13, Ljava/lang/CharSequence;

    .line 91
    .line 92
    invoke-virtual {v2, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    add-int/lit8 v7, v7, 0x1

    .line 96
    .line 97
    :cond_2
    shr-long/2addr v8, v11

    .line 98
    add-int/lit8 v12, v12, 0x1

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    if-ne v10, v11, :cond_5

    .line 102
    .line 103
    :cond_4
    if-eq v6, v4, :cond_5

    .line 104
    .line 105
    add-int/lit8 v6, v6, 0x1

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_5
    const-string v0, "]"

    .line 109
    .line 110
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    :goto_2
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    const-string v1, "toString(...)"

    .line 118
    .line 119
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    return-object v0
.end method
