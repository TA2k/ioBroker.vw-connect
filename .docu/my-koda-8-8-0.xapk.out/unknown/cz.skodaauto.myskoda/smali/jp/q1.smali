.class public abstract Ljp/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ln1/a;Lx2/s;Ln1/v;Lk1/z0;Lk1/i;Lk1/g;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v12, p10

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v0, -0x7b81c7d6

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v2, 0x2

    .line 18
    const/4 v3, 0x4

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    or-int v0, p11, v0

    .line 25
    .line 26
    move-object/from16 v4, p1

    .line 27
    .line 28
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v5, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v5

    .line 40
    move-object/from16 v5, p2

    .line 41
    .line 42
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    const/16 v6, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v6, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v6

    .line 54
    const v6, 0x16406c00

    .line 55
    .line 56
    .line 57
    or-int/2addr v0, v6

    .line 58
    move-object/from16 v10, p9

    .line 59
    .line 60
    invoke-virtual {v12, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-eqz v6, :cond_3

    .line 65
    .line 66
    move v6, v3

    .line 67
    goto :goto_3

    .line 68
    :cond_3
    move v6, v2

    .line 69
    :goto_3
    const v7, 0x12492493

    .line 70
    .line 71
    .line 72
    and-int/2addr v7, v0

    .line 73
    const v8, 0x12492492

    .line 74
    .line 75
    .line 76
    const/4 v9, 0x0

    .line 77
    const/4 v11, 0x1

    .line 78
    if-ne v7, v8, :cond_5

    .line 79
    .line 80
    and-int/lit8 v7, v6, 0x3

    .line 81
    .line 82
    if-eq v7, v2, :cond_4

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move v2, v9

    .line 86
    goto :goto_5

    .line 87
    :cond_5
    :goto_4
    move v2, v11

    .line 88
    :goto_5
    and-int/lit8 v7, v0, 0x1

    .line 89
    .line 90
    invoke-virtual {v12, v7, v2}, Ll2/t;->O(IZ)Z

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    if-eqz v2, :cond_f

    .line 95
    .line 96
    invoke-virtual {v12}, Ll2/t;->T()V

    .line 97
    .line 98
    .line 99
    and-int/lit8 v2, p11, 0x1

    .line 100
    .line 101
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    const v8, -0x71c00001

    .line 104
    .line 105
    .line 106
    if-eqz v2, :cond_7

    .line 107
    .line 108
    invoke-virtual {v12}, Ll2/t;->y()Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-eqz v2, :cond_6

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_6
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    and-int/2addr v0, v8

    .line 119
    move-object/from16 v13, p3

    .line 120
    .line 121
    move-object/from16 v8, p8

    .line 122
    .line 123
    move v2, v0

    .line 124
    move v14, v6

    .line 125
    move-object/from16 v6, p6

    .line 126
    .line 127
    move/from16 v0, p7

    .line 128
    .line 129
    goto :goto_7

    .line 130
    :cond_7
    :goto_6
    int-to-float v2, v9

    .line 131
    new-instance v13, Lk1/a1;

    .line 132
    .line 133
    invoke-direct {v13, v2, v2, v2, v2}, Lk1/a1;-><init>(FFFF)V

    .line 134
    .line 135
    .line 136
    invoke-static {v12}, Lb1/h1;->a(Ll2/o;)Lc1/u;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v14

    .line 144
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v15

    .line 148
    if-nez v14, :cond_8

    .line 149
    .line 150
    if-ne v15, v7, :cond_9

    .line 151
    .line 152
    :cond_8
    new-instance v15, Lg1/d0;

    .line 153
    .line 154
    invoke-direct {v15, v2}, Lg1/d0;-><init>(Lc1/u;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    :cond_9
    move-object v2, v15

    .line 161
    check-cast v2, Lg1/d0;

    .line 162
    .line 163
    invoke-static {v12}, Le1/e1;->a(Ll2/o;)Le1/j;

    .line 164
    .line 165
    .line 166
    move-result-object v14

    .line 167
    and-int/2addr v0, v8

    .line 168
    move-object v8, v14

    .line 169
    move v14, v6

    .line 170
    move-object v6, v2

    .line 171
    move v2, v0

    .line 172
    move v0, v11

    .line 173
    :goto_7
    invoke-virtual {v12}, Ll2/t;->r()V

    .line 174
    .line 175
    .line 176
    and-int/lit8 v15, v2, 0xe

    .line 177
    .line 178
    or-int/lit8 v15, v15, 0x30

    .line 179
    .line 180
    and-int/lit8 v16, v15, 0xe

    .line 181
    .line 182
    const/16 v17, 0x6

    .line 183
    .line 184
    xor-int/lit8 v9, v16, 0x6

    .line 185
    .line 186
    if-le v9, v3, :cond_a

    .line 187
    .line 188
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v9

    .line 192
    if-nez v9, :cond_b

    .line 193
    .line 194
    :cond_a
    and-int/lit8 v9, v15, 0x6

    .line 195
    .line 196
    if-ne v9, v3, :cond_c

    .line 197
    .line 198
    :cond_b
    move v9, v11

    .line 199
    goto :goto_8

    .line 200
    :cond_c
    const/4 v9, 0x0

    .line 201
    :goto_8
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    if-nez v9, :cond_e

    .line 206
    .line 207
    if-ne v3, v7, :cond_d

    .line 208
    .line 209
    goto :goto_9

    .line 210
    :cond_d
    move-object/from16 v9, p5

    .line 211
    .line 212
    goto :goto_a

    .line 213
    :cond_e
    :goto_9
    new-instance v3, Ln1/c;

    .line 214
    .line 215
    new-instance v7, Llk/c;

    .line 216
    .line 217
    move-object/from16 v9, p5

    .line 218
    .line 219
    invoke-direct {v7, v1, v9}, Llk/c;-><init>(Ln1/a;Lk1/g;)V

    .line 220
    .line 221
    .line 222
    invoke-direct {v3, v7}, Ln1/c;-><init>(Llk/c;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    :goto_a
    check-cast v3, Ln1/c;

    .line 229
    .line 230
    shr-int/lit8 v2, v2, 0x3

    .line 231
    .line 232
    and-int/lit8 v7, v2, 0xe

    .line 233
    .line 234
    const/high16 v11, 0x30000

    .line 235
    .line 236
    or-int/2addr v7, v11

    .line 237
    and-int/lit8 v2, v2, 0x70

    .line 238
    .line 239
    or-int/2addr v2, v7

    .line 240
    const v7, 0x30c06c00    # 1.4000534E-9f

    .line 241
    .line 242
    .line 243
    or-int/2addr v2, v7

    .line 244
    shl-int/lit8 v7, v14, 0x3

    .line 245
    .line 246
    and-int/lit8 v7, v7, 0x70

    .line 247
    .line 248
    or-int v14, v17, v7

    .line 249
    .line 250
    move-object v7, v13

    .line 251
    move v13, v2

    .line 252
    move-object v2, v4

    .line 253
    move-object v4, v3

    .line 254
    move-object v3, v5

    .line 255
    move-object v5, v7

    .line 256
    move v7, v0

    .line 257
    move-object v11, v10

    .line 258
    move-object v10, v9

    .line 259
    move-object/from16 v9, p4

    .line 260
    .line 261
    invoke-static/range {v2 .. v14}, Ljp/r1;->a(Lx2/s;Ln1/v;Ln1/c;Lk1/z0;Lg1/j1;ZLe1/j;Lk1/i;Lk1/g;Lay0/k;Ll2/o;II)V

    .line 262
    .line 263
    .line 264
    move-object v4, v5

    .line 265
    move-object v9, v8

    .line 266
    move v8, v7

    .line 267
    move-object v7, v6

    .line 268
    goto :goto_b

    .line 269
    :cond_f
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 270
    .line 271
    .line 272
    move-object/from16 v4, p3

    .line 273
    .line 274
    move-object/from16 v7, p6

    .line 275
    .line 276
    move/from16 v8, p7

    .line 277
    .line 278
    move-object/from16 v9, p8

    .line 279
    .line 280
    :goto_b
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 281
    .line 282
    .line 283
    move-result-object v12

    .line 284
    if-eqz v12, :cond_10

    .line 285
    .line 286
    new-instance v0, Ln1/e;

    .line 287
    .line 288
    move-object/from16 v2, p1

    .line 289
    .line 290
    move-object/from16 v3, p2

    .line 291
    .line 292
    move-object/from16 v5, p4

    .line 293
    .line 294
    move-object/from16 v6, p5

    .line 295
    .line 296
    move-object/from16 v10, p9

    .line 297
    .line 298
    move/from16 v11, p11

    .line 299
    .line 300
    invoke-direct/range {v0 .. v11}, Ln1/e;-><init>(Ln1/a;Lx2/s;Ln1/v;Lk1/z0;Lk1/i;Lk1/g;Lg1/j1;ZLe1/j;Lay0/k;I)V

    .line 301
    .line 302
    .line 303
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 304
    .line 305
    :cond_10
    return-void
.end method

.method public static final b(Ljava/nio/charset/CharsetEncoder;Ljava/lang/CharSequence;II)[B
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "input"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    instance-of v0, p1, Ljava/lang/String;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    const-string v0, "getBytes(...)"

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    move-object v1, p1

    .line 20
    check-cast v1, Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-ne p3, v2, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/nio/charset/CharsetEncoder;->charset()Ljava/nio/charset/Charset;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_0
    check-cast p1, Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {p1, p2, p3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    const-string p2, "substring(...)"

    .line 47
    .line 48
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/nio/charset/CharsetEncoder;->charset()Ljava/nio/charset/Charset;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p1, p0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return-object p0

    .line 63
    :cond_1
    invoke-static {p1, p2, p3}, Ljava/nio/CharBuffer;->wrap(Ljava/lang/CharSequence;II)Ljava/nio/CharBuffer;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {p0, p1}, Ljava/nio/charset/CharsetEncoder;->encode(Ljava/nio/CharBuffer;)Ljava/nio/ByteBuffer;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->hasArray()Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    const/4 p2, 0x0

    .line 76
    if-eqz p1, :cond_2

    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    if-nez p1, :cond_2

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->array()[B

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    array-length p3, p1

    .line 89
    invoke-virtual {p0}, Ljava/nio/Buffer;->remaining()I

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-ne p3, v0, :cond_2

    .line 94
    .line 95
    move-object p2, p1

    .line 96
    :cond_2
    if-nez p2, :cond_3

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/nio/Buffer;->remaining()I

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    new-array p1, p1, [B

    .line 103
    .line 104
    invoke-virtual {p0, p1}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 105
    .line 106
    .line 107
    return-object p1

    .line 108
    :cond_3
    return-object p2
.end method

.method public static final c(Ljava/nio/charset/Charset;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/nio/charset/Charset;->name()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string v0, "name(...)"

    .line 11
    .line 12
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method
