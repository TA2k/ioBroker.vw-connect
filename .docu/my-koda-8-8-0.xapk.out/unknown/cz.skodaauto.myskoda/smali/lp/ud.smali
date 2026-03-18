.class public abstract Llp/ud;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;Ll2/o;II)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p15

    .line 4
    .line 5
    move/from16 v2, p16

    .line 6
    .line 7
    const-string v3, "state"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v14, p14

    .line 13
    .line 14
    check-cast v14, Ll2/t;

    .line 15
    .line 16
    const v3, 0x7f002f44

    .line 17
    .line 18
    .line 19
    invoke-virtual {v14, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v3, v1, 0xe

    .line 23
    .line 24
    if-nez v3, :cond_1

    .line 25
    .line 26
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    const/4 v3, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v3, 0x2

    .line 35
    :goto_0
    or-int/2addr v3, v1

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v3, v1

    .line 38
    :goto_1
    or-int/lit8 v3, v3, 0x30

    .line 39
    .line 40
    and-int/lit16 v4, v1, 0x380

    .line 41
    .line 42
    const/16 v5, 0x80

    .line 43
    .line 44
    const/16 v6, 0x100

    .line 45
    .line 46
    if-nez v4, :cond_3

    .line 47
    .line 48
    move/from16 v4, p2

    .line 49
    .line 50
    invoke-virtual {v14, v4}, Ll2/t;->h(Z)Z

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    if-eqz v7, :cond_2

    .line 55
    .line 56
    move v7, v6

    .line 57
    goto :goto_2

    .line 58
    :cond_2
    move v7, v5

    .line 59
    :goto_2
    or-int/2addr v3, v7

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    move/from16 v4, p2

    .line 62
    .line 63
    :goto_3
    and-int/lit16 v7, v1, 0x1c00

    .line 64
    .line 65
    if-nez v7, :cond_4

    .line 66
    .line 67
    or-int/lit16 v3, v3, 0x400

    .line 68
    .line 69
    :cond_4
    const v7, 0xe000

    .line 70
    .line 71
    .line 72
    and-int/2addr v7, v1

    .line 73
    if-nez v7, :cond_6

    .line 74
    .line 75
    move-object/from16 v7, p4

    .line 76
    .line 77
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v8

    .line 81
    if-eqz v8, :cond_5

    .line 82
    .line 83
    const/16 v8, 0x4000

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_5
    const/16 v8, 0x2000

    .line 87
    .line 88
    :goto_4
    or-int/2addr v3, v8

    .line 89
    goto :goto_5

    .line 90
    :cond_6
    move-object/from16 v7, p4

    .line 91
    .line 92
    :goto_5
    const/high16 v8, 0x70000

    .line 93
    .line 94
    and-int/2addr v8, v1

    .line 95
    if-nez v8, :cond_8

    .line 96
    .line 97
    move-wide/from16 v8, p5

    .line 98
    .line 99
    invoke-virtual {v14, v8, v9}, Ll2/t;->f(J)Z

    .line 100
    .line 101
    .line 102
    move-result v10

    .line 103
    if-eqz v10, :cond_7

    .line 104
    .line 105
    const/high16 v10, 0x20000

    .line 106
    .line 107
    goto :goto_6

    .line 108
    :cond_7
    const/high16 v10, 0x10000

    .line 109
    .line 110
    :goto_6
    or-int/2addr v3, v10

    .line 111
    goto :goto_7

    .line 112
    :cond_8
    move-wide/from16 v8, p5

    .line 113
    .line 114
    :goto_7
    const/high16 v10, 0xd80000

    .line 115
    .line 116
    or-int/2addr v3, v10

    .line 117
    const/high16 v10, 0xe000000

    .line 118
    .line 119
    and-int/2addr v10, v1

    .line 120
    if-nez v10, :cond_a

    .line 121
    .line 122
    move-object/from16 v10, p10

    .line 123
    .line 124
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v11

    .line 128
    if-eqz v11, :cond_9

    .line 129
    .line 130
    const/high16 v11, 0x4000000

    .line 131
    .line 132
    goto :goto_8

    .line 133
    :cond_9
    const/high16 v11, 0x2000000

    .line 134
    .line 135
    :goto_8
    or-int/2addr v3, v11

    .line 136
    goto :goto_9

    .line 137
    :cond_a
    move-object/from16 v10, p10

    .line 138
    .line 139
    :goto_9
    const/high16 v11, 0x30000000

    .line 140
    .line 141
    or-int/2addr v3, v11

    .line 142
    or-int/lit8 v11, v2, 0x6

    .line 143
    .line 144
    and-int/lit8 v12, v2, 0x70

    .line 145
    .line 146
    if-nez v12, :cond_c

    .line 147
    .line 148
    move-object/from16 v12, p12

    .line 149
    .line 150
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v13

    .line 154
    if-eqz v13, :cond_b

    .line 155
    .line 156
    const/16 v13, 0x20

    .line 157
    .line 158
    goto :goto_a

    .line 159
    :cond_b
    const/16 v13, 0x10

    .line 160
    .line 161
    :goto_a
    or-int/2addr v11, v13

    .line 162
    goto :goto_b

    .line 163
    :cond_c
    move-object/from16 v12, p12

    .line 164
    .line 165
    :goto_b
    and-int/lit16 v13, v2, 0x380

    .line 166
    .line 167
    if-nez v13, :cond_e

    .line 168
    .line 169
    move-object/from16 v13, p13

    .line 170
    .line 171
    invoke-virtual {v14, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v15

    .line 175
    if-eqz v15, :cond_d

    .line 176
    .line 177
    move v5, v6

    .line 178
    :cond_d
    or-int/2addr v11, v5

    .line 179
    goto :goto_c

    .line 180
    :cond_e
    move-object/from16 v13, p13

    .line 181
    .line 182
    :goto_c
    const v5, 0x5b6db6db

    .line 183
    .line 184
    .line 185
    and-int/2addr v5, v3

    .line 186
    const v6, 0x12492492

    .line 187
    .line 188
    .line 189
    if-ne v5, v6, :cond_10

    .line 190
    .line 191
    and-int/lit16 v5, v11, 0x2db

    .line 192
    .line 193
    const/16 v6, 0x92

    .line 194
    .line 195
    if-ne v5, v6, :cond_10

    .line 196
    .line 197
    invoke-virtual {v14}, Ll2/t;->A()Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-nez v5, :cond_f

    .line 202
    .line 203
    goto :goto_d

    .line 204
    :cond_f
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 205
    .line 206
    .line 207
    move-object/from16 v2, p1

    .line 208
    .line 209
    move-object/from16 v4, p3

    .line 210
    .line 211
    move-wide/from16 v8, p7

    .line 212
    .line 213
    move/from16 v10, p9

    .line 214
    .line 215
    move-object/from16 v12, p11

    .line 216
    .line 217
    goto :goto_10

    .line 218
    :cond_10
    :goto_d
    invoke-virtual {v14}, Ll2/t;->T()V

    .line 219
    .line 220
    .line 221
    and-int/lit8 v5, v1, 0x1

    .line 222
    .line 223
    if-eqz v5, :cond_12

    .line 224
    .line 225
    invoke-virtual {v14}, Ll2/t;->y()Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_11

    .line 230
    .line 231
    goto :goto_e

    .line 232
    :cond_11
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 233
    .line 234
    .line 235
    and-int/lit16 v3, v3, -0x1c01

    .line 236
    .line 237
    move-object/from16 v17, p1

    .line 238
    .line 239
    move-wide/from16 v7, p7

    .line 240
    .line 241
    move/from16 v9, p9

    .line 242
    .line 243
    move-object/from16 v6, p11

    .line 244
    .line 245
    move v5, v3

    .line 246
    move-object/from16 v3, p3

    .line 247
    .line 248
    goto :goto_f

    .line 249
    :cond_12
    :goto_e
    new-instance v5, Lkn/l0;

    .line 250
    .line 251
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 252
    .line 253
    .line 254
    and-int/lit16 v3, v3, -0x1c01

    .line 255
    .line 256
    sget-wide v15, Le3/s;->b:J

    .line 257
    .line 258
    sget-object v6, Lx2/c;->q:Lx2/h;

    .line 259
    .line 260
    sget-object v17, Lx2/p;->b:Lx2/p;

    .line 261
    .line 262
    const v18, 0x3ee66666    # 0.45f

    .line 263
    .line 264
    .line 265
    move-object v7, v5

    .line 266
    move v5, v3

    .line 267
    move-object v3, v7

    .line 268
    move-wide v7, v15

    .line 269
    move/from16 v9, v18

    .line 270
    .line 271
    :goto_f
    invoke-virtual {v14}, Ll2/t;->r()V

    .line 272
    .line 273
    .line 274
    const v15, 0x7ffffffe

    .line 275
    .line 276
    .line 277
    and-int/2addr v15, v5

    .line 278
    and-int/lit16 v5, v11, 0x3fe

    .line 279
    .line 280
    move v2, v4

    .line 281
    move/from16 v16, v5

    .line 282
    .line 283
    move-object v11, v6

    .line 284
    move-object/from16 v1, v17

    .line 285
    .line 286
    move-object/from16 v4, p4

    .line 287
    .line 288
    move-wide/from16 v5, p5

    .line 289
    .line 290
    invoke-static/range {v0 .. v16}, Llp/sd;->a(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 291
    .line 292
    .line 293
    move-object v2, v1

    .line 294
    move-object v4, v3

    .line 295
    move v10, v9

    .line 296
    move-object v12, v11

    .line 297
    move-wide v8, v7

    .line 298
    :goto_10
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    if-eqz v0, :cond_13

    .line 303
    .line 304
    move-object v1, v0

    .line 305
    new-instance v0, Lkn/a;

    .line 306
    .line 307
    const/16 v17, 0x2

    .line 308
    .line 309
    move/from16 v3, p2

    .line 310
    .line 311
    move-object/from16 v5, p4

    .line 312
    .line 313
    move-wide/from16 v6, p5

    .line 314
    .line 315
    move-object/from16 v11, p10

    .line 316
    .line 317
    move-object/from16 v13, p12

    .line 318
    .line 319
    move-object/from16 v14, p13

    .line 320
    .line 321
    move/from16 v15, p15

    .line 322
    .line 323
    move/from16 v16, p16

    .line 324
    .line 325
    move-object/from16 v19, v1

    .line 326
    .line 327
    move-object/from16 v1, p0

    .line 328
    .line 329
    invoke-direct/range {v0 .. v17}, Lkn/a;-><init>(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;III)V

    .line 330
    .line 331
    .line 332
    move-object/from16 v1, v19

    .line 333
    .line 334
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    .line 335
    .line 336
    :cond_13
    return-void
.end method

.method public static b(Ljava/io/InputStream;Ljava/io/OutputStream;)V
    .locals 3

    .line 1
    const/16 v0, 0x2000

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/io/InputStream;->read([B)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    :goto_0
    if-ltz v1, :cond_0

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p1, v0, v2, v1}, Ljava/io/OutputStream;->write([BII)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ljava/io/InputStream;->read([B)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    return-void
.end method

.method public static final c(Ljava/io/InputStream;)[B
    .locals 3

    .line 1
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    const/16 v1, 0x2000

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/io/InputStream;->available()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-direct {v0, v1}, Ljava/io/ByteArrayOutputStream;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0, v0}, Llp/ud;->b(Ljava/io/InputStream;Ljava/io/OutputStream;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v0, "toByteArray(...)"

    .line 24
    .line 25
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method
