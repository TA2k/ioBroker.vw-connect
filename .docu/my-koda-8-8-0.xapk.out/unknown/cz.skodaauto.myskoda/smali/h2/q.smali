.class public abstract Lh2/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    new-instance v1, Lgz0/e0;

    .line 5
    .line 6
    const/4 v2, 0x4

    .line 7
    invoke-direct {v1, v2}, Lgz0/e0;-><init>(I)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Ll2/e0;

    .line 11
    .line 12
    invoke-direct {v2, v1}, Ll2/e0;-><init>(Lay0/a;)V

    .line 13
    .line 14
    .line 15
    sput-object v2, Lh2/q;->a:Ll2/e0;

    .line 16
    .line 17
    new-instance v1, Lgz0/e0;

    .line 18
    .line 19
    const/4 v2, 0x5

    .line 20
    invoke-direct {v1, v2}, Lgz0/e0;-><init>(I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Ll2/w0;

    .line 24
    .line 25
    invoke-direct {v2, v1}, Ll2/w0;-><init>(Lay0/a;)V

    .line 26
    .line 27
    .line 28
    new-instance v1, Lc1/s;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    const v3, 0x3e19999a    # 0.15f

    .line 32
    .line 33
    .line 34
    const v4, 0x3f4ccccd    # 0.8f

    .line 35
    .line 36
    .line 37
    invoke-direct {v1, v4, v2, v4, v3}, Lc1/s;-><init>(FFFF)V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x4

    .line 41
    int-to-float v1, v1

    .line 42
    sput v1, Lh2/q;->b:F

    .line 43
    .line 44
    sub-float/2addr v0, v1

    .line 45
    sput v0, Lh2/q;->c:F

    .line 46
    .line 47
    return-void
.end method

.method public static final a(Lx2/s;Lt2/b;Lg4/p0;Lg4/p0;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;Ll2/o;II)V
    .locals 21

    .line 1
    move/from16 v10, p10

    .line 2
    .line 3
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 4
    .line 5
    move-object/from16 v1, p9

    .line 6
    .line 7
    check-cast v1, Ll2/t;

    .line 8
    .line 9
    const v2, -0x793953af

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v10, 0x6

    .line 16
    .line 17
    const/4 v4, 0x4

    .line 18
    move-object/from16 v12, p0

    .line 19
    .line 20
    if-nez v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    move v2, v4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v2, 0x2

    .line 31
    :goto_0
    or-int/2addr v2, v10

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v2, v10

    .line 34
    :goto_1
    and-int/lit8 v5, v10, 0x30

    .line 35
    .line 36
    const/16 v6, 0x10

    .line 37
    .line 38
    const/16 v7, 0x20

    .line 39
    .line 40
    move-object/from16 v13, p1

    .line 41
    .line 42
    if-nez v5, :cond_3

    .line 43
    .line 44
    invoke-virtual {v1, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-eqz v5, :cond_2

    .line 49
    .line 50
    move v5, v7

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v5, v6

    .line 53
    :goto_2
    or-int/2addr v2, v5

    .line 54
    :cond_3
    and-int/lit16 v5, v10, 0x180

    .line 55
    .line 56
    move-object/from16 v14, p2

    .line 57
    .line 58
    if-nez v5, :cond_5

    .line 59
    .line 60
    invoke-virtual {v1, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_4

    .line 65
    .line 66
    const/16 v5, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_4
    const/16 v5, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v2, v5

    .line 72
    :cond_5
    and-int/lit16 v5, v10, 0xc00

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    if-nez v5, :cond_7

    .line 76
    .line 77
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-eqz v5, :cond_6

    .line 82
    .line 83
    const/16 v5, 0x800

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_6
    const/16 v5, 0x400

    .line 87
    .line 88
    :goto_4
    or-int/2addr v2, v5

    .line 89
    :cond_7
    and-int/lit16 v5, v10, 0x6000

    .line 90
    .line 91
    move-object/from16 v15, p3

    .line 92
    .line 93
    if-nez v5, :cond_9

    .line 94
    .line 95
    invoke-virtual {v1, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_8

    .line 100
    .line 101
    const/16 v5, 0x4000

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_8
    const/16 v5, 0x2000

    .line 105
    .line 106
    :goto_5
    or-int/2addr v2, v5

    .line 107
    :cond_9
    const/high16 v5, 0x30000

    .line 108
    .line 109
    and-int/2addr v5, v10

    .line 110
    if-nez v5, :cond_b

    .line 111
    .line 112
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    if-eqz v0, :cond_a

    .line 117
    .line 118
    const/high16 v0, 0x20000

    .line 119
    .line 120
    goto :goto_6

    .line 121
    :cond_a
    const/high16 v0, 0x10000

    .line 122
    .line 123
    :goto_6
    or-int/2addr v2, v0

    .line 124
    :cond_b
    const/high16 v0, 0x180000

    .line 125
    .line 126
    and-int/2addr v0, v10

    .line 127
    move-object/from16 v5, p4

    .line 128
    .line 129
    if-nez v0, :cond_d

    .line 130
    .line 131
    invoke-virtual {v1, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-eqz v0, :cond_c

    .line 136
    .line 137
    const/high16 v0, 0x100000

    .line 138
    .line 139
    goto :goto_7

    .line 140
    :cond_c
    const/high16 v0, 0x80000

    .line 141
    .line 142
    :goto_7
    or-int/2addr v2, v0

    .line 143
    :cond_d
    const/high16 v0, 0xc00000

    .line 144
    .line 145
    and-int/2addr v0, v10

    .line 146
    if-nez v0, :cond_f

    .line 147
    .line 148
    move-object/from16 v0, p5

    .line 149
    .line 150
    invoke-virtual {v1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v9

    .line 154
    if-eqz v9, :cond_e

    .line 155
    .line 156
    const/high16 v9, 0x800000

    .line 157
    .line 158
    goto :goto_8

    .line 159
    :cond_e
    const/high16 v9, 0x400000

    .line 160
    .line 161
    :goto_8
    or-int/2addr v2, v9

    .line 162
    goto :goto_9

    .line 163
    :cond_f
    move-object/from16 v0, p5

    .line 164
    .line 165
    :goto_9
    const/high16 v9, 0x6000000

    .line 166
    .line 167
    and-int/2addr v9, v10

    .line 168
    if-nez v9, :cond_11

    .line 169
    .line 170
    move/from16 v9, p6

    .line 171
    .line 172
    invoke-virtual {v1, v9}, Ll2/t;->d(F)Z

    .line 173
    .line 174
    .line 175
    move-result v11

    .line 176
    if-eqz v11, :cond_10

    .line 177
    .line 178
    const/high16 v11, 0x4000000

    .line 179
    .line 180
    goto :goto_a

    .line 181
    :cond_10
    const/high16 v11, 0x2000000

    .line 182
    .line 183
    :goto_a
    or-int/2addr v2, v11

    .line 184
    goto :goto_b

    .line 185
    :cond_11
    move/from16 v9, p6

    .line 186
    .line 187
    :goto_b
    const/high16 v11, 0x30000000

    .line 188
    .line 189
    and-int/2addr v11, v10

    .line 190
    if-nez v11, :cond_13

    .line 191
    .line 192
    move-object/from16 v11, p7

    .line 193
    .line 194
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v16

    .line 198
    if-eqz v16, :cond_12

    .line 199
    .line 200
    const/high16 v16, 0x20000000

    .line 201
    .line 202
    goto :goto_c

    .line 203
    :cond_12
    const/high16 v16, 0x10000000

    .line 204
    .line 205
    :goto_c
    or-int v2, v2, v16

    .line 206
    .line 207
    goto :goto_d

    .line 208
    :cond_13
    move-object/from16 v11, p7

    .line 209
    .line 210
    :goto_d
    and-int/lit8 v16, p11, 0x6

    .line 211
    .line 212
    move-object/from16 v3, p8

    .line 213
    .line 214
    if-nez v16, :cond_15

    .line 215
    .line 216
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v16

    .line 220
    if-eqz v16, :cond_14

    .line 221
    .line 222
    goto :goto_e

    .line 223
    :cond_14
    const/4 v4, 0x2

    .line 224
    :goto_e
    or-int v4, p11, v4

    .line 225
    .line 226
    goto :goto_f

    .line 227
    :cond_15
    move/from16 v4, p11

    .line 228
    .line 229
    :goto_f
    and-int/lit8 v16, p11, 0x30

    .line 230
    .line 231
    if-nez v16, :cond_17

    .line 232
    .line 233
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v8

    .line 237
    if-eqz v8, :cond_16

    .line 238
    .line 239
    move v6, v7

    .line 240
    :cond_16
    or-int/2addr v4, v6

    .line 241
    :cond_17
    const v6, 0x12492493

    .line 242
    .line 243
    .line 244
    and-int/2addr v6, v2

    .line 245
    const v7, 0x12492492

    .line 246
    .line 247
    .line 248
    const/4 v8, 0x0

    .line 249
    const/16 v16, 0x1

    .line 250
    .line 251
    if-ne v6, v7, :cond_19

    .line 252
    .line 253
    and-int/lit8 v4, v4, 0x13

    .line 254
    .line 255
    const/16 v6, 0x12

    .line 256
    .line 257
    if-eq v4, v6, :cond_18

    .line 258
    .line 259
    goto :goto_10

    .line 260
    :cond_18
    move v4, v8

    .line 261
    goto :goto_11

    .line 262
    :cond_19
    :goto_10
    move/from16 v4, v16

    .line 263
    .line 264
    :goto_11
    and-int/lit8 v2, v2, 0x1

    .line 265
    .line 266
    invoke-virtual {v1, v2, v4}, Ll2/t;->O(IZ)Z

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    if-eqz v2, :cond_1a

    .line 271
    .line 272
    new-instance v11, Lh2/t8;

    .line 273
    .line 274
    move-object/from16 v19, p7

    .line 275
    .line 276
    move-object/from16 v17, v0

    .line 277
    .line 278
    move-object/from16 v20, v3

    .line 279
    .line 280
    move-object/from16 v16, v5

    .line 281
    .line 282
    move/from16 v18, v9

    .line 283
    .line 284
    invoke-direct/range {v11 .. v20}, Lh2/t8;-><init>(Lx2/s;Lt2/b;Lg4/p0;Lg4/p0;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;)V

    .line 285
    .line 286
    .line 287
    sget-object v0, Lh2/q;->a:Ll2/e0;

    .line 288
    .line 289
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    check-cast v0, Lh2/m4;

    .line 294
    .line 295
    invoke-virtual {v0, v11, v1, v8}, Lh2/m4;->a(Lh2/t8;Ll2/o;I)V

    .line 296
    .line 297
    .line 298
    goto :goto_12

    .line 299
    :cond_1a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 300
    .line 301
    .line 302
    :goto_12
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    if-eqz v12, :cond_1b

    .line 307
    .line 308
    new-instance v0, Lh2/n;

    .line 309
    .line 310
    move-object/from16 v1, p0

    .line 311
    .line 312
    move-object/from16 v2, p1

    .line 313
    .line 314
    move-object/from16 v3, p2

    .line 315
    .line 316
    move-object/from16 v4, p3

    .line 317
    .line 318
    move-object/from16 v5, p4

    .line 319
    .line 320
    move-object/from16 v6, p5

    .line 321
    .line 322
    move/from16 v7, p6

    .line 323
    .line 324
    move-object/from16 v8, p7

    .line 325
    .line 326
    move-object/from16 v9, p8

    .line 327
    .line 328
    move/from16 v11, p11

    .line 329
    .line 330
    invoke-direct/range {v0 .. v11}, Lh2/n;-><init>(Lx2/s;Lt2/b;Lg4/p0;Lg4/p0;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;II)V

    .line 331
    .line 332
    .line 333
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 334
    .line 335
    :cond_1b
    return-void
.end method

.method public static final b(Lt2/b;Lx2/s;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;Ll2/o;I)V
    .locals 18

    .line 1
    move/from16 v5, p4

    .line 2
    .line 3
    move-object/from16 v15, p7

    .line 4
    .line 5
    check-cast v15, Ll2/t;

    .line 6
    .line 7
    const v0, 0x6a5c1dd0

    .line 8
    .line 9
    .line 10
    invoke-virtual {v15, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    move-object/from16 v2, p1

    .line 14
    .line 15
    invoke-virtual {v15, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/16 v1, 0x10

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/16 v0, 0x20

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v0, v1

    .line 27
    :goto_0
    or-int v0, p8, v0

    .line 28
    .line 29
    move-object/from16 v10, p2

    .line 30
    .line 31
    invoke-virtual {v15, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    const/16 v3, 0x100

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v3, 0x80

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v3

    .line 43
    invoke-virtual {v15, v5}, Ll2/t;->d(F)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_2

    .line 48
    .line 49
    const/16 v3, 0x4000

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v3, 0x2000

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v3

    .line 55
    const/high16 v3, 0x10000

    .line 56
    .line 57
    or-int/2addr v0, v3

    .line 58
    move-object/from16 v7, p6

    .line 59
    .line 60
    invoke-virtual {v15, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    if-eqz v3, :cond_3

    .line 65
    .line 66
    const/high16 v3, 0x100000

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_3
    const/high16 v3, 0x80000

    .line 70
    .line 71
    :goto_3
    or-int/2addr v0, v3

    .line 72
    const/high16 v3, 0xc00000

    .line 73
    .line 74
    or-int/2addr v0, v3

    .line 75
    const v4, 0x492493

    .line 76
    .line 77
    .line 78
    and-int/2addr v4, v0

    .line 79
    const v6, 0x492492

    .line 80
    .line 81
    .line 82
    if-eq v4, v6, :cond_4

    .line 83
    .line 84
    const/4 v4, 0x1

    .line 85
    goto :goto_4

    .line 86
    :cond_4
    const/4 v4, 0x0

    .line 87
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 88
    .line 89
    invoke-virtual {v15, v6, v4}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_9

    .line 94
    .line 95
    invoke-virtual {v15}, Ll2/t;->T()V

    .line 96
    .line 97
    .line 98
    and-int/lit8 v4, p8, 0x1

    .line 99
    .line 100
    const v6, -0x70001

    .line 101
    .line 102
    .line 103
    if-eqz v4, :cond_6

    .line 104
    .line 105
    invoke-virtual {v15}, Ll2/t;->y()Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-eqz v4, :cond_5

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_5
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    and-int/2addr v0, v6

    .line 116
    move-object/from16 v13, p5

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_6
    :goto_5
    sget v4, Lh2/ac;->a:F

    .line 120
    .line 121
    invoke-static {v15}, Li2/a1;->l(Ll2/o;)Lk1/l1;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    sget v8, Lk1/d;->h:I

    .line 126
    .line 127
    or-int/2addr v1, v8

    .line 128
    new-instance v8, Lk1/v0;

    .line 129
    .line 130
    invoke-direct {v8, v4, v1}, Lk1/v0;-><init>(Lk1/q1;I)V

    .line 131
    .line 132
    .line 133
    and-int/2addr v0, v6

    .line 134
    move-object v13, v8

    .line 135
    :goto_6
    invoke-virtual {v15}, Ll2/t;->r()V

    .line 136
    .line 137
    .line 138
    sget-object v1, Lk2/e;->b:Lk2/p0;

    .line 139
    .line 140
    invoke-static {v1, v15}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 141
    .line 142
    .line 143
    move-result-object v8

    .line 144
    sget-object v9, Lg4/p0;->d:Lg4/p0;

    .line 145
    .line 146
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 147
    .line 148
    invoke-static {v5, v1}, Lt4/f;->a(FF)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-nez v1, :cond_8

    .line 153
    .line 154
    const/high16 v1, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 155
    .line 156
    invoke-static {v5, v1}, Lt4/f;->a(FF)Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-eqz v1, :cond_7

    .line 161
    .line 162
    goto :goto_7

    .line 163
    :cond_7
    move v12, v5

    .line 164
    goto :goto_8

    .line 165
    :cond_8
    :goto_7
    sget v1, Lh2/ac;->a:F

    .line 166
    .line 167
    move v12, v1

    .line 168
    :goto_8
    shr-int/lit8 v1, v0, 0x3

    .line 169
    .line 170
    and-int/lit8 v1, v1, 0xe

    .line 171
    .line 172
    const v4, 0x36c30

    .line 173
    .line 174
    .line 175
    or-int/2addr v1, v4

    .line 176
    shl-int/lit8 v4, v0, 0xc

    .line 177
    .line 178
    const/high16 v6, 0x380000

    .line 179
    .line 180
    and-int/2addr v4, v6

    .line 181
    or-int/2addr v1, v4

    .line 182
    or-int v16, v1, v3

    .line 183
    .line 184
    shr-int/lit8 v0, v0, 0x12

    .line 185
    .line 186
    and-int/lit8 v17, v0, 0x7e

    .line 187
    .line 188
    move-object/from16 v11, p3

    .line 189
    .line 190
    move-object v6, v2

    .line 191
    move-object v14, v7

    .line 192
    move-object/from16 v7, p0

    .line 193
    .line 194
    invoke-static/range {v6 .. v17}, Lh2/q;->a(Lx2/s;Lt2/b;Lg4/p0;Lg4/p0;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;Ll2/o;II)V

    .line 195
    .line 196
    .line 197
    move-object v6, v13

    .line 198
    goto :goto_9

    .line 199
    :cond_9
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 200
    .line 201
    .line 202
    move-object/from16 v6, p5

    .line 203
    .line 204
    :goto_9
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 205
    .line 206
    .line 207
    move-result-object v9

    .line 208
    if-eqz v9, :cond_a

    .line 209
    .line 210
    new-instance v0, Lh2/p;

    .line 211
    .line 212
    move-object/from16 v1, p0

    .line 213
    .line 214
    move-object/from16 v2, p1

    .line 215
    .line 216
    move-object/from16 v3, p2

    .line 217
    .line 218
    move-object/from16 v4, p3

    .line 219
    .line 220
    move-object/from16 v7, p6

    .line 221
    .line 222
    move/from16 v8, p8

    .line 223
    .line 224
    invoke-direct/range {v0 .. v8}, Lh2/p;-><init>(Lt2/b;Lx2/s;Lt2/b;Lt2/b;FLk1/q1;Lh2/zb;I)V

    .line 225
    .line 226
    .line 227
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 228
    .line 229
    :cond_a
    return-void
.end method

.method public static final c(Lx2/s;Li2/l0;JJJJLt2/b;Lg4/p0;Lg4/p0;Lay0/a;Lk1/i;Lt2/b;Lt2/b;FLl2/o;I)V
    .locals 35

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-wide/from16 v3, p2

    .line 6
    .line 7
    move-wide/from16 v9, p8

    .line 8
    .line 9
    move-object/from16 v0, p15

    .line 10
    .line 11
    move/from16 v5, p17

    .line 12
    .line 13
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 14
    .line 15
    move-object/from16 v15, p18

    .line 16
    .line 17
    check-cast v15, Ll2/t;

    .line 18
    .line 19
    const v7, 0x788a5dc

    .line 20
    .line 21
    .line 22
    invoke-virtual {v15, v7}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v15, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    if-eqz v7, :cond_0

    .line 30
    .line 31
    const/4 v7, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v7, 0x2

    .line 34
    :goto_0
    or-int v7, p19, v7

    .line 35
    .line 36
    invoke-virtual {v15, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v11

    .line 40
    if-eqz v11, :cond_1

    .line 41
    .line 42
    const/16 v11, 0x20

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    const/16 v11, 0x10

    .line 46
    .line 47
    :goto_1
    or-int/2addr v7, v11

    .line 48
    invoke-virtual {v15, v3, v4}, Ll2/t;->f(J)Z

    .line 49
    .line 50
    .line 51
    move-result v11

    .line 52
    if-eqz v11, :cond_2

    .line 53
    .line 54
    const/16 v11, 0x100

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v11, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v7, v11

    .line 60
    move-wide/from16 v13, p4

    .line 61
    .line 62
    invoke-virtual {v15, v13, v14}, Ll2/t;->f(J)Z

    .line 63
    .line 64
    .line 65
    move-result v16

    .line 66
    if-eqz v16, :cond_3

    .line 67
    .line 68
    const/16 v16, 0x800

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_3
    const/16 v16, 0x400

    .line 72
    .line 73
    :goto_3
    or-int v7, v7, v16

    .line 74
    .line 75
    move-wide/from16 v12, p6

    .line 76
    .line 77
    invoke-virtual {v15, v12, v13}, Ll2/t;->f(J)Z

    .line 78
    .line 79
    .line 80
    move-result v14

    .line 81
    if-eqz v14, :cond_4

    .line 82
    .line 83
    const/16 v14, 0x4000

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_4
    const/16 v14, 0x2000

    .line 87
    .line 88
    :goto_4
    or-int/2addr v7, v14

    .line 89
    invoke-virtual {v15, v9, v10}, Ll2/t;->f(J)Z

    .line 90
    .line 91
    .line 92
    move-result v14

    .line 93
    const/high16 v17, 0x10000

    .line 94
    .line 95
    const/high16 v18, 0x20000

    .line 96
    .line 97
    if-eqz v14, :cond_5

    .line 98
    .line 99
    move/from16 v14, v18

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    move/from16 v14, v17

    .line 103
    .line 104
    :goto_5
    or-int/2addr v7, v14

    .line 105
    move-object/from16 v14, p10

    .line 106
    .line 107
    invoke-virtual {v15, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v19

    .line 111
    if-eqz v19, :cond_6

    .line 112
    .line 113
    const/high16 v19, 0x100000

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_6
    const/high16 v19, 0x80000

    .line 117
    .line 118
    :goto_6
    or-int v7, v7, v19

    .line 119
    .line 120
    move-object/from16 v11, p11

    .line 121
    .line 122
    invoke-virtual {v15, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v20

    .line 126
    const/high16 v21, 0x400000

    .line 127
    .line 128
    if-eqz v20, :cond_7

    .line 129
    .line 130
    const/high16 v20, 0x800000

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_7
    move/from16 v20, v21

    .line 134
    .line 135
    :goto_7
    or-int v7, v7, v20

    .line 136
    .line 137
    const/4 v8, 0x0

    .line 138
    invoke-virtual {v15, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v8

    .line 142
    if-eqz v8, :cond_8

    .line 143
    .line 144
    const/high16 v8, 0x4000000

    .line 145
    .line 146
    goto :goto_8

    .line 147
    :cond_8
    const/high16 v8, 0x2000000

    .line 148
    .line 149
    :goto_8
    or-int/2addr v7, v8

    .line 150
    move-object/from16 v8, p12

    .line 151
    .line 152
    invoke-virtual {v15, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v22

    .line 156
    if-eqz v22, :cond_9

    .line 157
    .line 158
    const/high16 v22, 0x20000000

    .line 159
    .line 160
    goto :goto_9

    .line 161
    :cond_9
    const/high16 v22, 0x10000000

    .line 162
    .line 163
    :goto_9
    or-int v7, v7, v22

    .line 164
    .line 165
    invoke-virtual {v15, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v6

    .line 169
    if-eqz v6, :cond_a

    .line 170
    .line 171
    const/16 v6, 0x100

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_a
    const/16 v6, 0x80

    .line 175
    .line 176
    :goto_a
    const v22, 0x186c36

    .line 177
    .line 178
    .line 179
    or-int v6, v22, v6

    .line 180
    .line 181
    invoke-virtual {v15, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v22

    .line 185
    if-eqz v22, :cond_b

    .line 186
    .line 187
    move/from16 v17, v18

    .line 188
    .line 189
    :cond_b
    or-int v6, v6, v17

    .line 190
    .line 191
    invoke-virtual {v15, v5}, Ll2/t;->d(F)Z

    .line 192
    .line 193
    .line 194
    move-result v17

    .line 195
    if-eqz v17, :cond_c

    .line 196
    .line 197
    const/high16 v21, 0x800000

    .line 198
    .line 199
    :cond_c
    or-int v6, v6, v21

    .line 200
    .line 201
    const v17, 0x12492493

    .line 202
    .line 203
    .line 204
    move/from16 p18, v7

    .line 205
    .line 206
    and-int v7, p18, v17

    .line 207
    .line 208
    const v8, 0x12492492

    .line 209
    .line 210
    .line 211
    if-ne v7, v8, :cond_e

    .line 212
    .line 213
    const v7, 0x492493

    .line 214
    .line 215
    .line 216
    and-int/2addr v7, v6

    .line 217
    const v8, 0x492492

    .line 218
    .line 219
    .line 220
    if-eq v7, v8, :cond_d

    .line 221
    .line 222
    goto :goto_b

    .line 223
    :cond_d
    const/4 v7, 0x0

    .line 224
    goto :goto_c

    .line 225
    :cond_e
    :goto_b
    const/4 v7, 0x1

    .line 226
    :goto_c
    and-int/lit8 v8, p18, 0x1

    .line 227
    .line 228
    invoke-virtual {v15, v8, v7}, Ll2/t;->O(IZ)Z

    .line 229
    .line 230
    .line 231
    move-result v7

    .line 232
    if-eqz v7, :cond_21

    .line 233
    .line 234
    and-int/lit8 v7, p18, 0x70

    .line 235
    .line 236
    const/16 v8, 0x20

    .line 237
    .line 238
    if-eq v7, v8, :cond_f

    .line 239
    .line 240
    const/4 v7, 0x0

    .line 241
    goto :goto_d

    .line 242
    :cond_f
    const/4 v7, 0x1

    .line 243
    :goto_d
    and-int/lit16 v8, v6, 0x380

    .line 244
    .line 245
    const/16 v9, 0x100

    .line 246
    .line 247
    if-ne v8, v9, :cond_10

    .line 248
    .line 249
    const/4 v8, 0x1

    .line 250
    goto :goto_e

    .line 251
    :cond_10
    const/4 v8, 0x0

    .line 252
    :goto_e
    or-int/2addr v7, v8

    .line 253
    const/high16 v8, 0x1c00000

    .line 254
    .line 255
    and-int/2addr v8, v6

    .line 256
    const/high16 v9, 0x800000

    .line 257
    .line 258
    if-ne v8, v9, :cond_11

    .line 259
    .line 260
    const/4 v8, 0x1

    .line 261
    goto :goto_f

    .line 262
    :cond_11
    const/4 v8, 0x0

    .line 263
    :goto_f
    or-int/2addr v7, v8

    .line 264
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v8

    .line 268
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 269
    .line 270
    if-nez v7, :cond_13

    .line 271
    .line 272
    if-ne v8, v9, :cond_12

    .line 273
    .line 274
    goto :goto_10

    .line 275
    :cond_12
    move-object/from16 v7, p14

    .line 276
    .line 277
    goto :goto_11

    .line 278
    :cond_13
    :goto_10
    new-instance v8, Lh2/cc;

    .line 279
    .line 280
    move-object/from16 v7, p14

    .line 281
    .line 282
    invoke-direct {v8, v2, v7, v5}, Lh2/cc;-><init>(Li2/l0;Lk1/i;F)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v15, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 286
    .line 287
    .line 288
    :goto_11
    check-cast v8, Lh2/cc;

    .line 289
    .line 290
    iget-wide v10, v15, Ll2/t;->T:J

    .line 291
    .line 292
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 293
    .line 294
    .line 295
    move-result v10

    .line 296
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 297
    .line 298
    .line 299
    move-result-object v11

    .line 300
    invoke-static {v15, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 305
    .line 306
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 307
    .line 308
    .line 309
    sget-object v1, Lv3/j;->b:Lv3/i;

    .line 310
    .line 311
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 312
    .line 313
    .line 314
    iget-boolean v5, v15, Ll2/t;->S:Z

    .line 315
    .line 316
    if-eqz v5, :cond_14

    .line 317
    .line 318
    invoke-virtual {v15, v1}, Ll2/t;->l(Lay0/a;)V

    .line 319
    .line 320
    .line 321
    goto :goto_12

    .line 322
    :cond_14
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 323
    .line 324
    .line 325
    :goto_12
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 326
    .line 327
    invoke-static {v5, v8, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 328
    .line 329
    .line 330
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 331
    .line 332
    invoke-static {v8, v11, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 333
    .line 334
    .line 335
    sget-object v11, Lv3/j;->j:Lv3/h;

    .line 336
    .line 337
    move/from16 v16, v6

    .line 338
    .line 339
    iget-boolean v6, v15, Ll2/t;->S:Z

    .line 340
    .line 341
    if-nez v6, :cond_15

    .line 342
    .line 343
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v6

    .line 347
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 348
    .line 349
    .line 350
    move-result-object v7

    .line 351
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 352
    .line 353
    .line 354
    move-result v6

    .line 355
    if-nez v6, :cond_16

    .line 356
    .line 357
    :cond_15
    invoke-static {v10, v15, v10, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 358
    .line 359
    .line 360
    :cond_16
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 361
    .line 362
    invoke-static {v6, v2, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 363
    .line 364
    .line 365
    const-string v2, "navigationIcon"

    .line 366
    .line 367
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 368
    .line 369
    invoke-static {v7, v2}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 370
    .line 371
    .line 372
    move-result-object v22

    .line 373
    const/16 v26, 0x0

    .line 374
    .line 375
    const/16 v27, 0xe

    .line 376
    .line 377
    sget v31, Lh2/q;->b:F

    .line 378
    .line 379
    const/16 v24, 0x0

    .line 380
    .line 381
    const/16 v25, 0x0

    .line 382
    .line 383
    move/from16 v23, v31

    .line 384
    .line 385
    invoke-static/range {v22 .. v27}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    move/from16 v10, v23

    .line 390
    .line 391
    sget-object v12, Lx2/c;->d:Lx2/j;

    .line 392
    .line 393
    const/4 v13, 0x0

    .line 394
    invoke-static {v12, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 395
    .line 396
    .line 397
    move-result-object v14

    .line 398
    move-object/from16 v19, v12

    .line 399
    .line 400
    iget-wide v12, v15, Ll2/t;->T:J

    .line 401
    .line 402
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 403
    .line 404
    .line 405
    move-result v12

    .line 406
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 407
    .line 408
    .line 409
    move-result-object v13

    .line 410
    invoke-static {v15, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 411
    .line 412
    .line 413
    move-result-object v2

    .line 414
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 415
    .line 416
    .line 417
    move-object/from16 v20, v9

    .line 418
    .line 419
    iget-boolean v9, v15, Ll2/t;->S:Z

    .line 420
    .line 421
    if-eqz v9, :cond_17

    .line 422
    .line 423
    invoke-virtual {v15, v1}, Ll2/t;->l(Lay0/a;)V

    .line 424
    .line 425
    .line 426
    goto :goto_13

    .line 427
    :cond_17
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 428
    .line 429
    .line 430
    :goto_13
    invoke-static {v5, v14, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 431
    .line 432
    .line 433
    invoke-static {v8, v13, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 434
    .line 435
    .line 436
    iget-boolean v9, v15, Ll2/t;->S:Z

    .line 437
    .line 438
    if-nez v9, :cond_18

    .line 439
    .line 440
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v9

    .line 444
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 445
    .line 446
    .line 447
    move-result-object v13

    .line 448
    invoke-static {v9, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 449
    .line 450
    .line 451
    move-result v9

    .line 452
    if-nez v9, :cond_19

    .line 453
    .line 454
    :cond_18
    invoke-static {v12, v15, v12, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 455
    .line 456
    .line 457
    :cond_19
    invoke-static {v6, v2, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 458
    .line 459
    .line 460
    sget-object v2, Lh2/p1;->a:Ll2/e0;

    .line 461
    .line 462
    invoke-static {v3, v4, v2}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 463
    .line 464
    .line 465
    move-result-object v9

    .line 466
    shr-int/lit8 v12, v16, 0xc

    .line 467
    .line 468
    and-int/lit8 v12, v12, 0x70

    .line 469
    .line 470
    const/16 v13, 0x8

    .line 471
    .line 472
    or-int/2addr v12, v13

    .line 473
    invoke-static {v9, v0, v15, v12}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 474
    .line 475
    .line 476
    const/4 v9, 0x1

    .line 477
    invoke-virtual {v15, v9}, Ll2/t;->q(Z)V

    .line 478
    .line 479
    .line 480
    const v9, -0x510b6613

    .line 481
    .line 482
    .line 483
    invoke-virtual {v15, v9}, Ll2/t;->Y(I)V

    .line 484
    .line 485
    .line 486
    const-string v9, "title"

    .line 487
    .line 488
    invoke-static {v7, v9}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 489
    .line 490
    .line 491
    move-result-object v9

    .line 492
    const/4 v12, 0x0

    .line 493
    const/4 v13, 0x2

    .line 494
    invoke-static {v9, v10, v12, v13}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 495
    .line 496
    .line 497
    move-result-object v9

    .line 498
    const v12, 0x1e6b2c0d

    .line 499
    .line 500
    .line 501
    invoke-virtual {v15, v12}, Ll2/t;->Y(I)V

    .line 502
    .line 503
    .line 504
    const/4 v13, 0x0

    .line 505
    invoke-virtual {v15, v13}, Ll2/t;->q(Z)V

    .line 506
    .line 507
    .line 508
    invoke-interface {v9, v7}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 509
    .line 510
    .line 511
    move-result-object v9

    .line 512
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v12

    .line 516
    move-object/from16 v13, v20

    .line 517
    .line 518
    if-ne v12, v13, :cond_1a

    .line 519
    .line 520
    new-instance v12, Laj0/c;

    .line 521
    .line 522
    const/16 v13, 0x19

    .line 523
    .line 524
    move-object/from16 v14, p13

    .line 525
    .line 526
    invoke-direct {v12, v14, v13}, Laj0/c;-><init>(Lay0/a;I)V

    .line 527
    .line 528
    .line 529
    invoke-virtual {v15, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 530
    .line 531
    .line 532
    goto :goto_14

    .line 533
    :cond_1a
    move-object/from16 v14, p13

    .line 534
    .line 535
    :goto_14
    check-cast v12, Lay0/k;

    .line 536
    .line 537
    invoke-static {v9, v12}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 538
    .line 539
    .line 540
    move-result-object v9

    .line 541
    move-object/from16 v12, v19

    .line 542
    .line 543
    const/4 v13, 0x0

    .line 544
    invoke-static {v12, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    iget-wide v3, v15, Ll2/t;->T:J

    .line 549
    .line 550
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 551
    .line 552
    .line 553
    move-result v3

    .line 554
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 555
    .line 556
    .line 557
    move-result-object v4

    .line 558
    invoke-static {v15, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 559
    .line 560
    .line 561
    move-result-object v9

    .line 562
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 563
    .line 564
    .line 565
    iget-boolean v13, v15, Ll2/t;->S:Z

    .line 566
    .line 567
    if-eqz v13, :cond_1b

    .line 568
    .line 569
    invoke-virtual {v15, v1}, Ll2/t;->l(Lay0/a;)V

    .line 570
    .line 571
    .line 572
    goto :goto_15

    .line 573
    :cond_1b
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 574
    .line 575
    .line 576
    :goto_15
    invoke-static {v5, v0, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 577
    .line 578
    .line 579
    invoke-static {v8, v4, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 580
    .line 581
    .line 582
    iget-boolean v0, v15, Ll2/t;->S:Z

    .line 583
    .line 584
    if-nez v0, :cond_1c

    .line 585
    .line 586
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object v0

    .line 590
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 591
    .line 592
    .line 593
    move-result-object v4

    .line 594
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 595
    .line 596
    .line 597
    move-result v0

    .line 598
    if-nez v0, :cond_1d

    .line 599
    .line 600
    :cond_1c
    invoke-static {v3, v15, v3, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 601
    .line 602
    .line 603
    :cond_1d
    invoke-static {v6, v9, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 604
    .line 605
    .line 606
    shr-int/lit8 v0, p18, 0x9

    .line 607
    .line 608
    and-int/lit8 v0, v0, 0xe

    .line 609
    .line 610
    shr-int/lit8 v3, p18, 0x12

    .line 611
    .line 612
    and-int/lit8 v3, v3, 0x70

    .line 613
    .line 614
    or-int/2addr v0, v3

    .line 615
    shr-int/lit8 v3, p18, 0xc

    .line 616
    .line 617
    and-int/lit16 v3, v3, 0x380

    .line 618
    .line 619
    or-int v16, v0, v3

    .line 620
    .line 621
    move-object/from16 v14, p10

    .line 622
    .line 623
    move-object/from16 v13, p11

    .line 624
    .line 625
    move-object v0, v11

    .line 626
    move-object v3, v12

    .line 627
    move-wide/from16 v11, p4

    .line 628
    .line 629
    invoke-static/range {v11 .. v16}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 630
    .line 631
    .line 632
    const/4 v9, 0x1

    .line 633
    invoke-virtual {v15, v9}, Ll2/t;->q(Z)V

    .line 634
    .line 635
    .line 636
    const/4 v13, 0x0

    .line 637
    invoke-virtual {v15, v13}, Ll2/t;->q(Z)V

    .line 638
    .line 639
    .line 640
    const-string v4, "actionIcons"

    .line 641
    .line 642
    invoke-static {v7, v4}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 643
    .line 644
    .line 645
    move-result-object v28

    .line 646
    const/16 v32, 0x0

    .line 647
    .line 648
    const/16 v33, 0xb

    .line 649
    .line 650
    const/16 v29, 0x0

    .line 651
    .line 652
    const/16 v30, 0x0

    .line 653
    .line 654
    move/from16 v31, v10

    .line 655
    .line 656
    invoke-static/range {v28 .. v33}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 657
    .line 658
    .line 659
    move-result-object v4

    .line 660
    invoke-static {v3, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 661
    .line 662
    .line 663
    move-result-object v3

    .line 664
    iget-wide v9, v15, Ll2/t;->T:J

    .line 665
    .line 666
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 667
    .line 668
    .line 669
    move-result v7

    .line 670
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 671
    .line 672
    .line 673
    move-result-object v9

    .line 674
    invoke-static {v15, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 675
    .line 676
    .line 677
    move-result-object v4

    .line 678
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 679
    .line 680
    .line 681
    iget-boolean v10, v15, Ll2/t;->S:Z

    .line 682
    .line 683
    if-eqz v10, :cond_1e

    .line 684
    .line 685
    invoke-virtual {v15, v1}, Ll2/t;->l(Lay0/a;)V

    .line 686
    .line 687
    .line 688
    goto :goto_16

    .line 689
    :cond_1e
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 690
    .line 691
    .line 692
    :goto_16
    invoke-static {v5, v3, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 693
    .line 694
    .line 695
    invoke-static {v8, v9, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 696
    .line 697
    .line 698
    iget-boolean v1, v15, Ll2/t;->S:Z

    .line 699
    .line 700
    if-nez v1, :cond_1f

    .line 701
    .line 702
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 703
    .line 704
    .line 705
    move-result-object v1

    .line 706
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 707
    .line 708
    .line 709
    move-result-object v3

    .line 710
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 711
    .line 712
    .line 713
    move-result v1

    .line 714
    if-nez v1, :cond_20

    .line 715
    .line 716
    :cond_1f
    invoke-static {v7, v15, v7, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 717
    .line 718
    .line 719
    :cond_20
    invoke-static {v6, v4, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 720
    .line 721
    .line 722
    new-instance v0, Le3/s;

    .line 723
    .line 724
    move-wide/from16 v9, p8

    .line 725
    .line 726
    invoke-direct {v0, v9, v10}, Le3/s;-><init>(J)V

    .line 727
    .line 728
    .line 729
    invoke-virtual {v2, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 730
    .line 731
    .line 732
    move-result-object v0

    .line 733
    const/16 v1, 0x38

    .line 734
    .line 735
    move-object/from16 v2, p16

    .line 736
    .line 737
    invoke-static {v0, v2, v15, v1}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 738
    .line 739
    .line 740
    const/4 v0, 0x1

    .line 741
    invoke-virtual {v15, v0}, Ll2/t;->q(Z)V

    .line 742
    .line 743
    .line 744
    invoke-virtual {v15, v0}, Ll2/t;->q(Z)V

    .line 745
    .line 746
    .line 747
    goto :goto_17

    .line 748
    :cond_21
    move-wide/from16 v9, p8

    .line 749
    .line 750
    move-object/from16 v2, p16

    .line 751
    .line 752
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 753
    .line 754
    .line 755
    :goto_17
    invoke-virtual {v15}, Ll2/t;->s()Ll2/u1;

    .line 756
    .line 757
    .line 758
    move-result-object v0

    .line 759
    if-eqz v0, :cond_22

    .line 760
    .line 761
    move-object v1, v0

    .line 762
    new-instance v0, Lh2/o;

    .line 763
    .line 764
    move-wide/from16 v3, p2

    .line 765
    .line 766
    move-wide/from16 v5, p4

    .line 767
    .line 768
    move-wide/from16 v7, p6

    .line 769
    .line 770
    move-object/from16 v11, p10

    .line 771
    .line 772
    move-object/from16 v12, p11

    .line 773
    .line 774
    move-object/from16 v13, p12

    .line 775
    .line 776
    move-object/from16 v14, p13

    .line 777
    .line 778
    move-object/from16 v15, p14

    .line 779
    .line 780
    move-object/from16 v16, p15

    .line 781
    .line 782
    move/from16 v18, p17

    .line 783
    .line 784
    move/from16 v19, p19

    .line 785
    .line 786
    move-object/from16 v34, v1

    .line 787
    .line 788
    move-object/from16 v17, v2

    .line 789
    .line 790
    move-object/from16 v1, p0

    .line 791
    .line 792
    move-object/from16 v2, p1

    .line 793
    .line 794
    invoke-direct/range {v0 .. v19}, Lh2/o;-><init>(Lx2/s;Li2/l0;JJJJLt2/b;Lg4/p0;Lg4/p0;Lay0/a;Lk1/i;Lt2/b;Lt2/b;FI)V

    .line 795
    .line 796
    .line 797
    move-object/from16 v1, v34

    .line 798
    .line 799
    iput-object v0, v1, Ll2/u1;->d:Lay0/n;

    .line 800
    .line 801
    :cond_22
    return-void
.end method
