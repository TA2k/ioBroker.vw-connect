.class public abstract Li40/o3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F

.field public static final f:F

.field public static final g:F

.field public static final h:F

.field public static final i:F

.field public static final j:F

.field public static final k:F

.field public static final l:F

.field public static final m:F

.field public static final n:F

.field public static final o:F

.field public static final p:F


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0xc

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li40/o3;->a:F

    .line 5
    .line 6
    const/16 v1, 0x14

    .line 7
    .line 8
    int-to-float v1, v1

    .line 9
    sput v1, Li40/o3;->b:F

    .line 10
    .line 11
    const/16 v1, 0xf0

    .line 12
    .line 13
    int-to-float v1, v1

    .line 14
    sput v1, Li40/o3;->c:F

    .line 15
    .line 16
    const/16 v1, 0xa0

    .line 17
    .line 18
    int-to-float v1, v1

    .line 19
    sput v1, Li40/o3;->d:F

    .line 20
    .line 21
    const/16 v1, 0x44

    .line 22
    .line 23
    int-to-float v1, v1

    .line 24
    sput v1, Li40/o3;->e:F

    .line 25
    .line 26
    const/16 v1, 0xa

    .line 27
    .line 28
    int-to-float v1, v1

    .line 29
    sput v1, Li40/o3;->f:F

    .line 30
    .line 31
    const/16 v2, 0x10

    .line 32
    .line 33
    int-to-float v2, v2

    .line 34
    sput v2, Li40/o3;->g:F

    .line 35
    .line 36
    const/16 v2, 0x72

    .line 37
    .line 38
    int-to-float v2, v2

    .line 39
    sput v2, Li40/o3;->h:F

    .line 40
    .line 41
    const/16 v2, 0x4c

    .line 42
    .line 43
    int-to-float v2, v2

    .line 44
    sput v2, Li40/o3;->i:F

    .line 45
    .line 46
    sput v1, Li40/o3;->j:F

    .line 47
    .line 48
    const/16 v1, 0x22

    .line 49
    .line 50
    int-to-float v1, v1

    .line 51
    sput v1, Li40/o3;->k:F

    .line 52
    .line 53
    const/4 v1, 0x5

    .line 54
    int-to-float v1, v1

    .line 55
    sput v1, Li40/o3;->l:F

    .line 56
    .line 57
    const/16 v1, 0x8

    .line 58
    .line 59
    int-to-float v1, v1

    .line 60
    sput v1, Li40/o3;->m:F

    .line 61
    .line 62
    const/16 v1, 0xd4

    .line 63
    .line 64
    int-to-float v1, v1

    .line 65
    sput v1, Li40/o3;->n:F

    .line 66
    .line 67
    sput v0, Li40/o3;->o:F

    .line 68
    .line 69
    const/4 v0, 0x4

    .line 70
    int-to-float v0, v0

    .line 71
    sput v0, Li40/o3;->p:F

    .line 72
    .line 73
    return-void
.end method

.method public static final a(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move/from16 v9, p9

    .line 6
    .line 7
    move-object/from16 v14, p8

    .line 8
    .line 9
    check-cast v14, Ll2/t;

    .line 10
    .line 11
    const v0, 0x720285aa

    .line 12
    .line 13
    .line 14
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v9, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v9

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v9

    .line 33
    :goto_1
    and-int/lit8 v3, v9, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_3

    .line 36
    .line 37
    sget v3, Li40/o3;->a:F

    .line 38
    .line 39
    invoke-virtual {v14, v3}, Ll2/t;->d(F)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_2

    .line 44
    .line 45
    const/16 v3, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v3, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v3

    .line 51
    :cond_3
    and-int/lit16 v3, v9, 0x180

    .line 52
    .line 53
    if-nez v3, :cond_5

    .line 54
    .line 55
    invoke-virtual {v14, v2}, Ll2/t;->d(F)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_4

    .line 60
    .line 61
    const/16 v3, 0x100

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_4
    const/16 v3, 0x80

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v3

    .line 67
    :cond_5
    and-int/lit16 v3, v9, 0xc00

    .line 68
    .line 69
    if-nez v3, :cond_7

    .line 70
    .line 71
    move/from16 v3, p2

    .line 72
    .line 73
    invoke-virtual {v14, v3}, Ll2/t;->d(F)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_6

    .line 78
    .line 79
    const/16 v4, 0x800

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_6
    const/16 v4, 0x400

    .line 83
    .line 84
    :goto_4
    or-int/2addr v0, v4

    .line 85
    goto :goto_5

    .line 86
    :cond_7
    move/from16 v3, p2

    .line 87
    .line 88
    :goto_5
    and-int/lit16 v4, v9, 0x6000

    .line 89
    .line 90
    if-nez v4, :cond_9

    .line 91
    .line 92
    move/from16 v4, p3

    .line 93
    .line 94
    invoke-virtual {v14, v4}, Ll2/t;->d(F)Z

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    if-eqz v5, :cond_8

    .line 99
    .line 100
    const/16 v5, 0x4000

    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_8
    const/16 v5, 0x2000

    .line 104
    .line 105
    :goto_6
    or-int/2addr v0, v5

    .line 106
    goto :goto_7

    .line 107
    :cond_9
    move/from16 v4, p3

    .line 108
    .line 109
    :goto_7
    const/high16 v5, 0x30000

    .line 110
    .line 111
    and-int/2addr v5, v9

    .line 112
    if-nez v5, :cond_b

    .line 113
    .line 114
    move/from16 v5, p4

    .line 115
    .line 116
    invoke-virtual {v14, v5}, Ll2/t;->d(F)Z

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    if-eqz v6, :cond_a

    .line 121
    .line 122
    const/high16 v6, 0x20000

    .line 123
    .line 124
    goto :goto_8

    .line 125
    :cond_a
    const/high16 v6, 0x10000

    .line 126
    .line 127
    :goto_8
    or-int/2addr v0, v6

    .line 128
    goto :goto_9

    .line 129
    :cond_b
    move/from16 v5, p4

    .line 130
    .line 131
    :goto_9
    const/high16 v6, 0x180000

    .line 132
    .line 133
    and-int/2addr v6, v9

    .line 134
    if-nez v6, :cond_d

    .line 135
    .line 136
    move-object/from16 v6, p5

    .line 137
    .line 138
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    if-eqz v7, :cond_c

    .line 143
    .line 144
    const/high16 v7, 0x100000

    .line 145
    .line 146
    goto :goto_a

    .line 147
    :cond_c
    const/high16 v7, 0x80000

    .line 148
    .line 149
    :goto_a
    or-int/2addr v0, v7

    .line 150
    goto :goto_b

    .line 151
    :cond_d
    move-object/from16 v6, p5

    .line 152
    .line 153
    :goto_b
    const/high16 v7, 0xc00000

    .line 154
    .line 155
    and-int/2addr v7, v9

    .line 156
    if-nez v7, :cond_f

    .line 157
    .line 158
    move-object/from16 v7, p6

    .line 159
    .line 160
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-eqz v8, :cond_e

    .line 165
    .line 166
    const/high16 v8, 0x800000

    .line 167
    .line 168
    goto :goto_c

    .line 169
    :cond_e
    const/high16 v8, 0x400000

    .line 170
    .line 171
    :goto_c
    or-int/2addr v0, v8

    .line 172
    goto :goto_d

    .line 173
    :cond_f
    move-object/from16 v7, p6

    .line 174
    .line 175
    :goto_d
    const/high16 v8, 0x6000000

    .line 176
    .line 177
    and-int/2addr v8, v9

    .line 178
    if-nez v8, :cond_11

    .line 179
    .line 180
    move-object/from16 v8, p7

    .line 181
    .line 182
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v10

    .line 186
    if-eqz v10, :cond_10

    .line 187
    .line 188
    const/high16 v10, 0x4000000

    .line 189
    .line 190
    goto :goto_e

    .line 191
    :cond_10
    const/high16 v10, 0x2000000

    .line 192
    .line 193
    :goto_e
    or-int/2addr v0, v10

    .line 194
    goto :goto_f

    .line 195
    :cond_11
    move-object/from16 v8, p7

    .line 196
    .line 197
    :goto_f
    const v10, 0x2492493

    .line 198
    .line 199
    .line 200
    and-int/2addr v10, v0

    .line 201
    const v11, 0x2492492

    .line 202
    .line 203
    .line 204
    const/4 v12, 0x1

    .line 205
    if-eq v10, v11, :cond_12

    .line 206
    .line 207
    move v10, v12

    .line 208
    goto :goto_10

    .line 209
    :cond_12
    const/4 v10, 0x0

    .line 210
    :goto_10
    and-int/2addr v0, v12

    .line 211
    invoke-virtual {v14, v0, v10}, Ll2/t;->O(IZ)Z

    .line 212
    .line 213
    .line 214
    move-result v0

    .line 215
    if-eqz v0, :cond_13

    .line 216
    .line 217
    new-instance v0, Li40/d;

    .line 218
    .line 219
    invoke-direct {v0, v2}, Li40/d;-><init>(F)V

    .line 220
    .line 221
    .line 222
    sget-wide v10, Le3/s;->e:J

    .line 223
    .line 224
    const/high16 v12, 0x3f400000    # 0.75f

    .line 225
    .line 226
    invoke-static {v10, v11, v12}, Le3/s;->b(JF)J

    .line 227
    .line 228
    .line 229
    move-result-wide v18

    .line 230
    const-wide/high16 v10, 0x3fe0000000000000L    # 0.5

    .line 231
    .line 232
    double-to-float v10, v10

    .line 233
    const-string v11, "$this$innerShadow"

    .line 234
    .line 235
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    new-instance v15, Lxf0/k2;

    .line 239
    .line 240
    move/from16 v20, v10

    .line 241
    .line 242
    move/from16 v21, v10

    .line 243
    .line 244
    move/from16 v22, v10

    .line 245
    .line 246
    move-object/from16 v17, v0

    .line 247
    .line 248
    move/from16 v16, v10

    .line 249
    .line 250
    invoke-direct/range {v15 .. v22}, Lxf0/k2;-><init>(FLi40/d;JFFF)V

    .line 251
    .line 252
    .line 253
    invoke-static {v1, v15}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    invoke-static {v10, v0}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 258
    .line 259
    .line 260
    move-result-object v10

    .line 261
    new-instance v15, Li40/m3;

    .line 262
    .line 263
    move/from16 v17, v3

    .line 264
    .line 265
    move/from16 v19, v4

    .line 266
    .line 267
    move/from16 v18, v5

    .line 268
    .line 269
    move-object/from16 v21, v6

    .line 270
    .line 271
    move-object/from16 v16, v7

    .line 272
    .line 273
    move-object/from16 v20, v8

    .line 274
    .line 275
    invoke-direct/range {v15 .. v21}, Li40/m3;-><init>(Landroid/net/Uri;FFFLjava/lang/String;Lg4/p0;)V

    .line 276
    .line 277
    .line 278
    const v0, -0x2c041221

    .line 279
    .line 280
    .line 281
    invoke-static {v0, v14, v15}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 282
    .line 283
    .line 284
    move-result-object v13

    .line 285
    const/16 v15, 0xc00

    .line 286
    .line 287
    const/16 v16, 0x6

    .line 288
    .line 289
    const/4 v11, 0x0

    .line 290
    const/4 v12, 0x0

    .line 291
    invoke-static/range {v10 .. v16}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 292
    .line 293
    .line 294
    goto :goto_11

    .line 295
    :cond_13
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 296
    .line 297
    .line 298
    :goto_11
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 299
    .line 300
    .line 301
    move-result-object v10

    .line 302
    if-eqz v10, :cond_14

    .line 303
    .line 304
    new-instance v0, Li40/n3;

    .line 305
    .line 306
    move/from16 v3, p2

    .line 307
    .line 308
    move/from16 v4, p3

    .line 309
    .line 310
    move/from16 v5, p4

    .line 311
    .line 312
    move-object/from16 v6, p5

    .line 313
    .line 314
    move-object/from16 v7, p6

    .line 315
    .line 316
    move-object/from16 v8, p7

    .line 317
    .line 318
    invoke-direct/range {v0 .. v9}, Li40/n3;-><init>(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;I)V

    .line 319
    .line 320
    .line 321
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 322
    .line 323
    :cond_14
    return-void
.end method

.method public static final b(Lx2/s;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v8, p3

    .line 2
    check-cast v8, Ll2/t;

    .line 3
    .line 4
    const v0, -0x1952aef5

    .line 5
    .line 6
    .line 7
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    or-int/lit8 v0, p4, 0x6

    .line 11
    .line 12
    invoke-virtual {v8, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    const/16 v1, 0x20

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/16 v1, 0x10

    .line 22
    .line 23
    :goto_0
    or-int/2addr v0, v1

    .line 24
    invoke-virtual {v8, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const/16 v1, 0x100

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/16 v1, 0x80

    .line 34
    .line 35
    :goto_1
    or-int/2addr v0, v1

    .line 36
    and-int/lit16 v1, v0, 0x93

    .line 37
    .line 38
    const/16 v2, 0x92

    .line 39
    .line 40
    if-eq v1, v2, :cond_2

    .line 41
    .line 42
    const/4 v1, 0x1

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/4 v1, 0x0

    .line 45
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 46
    .line 47
    invoke-virtual {v8, v2, v1}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_3

    .line 52
    .line 53
    sget v1, Li40/o3;->c:F

    .line 54
    .line 55
    sget v2, Li40/o3;->d:F

    .line 56
    .line 57
    invoke-static {v1, v2}, Lkp/c9;->a(FF)J

    .line 58
    .line 59
    .line 60
    move-result-wide v1

    .line 61
    sget-object v5, Landroidx/compose/foundation/layout/d;->a:Landroidx/compose/foundation/layout/FillElement;

    .line 62
    .line 63
    invoke-static {v1, v2}, Lt4/h;->c(J)F

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    invoke-static {v1, v2}, Lt4/h;->b(J)F

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 72
    .line 73
    invoke-static {v10, v5, v1}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 78
    .line 79
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    check-cast v2, Lj91/f;

    .line 84
    .line 85
    invoke-virtual {v2}, Lj91/f;->i()Lg4/p0;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    shl-int/lit8 v0, v0, 0x12

    .line 90
    .line 91
    const/high16 v2, 0x1c00000

    .line 92
    .line 93
    and-int/2addr v2, v0

    .line 94
    const v6, 0x36db0

    .line 95
    .line 96
    .line 97
    or-int/2addr v2, v6

    .line 98
    const/high16 v6, 0xe000000

    .line 99
    .line 100
    and-int/2addr v0, v6

    .line 101
    or-int v9, v2, v0

    .line 102
    .line 103
    move-object v0, v1

    .line 104
    sget v1, Li40/o3;->b:F

    .line 105
    .line 106
    sget v2, Li40/o3;->g:F

    .line 107
    .line 108
    sget v3, Li40/o3;->f:F

    .line 109
    .line 110
    sget v4, Li40/o3;->e:F

    .line 111
    .line 112
    move-object v6, p1

    .line 113
    move-object v7, p2

    .line 114
    invoke-static/range {v0 .. v9}, Li40/o3;->a(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V

    .line 115
    .line 116
    .line 117
    move-object v2, v10

    .line 118
    goto :goto_3

    .line 119
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 120
    .line 121
    .line 122
    move-object v2, p0

    .line 123
    :goto_3
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    if-eqz v0, :cond_4

    .line 128
    .line 129
    new-instance v1, Li40/l3;

    .line 130
    .line 131
    const/4 v6, 0x0

    .line 132
    move-object v3, p1

    .line 133
    move-object v4, p2

    .line 134
    move v5, p4

    .line 135
    invoke-direct/range {v1 .. v6}, Li40/l3;-><init>(Lx2/s;Landroid/net/Uri;Ljava/lang/String;II)V

    .line 136
    .line 137
    .line 138
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_4
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x58ef262b

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Ll2/t;->O(IZ)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    invoke-static {p0}, Lkp/k;->c(Ll2/o;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    const-wide v0, 0xff141e1cL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const-wide v0, 0xffb2dfc5L

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    :goto_1
    sget v2, Li40/o3;->n:F

    .line 48
    .line 49
    sget v3, Li40/o3;->o:F

    .line 50
    .line 51
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 52
    .line 53
    invoke-static {v4, v2, v3}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    sget v3, Li40/o3;->p:F

    .line 58
    .line 59
    invoke-static {v2, v3}, Ljp/b2;->a(Lx2/s;F)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v0, v1}, Ll2/t;->f(J)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    if-nez v3, :cond_2

    .line 72
    .line 73
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 74
    .line 75
    if-ne v4, v3, :cond_3

    .line 76
    .line 77
    :cond_2
    new-instance v4, Le81/e;

    .line 78
    .line 79
    const/4 v3, 0x3

    .line 80
    invoke-direct {v4, v0, v1, v3}, Le81/e;-><init>(JI)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_3
    check-cast v4, Lay0/k;

    .line 87
    .line 88
    const/4 v0, 0x6

    .line 89
    invoke-static {v2, v4, p0, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 94
    .line 95
    .line 96
    :goto_2
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-eqz p0, :cond_5

    .line 101
    .line 102
    new-instance v0, Li40/j2;

    .line 103
    .line 104
    const/16 v1, 0xb

    .line 105
    .line 106
    invoke-direct {v0, p1, v1}, Li40/j2;-><init>(II)V

    .line 107
    .line 108
    .line 109
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 110
    .line 111
    :cond_5
    return-void
.end method

.method public static final d(Lx2/s;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v8, p3

    .line 2
    check-cast v8, Ll2/t;

    .line 3
    .line 4
    const v0, -0x6b998b72

    .line 5
    .line 6
    .line 7
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    or-int/lit8 v0, p4, 0x6

    .line 11
    .line 12
    invoke-virtual {v8, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    const/16 v1, 0x20

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/16 v1, 0x10

    .line 22
    .line 23
    :goto_0
    or-int/2addr v0, v1

    .line 24
    invoke-virtual {v8, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const/16 v1, 0x100

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/16 v1, 0x80

    .line 34
    .line 35
    :goto_1
    or-int/2addr v0, v1

    .line 36
    and-int/lit16 v1, v0, 0x93

    .line 37
    .line 38
    const/16 v2, 0x92

    .line 39
    .line 40
    if-eq v1, v2, :cond_2

    .line 41
    .line 42
    const/4 v1, 0x1

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/4 v1, 0x0

    .line 45
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 46
    .line 47
    invoke-virtual {v8, v2, v1}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_3

    .line 52
    .line 53
    sget v1, Li40/o3;->h:F

    .line 54
    .line 55
    sget v2, Li40/o3;->i:F

    .line 56
    .line 57
    invoke-static {v1, v2}, Lkp/c9;->a(FF)J

    .line 58
    .line 59
    .line 60
    move-result-wide v1

    .line 61
    sget-object v5, Landroidx/compose/foundation/layout/d;->a:Landroidx/compose/foundation/layout/FillElement;

    .line 62
    .line 63
    invoke-static {v1, v2}, Lt4/h;->c(J)F

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    invoke-static {v1, v2}, Lt4/h;->b(J)F

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 72
    .line 73
    invoke-static {v10, v5, v1}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 78
    .line 79
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    check-cast v2, Lj91/f;

    .line 84
    .line 85
    invoke-virtual {v2}, Lj91/f;->m()Lg4/p0;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    shl-int/lit8 v0, v0, 0x12

    .line 90
    .line 91
    const/high16 v2, 0x1c00000

    .line 92
    .line 93
    and-int/2addr v2, v0

    .line 94
    const v6, 0x36db0

    .line 95
    .line 96
    .line 97
    or-int/2addr v2, v6

    .line 98
    const/high16 v6, 0xe000000

    .line 99
    .line 100
    and-int/2addr v0, v6

    .line 101
    or-int v9, v2, v0

    .line 102
    .line 103
    move-object v0, v1

    .line 104
    sget v1, Li40/o3;->j:F

    .line 105
    .line 106
    sget v2, Li40/o3;->m:F

    .line 107
    .line 108
    sget v3, Li40/o3;->l:F

    .line 109
    .line 110
    sget v4, Li40/o3;->k:F

    .line 111
    .line 112
    move-object v6, p1

    .line 113
    move-object v7, p2

    .line 114
    invoke-static/range {v0 .. v9}, Li40/o3;->a(Lx2/s;FFFFLg4/p0;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V

    .line 115
    .line 116
    .line 117
    move-object v2, v10

    .line 118
    goto :goto_3

    .line 119
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 120
    .line 121
    .line 122
    move-object v2, p0

    .line 123
    :goto_3
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    if-eqz v0, :cond_4

    .line 128
    .line 129
    new-instance v1, Li40/l3;

    .line 130
    .line 131
    const/4 v6, 0x1

    .line 132
    move-object v3, p1

    .line 133
    move-object v4, p2

    .line 134
    move v5, p4

    .line 135
    invoke-direct/range {v1 .. v6}, Li40/l3;-><init>(Lx2/s;Landroid/net/Uri;Ljava/lang/String;II)V

    .line 136
    .line 137
    .line 138
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_4
    return-void
.end method
