.class public abstract Los0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lo90/a;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lo90/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, 0x8ead881

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Los0/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Lo90/a;

    .line 20
    .line 21
    const/16 v1, 0xb

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lo90/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, -0x5924b19e

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Los0/a;->b:Lt2/b;

    .line 35
    .line 36
    return-void
.end method

.method public static final a(Lns0/f;Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x13f60c45

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    if-eq v2, v1, :cond_1

    .line 24
    .line 25
    move v1, v3

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 v1, 0x0

    .line 28
    :goto_1
    and-int/2addr v0, v3

    .line 29
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_4

    .line 34
    .line 35
    sget-object v0, Lbe0/b;->a:Ll2/e0;

    .line 36
    .line 37
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lyy0/i;

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    or-int/2addr v1, v2

    .line 52
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    if-nez v1, :cond_2

    .line 57
    .line 58
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 59
    .line 60
    if-ne v2, v1, :cond_3

    .line 61
    .line 62
    :cond_2
    new-instance v2, Lna/e;

    .line 63
    .line 64
    const/4 v1, 0x0

    .line 65
    const/16 v3, 0xd

    .line 66
    .line 67
    invoke-direct {v2, v3, v0, p0, v1}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_3
    check-cast v2, Lay0/n;

    .line 74
    .line 75
    invoke-static {v2, v0, p1}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 76
    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 80
    .line 81
    .line 82
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    if-eqz p1, :cond_5

    .line 87
    .line 88
    new-instance v0, Llk/c;

    .line 89
    .line 90
    const/16 v1, 0xd

    .line 91
    .line 92
    invoke-direct {v0, p0, p2, v1}, Llk/c;-><init>(Ljava/lang/Object;II)V

    .line 93
    .line 94
    .line 95
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 96
    .line 97
    :cond_5
    return-void
.end method

.method public static final b(Lx2/s;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v5, p4

    .line 6
    .line 7
    move-object/from16 v12, p3

    .line 8
    .line 9
    check-cast v12, Ll2/t;

    .line 10
    .line 11
    const v0, -0x43882619

    .line 12
    .line 13
    .line 14
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v5, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, v5

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v5

    .line 33
    :goto_1
    and-int/lit8 v3, v5, 0x30

    .line 34
    .line 35
    const/16 v4, 0x20

    .line 36
    .line 37
    if-nez v3, :cond_3

    .line 38
    .line 39
    invoke-virtual {v12, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_2

    .line 44
    .line 45
    move v3, v4

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v3, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v3

    .line 50
    :cond_3
    and-int/lit16 v3, v5, 0x180

    .line 51
    .line 52
    if-nez v3, :cond_5

    .line 53
    .line 54
    move-object/from16 v3, p2

    .line 55
    .line 56
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-eqz v6, :cond_4

    .line 61
    .line 62
    const/16 v6, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v6, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v6

    .line 68
    goto :goto_4

    .line 69
    :cond_5
    move-object/from16 v3, p2

    .line 70
    .line 71
    :goto_4
    and-int/lit16 v6, v0, 0x93

    .line 72
    .line 73
    const/16 v7, 0x92

    .line 74
    .line 75
    const/4 v13, 0x0

    .line 76
    if-eq v6, v7, :cond_6

    .line 77
    .line 78
    const/4 v6, 0x1

    .line 79
    goto :goto_5

    .line 80
    :cond_6
    move v6, v13

    .line 81
    :goto_5
    and-int/lit8 v7, v0, 0x1

    .line 82
    .line 83
    invoke-virtual {v12, v7, v6}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    if-eqz v6, :cond_11

    .line 88
    .line 89
    sget-object v6, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 90
    .line 91
    invoke-interface {v1, v6}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    sget-object v7, Lx2/c;->d:Lx2/j;

    .line 96
    .line 97
    invoke-static {v7, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    iget-wide v8, v12, Ll2/t;->T:J

    .line 102
    .line 103
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 104
    .line 105
    .line 106
    move-result v8

    .line 107
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 108
    .line 109
    .line 110
    move-result-object v9

    .line 111
    invoke-static {v12, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 116
    .line 117
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 121
    .line 122
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 123
    .line 124
    .line 125
    iget-boolean v10, v12, Ll2/t;->S:Z

    .line 126
    .line 127
    if-eqz v10, :cond_7

    .line 128
    .line 129
    invoke-virtual {v12, v14}, Ll2/t;->l(Lay0/a;)V

    .line 130
    .line 131
    .line 132
    goto :goto_6

    .line 133
    :cond_7
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 134
    .line 135
    .line 136
    :goto_6
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 137
    .line 138
    invoke-static {v10, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 142
    .line 143
    invoke-static {v7, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 147
    .line 148
    iget-boolean v11, v12, Ll2/t;->S:Z

    .line 149
    .line 150
    if-nez v11, :cond_8

    .line 151
    .line 152
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v11

    .line 156
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v15

    .line 160
    invoke-static {v11, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v11

    .line 164
    if-nez v11, :cond_9

    .line 165
    .line 166
    :cond_8
    invoke-static {v8, v12, v8, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 167
    .line 168
    .line 169
    :cond_9
    sget-object v15, Lv3/j;->d:Lv3/h;

    .line 170
    .line 171
    invoke-static {v15, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 172
    .line 173
    .line 174
    and-int/lit8 v6, v0, 0x70

    .line 175
    .line 176
    if-ne v6, v4, :cond_a

    .line 177
    .line 178
    const/4 v4, 0x1

    .line 179
    goto :goto_7

    .line 180
    :cond_a
    move v4, v13

    .line 181
    :goto_7
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    if-nez v4, :cond_b

    .line 186
    .line 187
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 188
    .line 189
    if-ne v6, v4, :cond_c

    .line 190
    .line 191
    :cond_b
    new-instance v6, Li50/d;

    .line 192
    .line 193
    const/16 v4, 0xf

    .line 194
    .line 195
    invoke-direct {v6, v4, v2}, Li50/d;-><init>(ILay0/k;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    :cond_c
    move-object v8, v6

    .line 202
    check-cast v8, Lay0/k;

    .line 203
    .line 204
    const/4 v6, 0x0

    .line 205
    move-object v4, v7

    .line 206
    const/4 v7, 0x5

    .line 207
    move-object v11, v9

    .line 208
    const/4 v9, 0x0

    .line 209
    move-object/from16 v16, v11

    .line 210
    .line 211
    const/4 v11, 0x0

    .line 212
    move-object/from16 v17, v12

    .line 213
    .line 214
    move-object v12, v4

    .line 215
    move-object v4, v10

    .line 216
    move-object/from16 v10, v17

    .line 217
    .line 218
    move-object/from16 v17, v16

    .line 219
    .line 220
    invoke-static/range {v6 .. v11}, Ljp/ka;->b(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 221
    .line 222
    .line 223
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 224
    .line 225
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 226
    .line 227
    invoke-static {v6, v7, v10, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 228
    .line 229
    .line 230
    move-result-object v6

    .line 231
    iget-wide v7, v10, Ll2/t;->T:J

    .line 232
    .line 233
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 242
    .line 243
    invoke-static {v10, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 244
    .line 245
    .line 246
    move-result-object v9

    .line 247
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 248
    .line 249
    .line 250
    iget-boolean v11, v10, Ll2/t;->S:Z

    .line 251
    .line 252
    if-eqz v11, :cond_d

    .line 253
    .line 254
    invoke-virtual {v10, v14}, Ll2/t;->l(Lay0/a;)V

    .line 255
    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_d
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 259
    .line 260
    .line 261
    :goto_8
    invoke-static {v4, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 262
    .line 263
    .line 264
    invoke-static {v12, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 265
    .line 266
    .line 267
    iget-boolean v4, v10, Ll2/t;->S:Z

    .line 268
    .line 269
    if-nez v4, :cond_e

    .line 270
    .line 271
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v4

    .line 275
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 276
    .line 277
    .line 278
    move-result-object v6

    .line 279
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    move-result v4

    .line 283
    if-nez v4, :cond_f

    .line 284
    .line 285
    :cond_e
    move-object/from16 v11, v17

    .line 286
    .line 287
    invoke-static {v7, v10, v7, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 288
    .line 289
    .line 290
    :cond_f
    invoke-static {v15, v9, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 291
    .line 292
    .line 293
    shr-int/lit8 v0, v0, 0x6

    .line 294
    .line 295
    and-int/lit8 v0, v0, 0xe

    .line 296
    .line 297
    const/high16 v4, 0x180000

    .line 298
    .line 299
    or-int v13, v0, v4

    .line 300
    .line 301
    const/16 v14, 0x3e

    .line 302
    .line 303
    const/4 v7, 0x0

    .line 304
    const/4 v8, 0x0

    .line 305
    const/4 v9, 0x0

    .line 306
    move-object v12, v10

    .line 307
    const/4 v10, 0x0

    .line 308
    sget-object v11, Los0/a;->a:Lt2/b;

    .line 309
    .line 310
    move-object v6, v3

    .line 311
    invoke-static/range {v6 .. v14}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 312
    .line 313
    .line 314
    const/high16 v0, 0x3f800000    # 1.0f

    .line 315
    .line 316
    float-to-double v3, v0

    .line 317
    const-wide/16 v6, 0x0

    .line 318
    .line 319
    cmpl-double v3, v3, v6

    .line 320
    .line 321
    if-lez v3, :cond_10

    .line 322
    .line 323
    goto :goto_9

    .line 324
    :cond_10
    const-string v3, "invalid weight; must be greater than zero"

    .line 325
    .line 326
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    :goto_9
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 330
    .line 331
    const/4 v4, 0x1

    .line 332
    invoke-direct {v3, v0, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 333
    .line 334
    .line 335
    invoke-static {v12, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    goto :goto_a

    .line 345
    :cond_11
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 346
    .line 347
    .line 348
    :goto_a
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 349
    .line 350
    .line 351
    move-result-object v7

    .line 352
    if-eqz v7, :cond_12

    .line 353
    .line 354
    new-instance v0, Li50/j0;

    .line 355
    .line 356
    const/16 v6, 0x1c

    .line 357
    .line 358
    const/4 v3, 0x0

    .line 359
    move-object/from16 v4, p2

    .line 360
    .line 361
    invoke-direct/range {v0 .. v6}, Li50/j0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;II)V

    .line 362
    .line 363
    .line 364
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 365
    .line 366
    :cond_12
    return-void
.end method

.method public static final c(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x7884bacf

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Los0/a;->b:Lt2/b;

    .line 25
    .line 26
    const/16 v3, 0x30

    .line 27
    .line 28
    invoke-static {v0, v2, p0, v3, v1}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    new-instance v0, Lo90/a;

    .line 42
    .line 43
    const/16 v1, 0xc

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Lo90/a;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method

.method public static final d(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p1, 0x70556a94

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-nez p1, :cond_1

    .line 14
    .line 15
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    const/4 p1, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move p1, v0

    .line 24
    :goto_0
    or-int/2addr p1, p2

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p1, p2

    .line 27
    :goto_1
    and-int/lit8 v1, p1, 0x3

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x1

    .line 31
    if-eq v1, v0, :cond_2

    .line 32
    .line 33
    move v0, v3

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move v0, v2

    .line 36
    :goto_2
    and-int/lit8 v1, p1, 0x1

    .line 37
    .line 38
    invoke-virtual {v4, v1, v0}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_9

    .line 43
    .line 44
    invoke-static {v4}, Lxf0/y1;->F(Ll2/o;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    const p1, 0x63fede31

    .line 51
    .line 52
    .line 53
    invoke-virtual {v4, p1}, Ll2/t;->Y(I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v4, v2}, Los0/a;->c(Ll2/o;I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-eqz p1, :cond_a

    .line 67
    .line 68
    new-instance v0, Ln70/d0;

    .line 69
    .line 70
    const/16 v1, 0x8

    .line 71
    .line 72
    const/4 v2, 0x0

    .line 73
    invoke-direct {v0, p0, p2, v1, v2}, Ln70/d0;-><init>(Lx2/s;IIB)V

    .line 74
    .line 75
    .line 76
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 77
    .line 78
    return-void

    .line 79
    :cond_3
    const v0, 0x63e6742e

    .line 80
    .line 81
    .line 82
    const v1, -0x6040e0aa

    .line 83
    .line 84
    .line 85
    invoke-static {v0, v1, v4, v4, v2}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    if-eqz v0, :cond_8

    .line 90
    .line 91
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 96
    .line 97
    .line 98
    move-result-object v10

    .line 99
    const-class v1, Lns0/f;

    .line 100
    .line 101
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 102
    .line 103
    invoke-virtual {v5, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    const/4 v7, 0x0

    .line 112
    const/4 v9, 0x0

    .line 113
    const/4 v11, 0x0

    .line 114
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 119
    .line 120
    .line 121
    move-object v7, v0

    .line 122
    check-cast v7, Lns0/f;

    .line 123
    .line 124
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 125
    .line 126
    const/4 v1, 0x0

    .line 127
    invoke-static {v0, v1, v4, v3}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-static {v7, v4, v2}, Los0/a;->a(Lns0/f;Ll2/o;I)V

    .line 132
    .line 133
    .line 134
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Lns0/d;

    .line 139
    .line 140
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 149
    .line 150
    if-nez v1, :cond_4

    .line 151
    .line 152
    if-ne v2, v3, :cond_5

    .line 153
    .line 154
    :cond_4
    new-instance v5, Lo90/f;

    .line 155
    .line 156
    const/4 v11, 0x0

    .line 157
    const/4 v12, 0x6

    .line 158
    const/4 v6, 0x1

    .line 159
    const-class v8, Lns0/f;

    .line 160
    .line 161
    const-string v9, "onQrCodeScanned"

    .line 162
    .line 163
    const-string v10, "onQrCodeScanned(Ljava/lang/String;)V"

    .line 164
    .line 165
    invoke-direct/range {v5 .. v12}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-object v2, v5

    .line 172
    :cond_5
    check-cast v2, Lhy0/g;

    .line 173
    .line 174
    check-cast v2, Lay0/k;

    .line 175
    .line 176
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    if-nez v1, :cond_6

    .line 185
    .line 186
    if-ne v5, v3, :cond_7

    .line 187
    .line 188
    :cond_6
    new-instance v5, Lo50/r;

    .line 189
    .line 190
    const/4 v11, 0x0

    .line 191
    const/16 v12, 0x12

    .line 192
    .line 193
    const/4 v6, 0x0

    .line 194
    const-class v8, Lns0/f;

    .line 195
    .line 196
    const-string v9, "onQrScannerHide"

    .line 197
    .line 198
    const-string v10, "onQrScannerHide()V"

    .line 199
    .line 200
    invoke-direct/range {v5 .. v12}, Lo50/r;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    :cond_7
    check-cast v5, Lhy0/g;

    .line 207
    .line 208
    move-object v3, v5

    .line 209
    check-cast v3, Lay0/a;

    .line 210
    .line 211
    shl-int/lit8 p1, p1, 0x3

    .line 212
    .line 213
    and-int/lit8 v5, p1, 0x70

    .line 214
    .line 215
    const/4 v6, 0x0

    .line 216
    move-object v1, p0

    .line 217
    invoke-static/range {v0 .. v6}, Los0/a;->e(Lns0/d;Lx2/s;Lay0/k;Lay0/a;Ll2/o;II)V

    .line 218
    .line 219
    .line 220
    goto :goto_3

    .line 221
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 222
    .line 223
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 224
    .line 225
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    throw p0

    .line 229
    :cond_9
    move-object v1, p0

    .line 230
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 231
    .line 232
    .line 233
    :goto_3
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    if-eqz p0, :cond_a

    .line 238
    .line 239
    new-instance p1, Ln70/d0;

    .line 240
    .line 241
    const/16 v0, 0x9

    .line 242
    .line 243
    const/4 v2, 0x0

    .line 244
    invoke-direct {p1, v1, p2, v0, v2}, Ln70/d0;-><init>(Lx2/s;IIB)V

    .line 245
    .line 246
    .line 247
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 248
    .line 249
    :cond_a
    return-void
.end method

.method public static final e(Lns0/d;Lx2/s;Lay0/k;Lay0/a;Ll2/o;II)V
    .locals 12

    .line 1
    move/from16 v5, p5

    .line 2
    .line 3
    move-object/from16 v0, p4

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x1df43e60

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, v5, 0x6

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int/2addr v1, v5

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v5

    .line 29
    :goto_1
    and-int/lit8 v2, p6, 0x2

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    or-int/lit8 v1, v1, 0x30

    .line 34
    .line 35
    goto :goto_3

    .line 36
    :cond_2
    and-int/lit8 v3, v5, 0x30

    .line 37
    .line 38
    if-nez v3, :cond_4

    .line 39
    .line 40
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_3

    .line 45
    .line 46
    const/16 v3, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_3
    const/16 v3, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v1, v3

    .line 52
    :cond_4
    :goto_3
    and-int/lit8 v3, p6, 0x4

    .line 53
    .line 54
    if-eqz v3, :cond_5

    .line 55
    .line 56
    or-int/lit16 v1, v1, 0x180

    .line 57
    .line 58
    goto :goto_5

    .line 59
    :cond_5
    and-int/lit16 v4, v5, 0x180

    .line 60
    .line 61
    if-nez v4, :cond_7

    .line 62
    .line 63
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    if-eqz v6, :cond_6

    .line 68
    .line 69
    const/16 v6, 0x100

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_6
    const/16 v6, 0x80

    .line 73
    .line 74
    :goto_4
    or-int/2addr v1, v6

    .line 75
    :cond_7
    :goto_5
    and-int/lit8 v6, p6, 0x8

    .line 76
    .line 77
    if-eqz v6, :cond_8

    .line 78
    .line 79
    or-int/lit16 v1, v1, 0xc00

    .line 80
    .line 81
    goto :goto_7

    .line 82
    :cond_8
    and-int/lit16 v7, v5, 0xc00

    .line 83
    .line 84
    if-nez v7, :cond_a

    .line 85
    .line 86
    invoke-virtual {v0, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v8

    .line 90
    if-eqz v8, :cond_9

    .line 91
    .line 92
    const/16 v8, 0x800

    .line 93
    .line 94
    goto :goto_6

    .line 95
    :cond_9
    const/16 v8, 0x400

    .line 96
    .line 97
    :goto_6
    or-int/2addr v1, v8

    .line 98
    :cond_a
    :goto_7
    and-int/lit16 v8, v1, 0x493

    .line 99
    .line 100
    const/16 v9, 0x492

    .line 101
    .line 102
    const/4 v10, 0x0

    .line 103
    const/4 v11, 0x1

    .line 104
    if-eq v8, v9, :cond_b

    .line 105
    .line 106
    move v8, v11

    .line 107
    goto :goto_8

    .line 108
    :cond_b
    move v8, v10

    .line 109
    :goto_8
    and-int/lit8 v9, v1, 0x1

    .line 110
    .line 111
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    if-eqz v8, :cond_15

    .line 116
    .line 117
    if-eqz v2, :cond_c

    .line 118
    .line 119
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 120
    .line 121
    :cond_c
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 122
    .line 123
    if-eqz v3, :cond_e

    .line 124
    .line 125
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    if-ne v3, v2, :cond_d

    .line 130
    .line 131
    new-instance v3, Lod0/g;

    .line 132
    .line 133
    const/16 v4, 0x10

    .line 134
    .line 135
    invoke-direct {v3, v4}, Lod0/g;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_d
    check-cast v3, Lay0/k;

    .line 142
    .line 143
    goto :goto_9

    .line 144
    :cond_e
    move-object v3, p2

    .line 145
    :goto_9
    if-eqz v6, :cond_10

    .line 146
    .line 147
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    if-ne v4, v2, :cond_f

    .line 152
    .line 153
    new-instance v4, Lz81/g;

    .line 154
    .line 155
    const/4 v2, 0x2

    .line 156
    invoke-direct {v4, v2}, Lz81/g;-><init>(I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    :cond_f
    move-object v2, v4

    .line 163
    check-cast v2, Lay0/a;

    .line 164
    .line 165
    goto :goto_a

    .line 166
    :cond_10
    move-object v2, p3

    .line 167
    :goto_a
    iget-boolean v4, p0, Lns0/d;->a:Z

    .line 168
    .line 169
    if-eqz v4, :cond_11

    .line 170
    .line 171
    const v4, 0x361cafda

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0, v4}, Ll2/t;->Y(I)V

    .line 175
    .line 176
    .line 177
    shr-int/lit8 v1, v1, 0x3

    .line 178
    .line 179
    and-int/lit16 v1, v1, 0x3fe

    .line 180
    .line 181
    invoke-static {p1, v3, v2, v0, v1}, Los0/a;->b(Lx2/s;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, v10}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_c

    .line 188
    :cond_11
    const v1, 0x361e1aa6

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 195
    .line 196
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 197
    .line 198
    invoke-interface {p1, v4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 203
    .line 204
    invoke-virtual {v0, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    check-cast v6, Lj91/c;

    .line 209
    .line 210
    iget v6, v6, Lj91/c;->j:F

    .line 211
    .line 212
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    invoke-static {v1, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    iget-wide v6, v0, Ll2/t;->T:J

    .line 221
    .line 222
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 223
    .line 224
    .line 225
    move-result v6

    .line 226
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 227
    .line 228
    .line 229
    move-result-object v7

    .line 230
    invoke-static {v0, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 231
    .line 232
    .line 233
    move-result-object v4

    .line 234
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 235
    .line 236
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 240
    .line 241
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 242
    .line 243
    .line 244
    iget-boolean v9, v0, Ll2/t;->S:Z

    .line 245
    .line 246
    if-eqz v9, :cond_12

    .line 247
    .line 248
    invoke-virtual {v0, v8}, Ll2/t;->l(Lay0/a;)V

    .line 249
    .line 250
    .line 251
    goto :goto_b

    .line 252
    :cond_12
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 253
    .line 254
    .line 255
    :goto_b
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 256
    .line 257
    invoke-static {v8, v1, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 258
    .line 259
    .line 260
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 261
    .line 262
    invoke-static {v1, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 263
    .line 264
    .line 265
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 266
    .line 267
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 268
    .line 269
    if-nez v7, :cond_13

    .line 270
    .line 271
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v7

    .line 275
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 276
    .line 277
    .line 278
    move-result-object v8

    .line 279
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    move-result v7

    .line 283
    if-nez v7, :cond_14

    .line 284
    .line 285
    :cond_13
    invoke-static {v6, v0, v6, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 286
    .line 287
    .line 288
    :cond_14
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 289
    .line 290
    invoke-static {v1, v4, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 291
    .line 292
    .line 293
    const/4 v1, 0x0

    .line 294
    invoke-static {v10, v11, v0, v1}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 295
    .line 296
    .line 297
    invoke-virtual {v0, v11}, Ll2/t;->q(Z)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v0, v10}, Ll2/t;->q(Z)V

    .line 301
    .line 302
    .line 303
    :goto_c
    move-object v4, v2

    .line 304
    :goto_d
    move-object v2, p1

    .line 305
    goto :goto_e

    .line 306
    :cond_15
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 307
    .line 308
    .line 309
    move-object v3, p2

    .line 310
    move-object v4, p3

    .line 311
    goto :goto_d

    .line 312
    :goto_e
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    if-eqz p1, :cond_16

    .line 317
    .line 318
    new-instance v0, Ldk/j;

    .line 319
    .line 320
    const/16 v7, 0xa

    .line 321
    .line 322
    move-object v1, p0

    .line 323
    move/from16 v6, p6

    .line 324
    .line 325
    invoke-direct/range {v0 .. v7}, Ldk/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 326
    .line 327
    .line 328
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 329
    .line 330
    :cond_16
    return-void
.end method
