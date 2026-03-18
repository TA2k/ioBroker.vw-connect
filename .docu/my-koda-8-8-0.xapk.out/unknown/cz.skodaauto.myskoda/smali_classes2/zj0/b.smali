.class public abstract Lzj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x92

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lzj0/b;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lxj0/f;Lx2/s;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "location"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v3, p2

    .line 13
    .line 14
    check-cast v3, Ll2/t;

    .line 15
    .line 16
    const v4, 0x6581ad44

    .line 17
    .line 18
    .line 19
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    const/4 v5, 0x4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    move v4, v5

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v4, 0x2

    .line 32
    :goto_0
    or-int/2addr v4, v2

    .line 33
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    if-eqz v6, :cond_1

    .line 38
    .line 39
    const/16 v6, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v6, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v4, v6

    .line 45
    and-int/lit8 v6, v4, 0x13

    .line 46
    .line 47
    const/16 v7, 0x12

    .line 48
    .line 49
    const/4 v8, 0x0

    .line 50
    const/4 v9, 0x1

    .line 51
    if-eq v6, v7, :cond_2

    .line 52
    .line 53
    move v6, v9

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move v6, v8

    .line 56
    :goto_2
    and-int/lit8 v7, v4, 0x1

    .line 57
    .line 58
    invoke-virtual {v3, v7, v6}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    if-eqz v6, :cond_c

    .line 63
    .line 64
    sget-object v6, Lx2/c;->d:Lx2/j;

    .line 65
    .line 66
    invoke-static {v6, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    iget-wide v10, v3, Ll2/t;->T:J

    .line 71
    .line 72
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 77
    .line 78
    .line 79
    move-result-object v10

    .line 80
    invoke-static {v3, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v11

    .line 84
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 85
    .line 86
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 90
    .line 91
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 92
    .line 93
    .line 94
    iget-boolean v13, v3, Ll2/t;->S:Z

    .line 95
    .line 96
    if-eqz v13, :cond_3

    .line 97
    .line 98
    invoke-virtual {v3, v12}, Ll2/t;->l(Lay0/a;)V

    .line 99
    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_3
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 103
    .line 104
    .line 105
    :goto_3
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 106
    .line 107
    invoke-static {v12, v6, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 108
    .line 109
    .line 110
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 111
    .line 112
    invoke-static {v6, v10, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 113
    .line 114
    .line 115
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 116
    .line 117
    iget-boolean v10, v3, Ll2/t;->S:Z

    .line 118
    .line 119
    if-nez v10, :cond_4

    .line 120
    .line 121
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v12

    .line 129
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v10

    .line 133
    if-nez v10, :cond_5

    .line 134
    .line 135
    :cond_4
    invoke-static {v7, v3, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 136
    .line 137
    .line 138
    :cond_5
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 139
    .line 140
    invoke-static {v6, v11, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 144
    .line 145
    invoke-virtual {v3, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    check-cast v6, Landroid/content/Context;

    .line 150
    .line 151
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 156
    .line 157
    if-ne v7, v10, :cond_6

    .line 158
    .line 159
    new-instance v7, Luu/u0;

    .line 160
    .line 161
    invoke-static {v6}, Lsp/j;->x0(Landroid/content/Context;)Lsp/j;

    .line 162
    .line 163
    .line 164
    move-result-object v6

    .line 165
    const/16 v11, 0x1df

    .line 166
    .line 167
    invoke-direct {v7, v6, v11}, Luu/u0;-><init>(Lsp/j;I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v3, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    :cond_6
    check-cast v7, Luu/u0;

    .line 174
    .line 175
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v6

    .line 179
    if-ne v6, v10, :cond_7

    .line 180
    .line 181
    sget-object v6, Lzj0/d;->c:Luu/a1;

    .line 182
    .line 183
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_7
    check-cast v6, Luu/a1;

    .line 187
    .line 188
    new-instance v11, Lyk0/o;

    .line 189
    .line 190
    const/4 v12, 0x1

    .line 191
    invoke-direct {v11, v0, v12}, Lyk0/o;-><init>(Lxj0/f;I)V

    .line 192
    .line 193
    .line 194
    new-array v12, v8, [Ljava/lang/Object;

    .line 195
    .line 196
    new-instance v13, Lep0/f;

    .line 197
    .line 198
    const/16 v14, 0x18

    .line 199
    .line 200
    invoke-direct {v13, v11, v14}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 201
    .line 202
    .line 203
    sget-object v11, Luu/g;->h:Lu2/l;

    .line 204
    .line 205
    invoke-static {v12, v11, v13, v3, v8}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v11

    .line 209
    check-cast v11, Luu/g;

    .line 210
    .line 211
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v12

    .line 215
    if-ne v12, v10, :cond_8

    .line 216
    .line 217
    sget-object v12, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 218
    .line 219
    invoke-static {v12}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 220
    .line 221
    .line 222
    move-result-object v12

    .line 223
    invoke-virtual {v3, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    :cond_8
    check-cast v12, Ll2/b1;

    .line 227
    .line 228
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 229
    .line 230
    const/high16 v14, 0x3f800000    # 1.0f

    .line 231
    .line 232
    invoke-static {v13, v14}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 233
    .line 234
    .line 235
    move-result-object v15

    .line 236
    move-object/from16 p2, v6

    .line 237
    .line 238
    sget v6, Lzj0/b;->a:F

    .line 239
    .line 240
    invoke-static {v15, v6}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 241
    .line 242
    .line 243
    move-result-object v15

    .line 244
    invoke-virtual {v3, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v16

    .line 248
    and-int/lit8 v4, v4, 0xe

    .line 249
    .line 250
    if-ne v4, v5, :cond_9

    .line 251
    .line 252
    move v4, v9

    .line 253
    goto :goto_4

    .line 254
    :cond_9
    move v4, v8

    .line 255
    :goto_4
    or-int v4, v16, v4

    .line 256
    .line 257
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    if-nez v4, :cond_a

    .line 262
    .line 263
    if-ne v5, v10, :cond_b

    .line 264
    .line 265
    :cond_a
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 266
    .line 267
    const/16 v4, 0x13

    .line 268
    .line 269
    invoke-direct {v5, v11, v0, v12, v4}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    :cond_b
    check-cast v5, Lay0/a;

    .line 276
    .line 277
    new-instance v4, Lza0/j;

    .line 278
    .line 279
    const/4 v10, 0x4

    .line 280
    invoke-direct {v4, v0, v10}, Lza0/j;-><init>(Ljava/lang/Object;I)V

    .line 281
    .line 282
    .line 283
    const v10, -0x590e955b

    .line 284
    .line 285
    .line 286
    invoke-static {v10, v3, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 287
    .line 288
    .line 289
    move-result-object v4

    .line 290
    const/high16 v18, 0x6000000

    .line 291
    .line 292
    const v19, 0x3f75a

    .line 293
    .line 294
    .line 295
    move v10, v6

    .line 296
    const/4 v6, 0x0

    .line 297
    move/from16 v16, v9

    .line 298
    .line 299
    const/4 v9, 0x0

    .line 300
    move/from16 v17, v10

    .line 301
    .line 302
    const/4 v10, 0x0

    .line 303
    move-object/from16 v20, v12

    .line 304
    .line 305
    move-object v12, v5

    .line 306
    move-object v5, v11

    .line 307
    const/4 v11, 0x0

    .line 308
    move-object/from16 v21, v13

    .line 309
    .line 310
    const/4 v13, 0x0

    .line 311
    move/from16 v22, v14

    .line 312
    .line 313
    const/4 v14, 0x0

    .line 314
    move/from16 v23, v17

    .line 315
    .line 316
    const/16 v17, 0x6

    .line 317
    .line 318
    move-object v0, v15

    .line 319
    move-object v15, v4

    .line 320
    move-object v4, v0

    .line 321
    move-object/from16 v8, p2

    .line 322
    .line 323
    move-object/from16 v16, v3

    .line 324
    .line 325
    move-object/from16 v0, v21

    .line 326
    .line 327
    move/from16 v3, v22

    .line 328
    .line 329
    move/from16 v1, v23

    .line 330
    .line 331
    invoke-static/range {v4 .. v19}, Llp/ca;->b(Lx2/s;Luu/g;Lay0/a;Luu/u0;Luu/a1;Luu/o;Lay0/k;Lay0/k;Lay0/a;Lk1/z0;Lay0/n;Lt2/b;Ll2/o;III)V

    .line 332
    .line 333
    .line 334
    move-object/from16 v4, v16

    .line 335
    .line 336
    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 341
    .line 342
    .line 343
    move-result-object v0

    .line 344
    invoke-interface/range {v20 .. v20}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v1

    .line 348
    check-cast v1, Ljava/lang/Boolean;

    .line 349
    .line 350
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 351
    .line 352
    .line 353
    move-result v1

    .line 354
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 355
    .line 356
    invoke-static {v0, v1, v3}, Lxf0/y1;->G(Lx2/s;ZLe3/n0;)Lx2/s;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    const/4 v1, 0x0

    .line 361
    invoke-static {v0, v4, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 362
    .line 363
    .line 364
    const/4 v0, 0x1

    .line 365
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 366
    .line 367
    .line 368
    goto :goto_5

    .line 369
    :cond_c
    move-object v4, v3

    .line 370
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 371
    .line 372
    .line 373
    :goto_5
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    if-eqz v0, :cond_d

    .line 378
    .line 379
    new-instance v1, Lzb/d;

    .line 380
    .line 381
    move-object/from16 v3, p0

    .line 382
    .line 383
    move-object/from16 v4, p1

    .line 384
    .line 385
    invoke-direct {v1, v3, v4, v2}, Lzb/d;-><init>(Lxj0/f;Lx2/s;I)V

    .line 386
    .line 387
    .line 388
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 389
    .line 390
    :cond_d
    return-void
.end method

.method public static final b(Lxj0/f;JZLl2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v2, p1

    .line 4
    .line 5
    const-string v0, "location"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v13, p4

    .line 11
    .line 12
    check-cast v13, Ll2/t;

    .line 13
    .line 14
    const v0, -0x43689dfb

    .line 15
    .line 16
    .line 17
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v13, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v0, 0x2

    .line 29
    :goto_0
    or-int v0, p5, v0

    .line 30
    .line 31
    invoke-virtual {v13, v2, v3}, Ll2/t;->f(J)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_1

    .line 36
    .line 37
    const/16 v4, 0x20

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v4, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v4

    .line 43
    or-int/lit16 v4, v0, 0x180

    .line 44
    .line 45
    and-int/lit8 v5, p6, 0x8

    .line 46
    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    or-int/lit16 v0, v0, 0xd80

    .line 50
    .line 51
    move v15, v0

    .line 52
    move/from16 v0, p3

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_2
    move/from16 v0, p3

    .line 56
    .line 57
    invoke-virtual {v13, v0}, Ll2/t;->h(Z)Z

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    if-eqz v6, :cond_3

    .line 62
    .line 63
    const/16 v6, 0x800

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    const/16 v6, 0x400

    .line 67
    .line 68
    :goto_2
    or-int/2addr v4, v6

    .line 69
    move v15, v4

    .line 70
    :goto_3
    and-int/lit16 v4, v15, 0x493

    .line 71
    .line 72
    const/16 v6, 0x492

    .line 73
    .line 74
    const/4 v7, 0x0

    .line 75
    const/4 v8, 0x1

    .line 76
    if-eq v4, v6, :cond_4

    .line 77
    .line 78
    move v4, v8

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v4, v7

    .line 81
    :goto_4
    and-int/lit8 v6, v15, 0x1

    .line 82
    .line 83
    invoke-virtual {v13, v6, v4}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    if-eqz v4, :cond_7

    .line 88
    .line 89
    if-eqz v5, :cond_5

    .line 90
    .line 91
    move v0, v8

    .line 92
    :cond_5
    invoke-static {v1}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    const v16, 0xe000

    .line 97
    .line 98
    .line 99
    const v17, 0x180c00

    .line 100
    .line 101
    .line 102
    if-eqz v0, :cond_6

    .line 103
    .line 104
    const v5, -0x6b656e72

    .line 105
    .line 106
    .line 107
    invoke-virtual {v13, v5}, Ll2/t;->Y(I)V

    .line 108
    .line 109
    .line 110
    const v5, 0x3dcccccd    # 0.1f

    .line 111
    .line 112
    .line 113
    invoke-static {v2, v3, v5}, Le3/s;->b(JF)J

    .line 114
    .line 115
    .line 116
    move-result-wide v5

    .line 117
    shl-int/lit8 v8, v15, 0x9

    .line 118
    .line 119
    and-int v8, v8, v16

    .line 120
    .line 121
    or-int v14, v8, v17

    .line 122
    .line 123
    move-object v2, v4

    .line 124
    move-wide v3, v5

    .line 125
    const-wide/high16 v5, 0x4059000000000000L    # 100.0

    .line 126
    .line 127
    const/high16 v9, 0x40800000    # 4.0f

    .line 128
    .line 129
    const/4 v10, 0x0

    .line 130
    const v11, 0x3dcccccd    # 0.1f

    .line 131
    .line 132
    .line 133
    const/4 v12, 0x0

    .line 134
    move/from16 p3, v0

    .line 135
    .line 136
    move v0, v7

    .line 137
    move-wide/from16 v7, p1

    .line 138
    .line 139
    invoke-static/range {v2 .. v14}, Llp/ba;->a(Lcom/google/android/gms/maps/model/LatLng;JDJFZFLay0/k;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    :goto_5
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_6
    move/from16 p3, v0

    .line 147
    .line 148
    move-object v2, v4

    .line 149
    move v0, v7

    .line 150
    const v3, -0x6b8fe1c3

    .line 151
    .line 152
    .line 153
    invoke-virtual {v13, v3}, Ll2/t;->Y(I)V

    .line 154
    .line 155
    .line 156
    goto :goto_5

    .line 157
    :goto_6
    shl-int/lit8 v0, v15, 0x3

    .line 158
    .line 159
    and-int/lit16 v0, v0, 0x380

    .line 160
    .line 161
    or-int v0, v0, v17

    .line 162
    .line 163
    shl-int/lit8 v3, v15, 0x9

    .line 164
    .line 165
    and-int v3, v3, v16

    .line 166
    .line 167
    or-int v14, v0, v3

    .line 168
    .line 169
    const-wide/high16 v5, 0x3ff0000000000000L    # 1.0

    .line 170
    .line 171
    const/high16 v9, 0x41f00000    # 30.0f

    .line 172
    .line 173
    const/4 v10, 0x0

    .line 174
    const v11, 0x3e4ccccd    # 0.2f

    .line 175
    .line 176
    .line 177
    const/4 v12, 0x0

    .line 178
    move-wide/from16 v7, p1

    .line 179
    .line 180
    move-wide/from16 v3, p1

    .line 181
    .line 182
    invoke-static/range {v2 .. v14}, Llp/ba;->a(Lcom/google/android/gms/maps/model/LatLng;JDJFZFLay0/k;Ll2/o;I)V

    .line 183
    .line 184
    .line 185
    move/from16 v4, p3

    .line 186
    .line 187
    goto :goto_7

    .line 188
    :cond_7
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    move v4, v0

    .line 192
    :goto_7
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    if-eqz v7, :cond_8

    .line 197
    .line 198
    new-instance v0, Lzj0/a;

    .line 199
    .line 200
    move-wide/from16 v2, p1

    .line 201
    .line 202
    move/from16 v5, p5

    .line 203
    .line 204
    move/from16 v6, p6

    .line 205
    .line 206
    invoke-direct/range {v0 .. v6}, Lzj0/a;-><init>(Lxj0/f;JZII)V

    .line 207
    .line 208
    .line 209
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 210
    .line 211
    :cond_8
    return-void
.end method
