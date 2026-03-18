.class public final synthetic Li40/i3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lh40/d4;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/k;

.field public final synthetic o:Lay0/k;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:Lay0/a;

.field public final synthetic r:Lay0/a;

.field public final synthetic s:Lay0/a;

.field public final synthetic t:Lay0/a;

.field public final synthetic u:Lay0/a;

.field public final synthetic v:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/d4;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/i3;->d:Lh40/d4;

    .line 5
    .line 6
    iput-object p2, p0, Li40/i3;->e:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Li40/i3;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Li40/i3;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Li40/i3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Li40/i3;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p7, p0, Li40/i3;->j:Lay0/k;

    .line 17
    .line 18
    iput-object p8, p0, Li40/i3;->k:Lay0/k;

    .line 19
    .line 20
    iput-object p9, p0, Li40/i3;->l:Lay0/k;

    .line 21
    .line 22
    iput-object p10, p0, Li40/i3;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p11, p0, Li40/i3;->n:Lay0/k;

    .line 25
    .line 26
    iput-object p12, p0, Li40/i3;->o:Lay0/k;

    .line 27
    .line 28
    iput-object p13, p0, Li40/i3;->p:Lay0/a;

    .line 29
    .line 30
    iput-object p14, p0, Li40/i3;->q:Lay0/a;

    .line 31
    .line 32
    iput-object p15, p0, Li40/i3;->r:Lay0/a;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Li40/i3;->s:Lay0/a;

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Li40/i3;->t:Lay0/a;

    .line 41
    .line 42
    move-object/from16 p1, p18

    .line 43
    .line 44
    iput-object p1, p0, Li40/i3;->u:Lay0/a;

    .line 45
    .line 46
    move-object/from16 p1, p19

    .line 47
    .line 48
    iput-object p1, p0, Li40/i3;->v:Lay0/a;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$PullToRefreshBox"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v1, v3, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    const/4 v6, 0x0

    .line 30
    if-eq v1, v4, :cond_0

    .line 31
    .line 32
    move v1, v5

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v1, v6

    .line 35
    :goto_0
    and-int/2addr v3, v5

    .line 36
    move-object v10, v2

    .line 37
    check-cast v10, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v10, v3, v1}, Ll2/t;->O(IZ)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_d

    .line 44
    .line 45
    iget-object v12, v0, Li40/i3;->d:Lh40/d4;

    .line 46
    .line 47
    iget-boolean v1, v12, Lh40/d4;->d:Z

    .line 48
    .line 49
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 50
    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    const v1, 0x3ac1765f    # 0.0014760009f

    .line 54
    .line 55
    .line 56
    invoke-virtual {v10, v1}, Ll2/t;->Y(I)V

    .line 57
    .line 58
    .line 59
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 60
    .line 61
    invoke-static {v6, v5, v10}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    const/16 v4, 0xe

    .line 66
    .line 67
    invoke-static {v1, v3, v4}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    sget-object v3, Lk1/r0;->e:Lk1/r0;

    .line 72
    .line 73
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 78
    .line 79
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Lj91/e;

    .line 84
    .line 85
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 86
    .line 87
    .line 88
    move-result-wide v3

    .line 89
    invoke-static {v1, v3, v4, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 94
    .line 95
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 96
    .line 97
    invoke-static {v2, v3, v10, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    iget-wide v3, v10, Ll2/t;->T:J

    .line 102
    .line 103
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    invoke-static {v10, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 116
    .line 117
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 121
    .line 122
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 123
    .line 124
    .line 125
    iget-boolean v8, v10, Ll2/t;->S:Z

    .line 126
    .line 127
    if-eqz v8, :cond_1

    .line 128
    .line 129
    invoke-virtual {v10, v7}, Ll2/t;->l(Lay0/a;)V

    .line 130
    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_1
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 134
    .line 135
    .line 136
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 137
    .line 138
    invoke-static {v7, v2, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 142
    .line 143
    invoke-static {v2, v4, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 147
    .line 148
    iget-boolean v4, v10, Ll2/t;->S:Z

    .line 149
    .line 150
    if-nez v4, :cond_2

    .line 151
    .line 152
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v7

    .line 160
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v4

    .line 164
    if-nez v4, :cond_3

    .line 165
    .line 166
    :cond_2
    invoke-static {v3, v10, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 167
    .line 168
    .line 169
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 170
    .line 171
    invoke-static {v2, v1, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 172
    .line 173
    .line 174
    invoke-static {v10, v6}, Li40/l1;->d(Ll2/o;I)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v10, v6}, Ll2/t;->q(Z)V

    .line 181
    .line 182
    .line 183
    move v2, v6

    .line 184
    move-object v1, v12

    .line 185
    goto/16 :goto_5

    .line 186
    .line 187
    :cond_4
    const v1, 0x3ac7375b

    .line 188
    .line 189
    .line 190
    invoke-virtual {v10, v1}, Ll2/t;->Y(I)V

    .line 191
    .line 192
    .line 193
    const/4 v1, 0x3

    .line 194
    invoke-static {v6, v1, v10}, Lm1/v;->a(IILl2/o;)Lm1/t;

    .line 195
    .line 196
    .line 197
    move-result-object v8

    .line 198
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 199
    .line 200
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 201
    .line 202
    invoke-virtual {v10, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    check-cast v3, Lj91/e;

    .line 207
    .line 208
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 209
    .line 210
    .line 211
    move-result-wide v3

    .line 212
    invoke-static {v1, v3, v4, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    invoke-virtual {v10, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v1

    .line 220
    iget-object v13, v0, Li40/i3;->e:Lay0/k;

    .line 221
    .line 222
    invoke-virtual {v10, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    or-int/2addr v1, v2

    .line 227
    iget-object v14, v0, Li40/i3;->f:Lay0/k;

    .line 228
    .line 229
    invoke-virtual {v10, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v2

    .line 233
    or-int/2addr v1, v2

    .line 234
    iget-object v15, v0, Li40/i3;->g:Lay0/k;

    .line 235
    .line 236
    invoke-virtual {v10, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    or-int/2addr v1, v2

    .line 241
    iget-object v2, v0, Li40/i3;->h:Lay0/k;

    .line 242
    .line 243
    invoke-virtual {v10, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v3

    .line 247
    or-int/2addr v1, v3

    .line 248
    iget-object v3, v0, Li40/i3;->i:Lay0/k;

    .line 249
    .line 250
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-result v4

    .line 254
    or-int/2addr v1, v4

    .line 255
    iget-object v4, v0, Li40/i3;->j:Lay0/k;

    .line 256
    .line 257
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    or-int/2addr v1, v5

    .line 262
    iget-object v5, v0, Li40/i3;->k:Lay0/k;

    .line 263
    .line 264
    invoke-virtual {v10, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v9

    .line 268
    or-int/2addr v1, v9

    .line 269
    iget-object v9, v0, Li40/i3;->l:Lay0/k;

    .line 270
    .line 271
    invoke-virtual {v10, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v11

    .line 275
    or-int/2addr v1, v11

    .line 276
    iget-object v11, v0, Li40/i3;->m:Lay0/k;

    .line 277
    .line 278
    invoke-virtual {v10, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v16

    .line 282
    or-int v1, v1, v16

    .line 283
    .line 284
    iget-object v6, v0, Li40/i3;->n:Lay0/k;

    .line 285
    .line 286
    invoke-virtual {v10, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v16

    .line 290
    or-int v1, v1, v16

    .line 291
    .line 292
    move/from16 p2, v1

    .line 293
    .line 294
    iget-object v1, v0, Li40/i3;->o:Lay0/k;

    .line 295
    .line 296
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v16

    .line 300
    or-int v16, p2, v16

    .line 301
    .line 302
    move-object/from16 v23, v1

    .line 303
    .line 304
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    if-nez v16, :cond_6

    .line 309
    .line 310
    move-object/from16 v16, v2

    .line 311
    .line 312
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 313
    .line 314
    if-ne v1, v2, :cond_5

    .line 315
    .line 316
    :goto_2
    move-object/from16 v21, v11

    .line 317
    .line 318
    goto :goto_3

    .line 319
    :cond_5
    move-object v11, v1

    .line 320
    move-object v1, v12

    .line 321
    goto :goto_4

    .line 322
    :cond_6
    move-object/from16 v16, v2

    .line 323
    .line 324
    goto :goto_2

    .line 325
    :goto_3
    new-instance v11, Li40/h3;

    .line 326
    .line 327
    move-object/from16 v17, v3

    .line 328
    .line 329
    move-object/from16 v18, v4

    .line 330
    .line 331
    move-object/from16 v19, v5

    .line 332
    .line 333
    move-object/from16 v22, v6

    .line 334
    .line 335
    move-object/from16 v20, v9

    .line 336
    .line 337
    invoke-direct/range {v11 .. v23}, Li40/h3;-><init>(Lh40/d4;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V

    .line 338
    .line 339
    .line 340
    move-object v1, v12

    .line 341
    invoke-virtual {v10, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 342
    .line 343
    .line 344
    :goto_4
    move-object v15, v11

    .line 345
    check-cast v15, Lay0/k;

    .line 346
    .line 347
    const/16 v17, 0x0

    .line 348
    .line 349
    const/16 v18, 0x1fc

    .line 350
    .line 351
    const/4 v9, 0x0

    .line 352
    move-object/from16 v16, v10

    .line 353
    .line 354
    const/4 v10, 0x0

    .line 355
    const/4 v11, 0x0

    .line 356
    const/4 v12, 0x0

    .line 357
    const/4 v13, 0x0

    .line 358
    const/4 v14, 0x0

    .line 359
    invoke-static/range {v7 .. v18}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 360
    .line 361
    .line 362
    move-object/from16 v10, v16

    .line 363
    .line 364
    const/4 v2, 0x0

    .line 365
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 366
    .line 367
    .line 368
    :goto_5
    iget-boolean v3, v1, Lh40/d4;->l:Z

    .line 369
    .line 370
    const v4, 0x3a5ea3f3

    .line 371
    .line 372
    .line 373
    if-eqz v3, :cond_7

    .line 374
    .line 375
    const v3, 0x3ad6928b

    .line 376
    .line 377
    .line 378
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 379
    .line 380
    .line 381
    iget-object v3, v0, Li40/i3;->p:Lay0/a;

    .line 382
    .line 383
    iget-object v5, v0, Li40/i3;->q:Lay0/a;

    .line 384
    .line 385
    invoke-static {v3, v5, v10, v2}, Li40/l1;->e0(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 386
    .line 387
    .line 388
    :goto_6
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 389
    .line 390
    .line 391
    goto :goto_7

    .line 392
    :cond_7
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 393
    .line 394
    .line 395
    goto :goto_6

    .line 396
    :goto_7
    iget-boolean v3, v1, Lh40/d4;->q:Z

    .line 397
    .line 398
    if-eqz v3, :cond_8

    .line 399
    .line 400
    const v3, 0x3ad9f194

    .line 401
    .line 402
    .line 403
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 404
    .line 405
    .line 406
    iget-object v3, v0, Li40/i3;->r:Lay0/a;

    .line 407
    .line 408
    invoke-static {v3, v10, v2}, Li40/l1;->v0(Lay0/a;Ll2/o;I)V

    .line 409
    .line 410
    .line 411
    :goto_8
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 412
    .line 413
    .line 414
    goto :goto_9

    .line 415
    :cond_8
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 416
    .line 417
    .line 418
    goto :goto_8

    .line 419
    :goto_9
    iget-boolean v3, v1, Lh40/d4;->r:Z

    .line 420
    .line 421
    if-eqz v3, :cond_9

    .line 422
    .line 423
    const v3, 0x3adccfc5

    .line 424
    .line 425
    .line 426
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 427
    .line 428
    .line 429
    iget-object v3, v0, Li40/i3;->s:Lay0/a;

    .line 430
    .line 431
    iget-object v5, v0, Li40/i3;->t:Lay0/a;

    .line 432
    .line 433
    invoke-static {v3, v5, v10, v2}, Li40/l1;->u0(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 434
    .line 435
    .line 436
    :goto_a
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 437
    .line 438
    .line 439
    goto :goto_b

    .line 440
    :cond_9
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 441
    .line 442
    .line 443
    goto :goto_a

    .line 444
    :goto_b
    iget-boolean v3, v1, Lh40/d4;->s:Z

    .line 445
    .line 446
    if-eqz v3, :cond_a

    .line 447
    .line 448
    const v3, 0x3ae0b11a

    .line 449
    .line 450
    .line 451
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 452
    .line 453
    .line 454
    iget-object v3, v0, Li40/i3;->u:Lay0/a;

    .line 455
    .line 456
    invoke-static {v3, v10, v2}, Li40/k3;->b(Lay0/a;Ll2/o;I)V

    .line 457
    .line 458
    .line 459
    :goto_c
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 460
    .line 461
    .line 462
    goto :goto_d

    .line 463
    :cond_a
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 464
    .line 465
    .line 466
    goto :goto_c

    .line 467
    :goto_d
    iget-boolean v3, v1, Lh40/d4;->t:Z

    .line 468
    .line 469
    if-eqz v3, :cond_b

    .line 470
    .line 471
    const v3, 0x3ae37c86

    .line 472
    .line 473
    .line 474
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 475
    .line 476
    .line 477
    iget-object v0, v0, Li40/i3;->v:Lay0/a;

    .line 478
    .line 479
    invoke-static {v0, v10, v2}, Li40/k3;->a(Lay0/a;Ll2/o;I)V

    .line 480
    .line 481
    .line 482
    :goto_e
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 483
    .line 484
    .line 485
    goto :goto_f

    .line 486
    :cond_b
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 487
    .line 488
    .line 489
    goto :goto_e

    .line 490
    :goto_f
    iget-boolean v0, v1, Lh40/d4;->n:Z

    .line 491
    .line 492
    if-eqz v0, :cond_c

    .line 493
    .line 494
    const v0, 0x3ae61e0c

    .line 495
    .line 496
    .line 497
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 498
    .line 499
    .line 500
    const/4 v11, 0x0

    .line 501
    const/4 v12, 0x7

    .line 502
    const/4 v7, 0x0

    .line 503
    const/4 v8, 0x0

    .line 504
    const/4 v9, 0x0

    .line 505
    invoke-static/range {v7 .. v12}, Lxf0/y1;->b(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 506
    .line 507
    .line 508
    const/4 v2, 0x0

    .line 509
    :goto_10
    invoke-virtual {v10, v2}, Ll2/t;->q(Z)V

    .line 510
    .line 511
    .line 512
    goto :goto_11

    .line 513
    :cond_c
    const/4 v2, 0x0

    .line 514
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 515
    .line 516
    .line 517
    goto :goto_10

    .line 518
    :cond_d
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 519
    .line 520
    .line 521
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 522
    .line 523
    return-object v0
.end method
