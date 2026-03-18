.class public final synthetic Lz61/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;


# direct methods
.method public synthetic constructor <init>(ZZLay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    iput p6, p0, Lz61/l;->d:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lz61/l;->e:Z

    .line 4
    .line 5
    iput-boolean p2, p0, Lz61/l;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Lz61/l;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Lz61/l;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Lz61/l;->i:Lay0/a;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz61/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/q;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$FuSiScaffold"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v4, v3, 0x6

    .line 30
    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    move-object v4, v2

    .line 34
    check-cast v4, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    const/4 v4, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v4, 0x2

    .line 45
    :goto_0
    or-int/2addr v3, v4

    .line 46
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 47
    .line 48
    const/16 v6, 0x12

    .line 49
    .line 50
    const/4 v7, 0x0

    .line 51
    const/4 v8, 0x1

    .line 52
    if-eq v4, v6, :cond_2

    .line 53
    .line 54
    move v4, v8

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v4, v7

    .line 57
    :goto_1
    and-int/2addr v3, v8

    .line 58
    check-cast v2, Ll2/t;

    .line 59
    .line 60
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v3

    .line 64
    if-eqz v3, :cond_9

    .line 65
    .line 66
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 67
    .line 68
    const/high16 v4, 0x3f800000    # 1.0f

    .line 69
    .line 70
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    sget-object v9, Lh71/o;->a:Ll2/u2;

    .line 75
    .line 76
    invoke-virtual {v2, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v9

    .line 80
    check-cast v9, Lh71/n;

    .line 81
    .line 82
    iget v9, v9, Lh71/n;->a:F

    .line 83
    .line 84
    sget-object v10, Lh71/u;->a:Ll2/u2;

    .line 85
    .line 86
    invoke-virtual {v2, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v11

    .line 90
    check-cast v11, Lh71/t;

    .line 91
    .line 92
    iget v11, v11, Lh71/t;->g:F

    .line 93
    .line 94
    add-float/2addr v9, v11

    .line 95
    invoke-static {v6, v9}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    sget-object v9, Lx2/c;->k:Lx2/j;

    .line 100
    .line 101
    invoke-interface {v1, v6, v9}, Lk1/q;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    sget-object v6, Lx2/c;->d:Lx2/j;

    .line 106
    .line 107
    invoke-static {v6, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 108
    .line 109
    .line 110
    move-result-object v9

    .line 111
    iget-wide v11, v2, Ll2/t;->T:J

    .line 112
    .line 113
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 114
    .line 115
    .line 116
    move-result v11

    .line 117
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 118
    .line 119
    .line 120
    move-result-object v12

    .line 121
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 126
    .line 127
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 131
    .line 132
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 133
    .line 134
    .line 135
    iget-boolean v14, v2, Ll2/t;->S:Z

    .line 136
    .line 137
    if-eqz v14, :cond_3

    .line 138
    .line 139
    invoke-virtual {v2, v13}, Ll2/t;->l(Lay0/a;)V

    .line 140
    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_3
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 144
    .line 145
    .line 146
    :goto_2
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 147
    .line 148
    invoke-static {v14, v9, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v9, Lv3/j;->f:Lv3/h;

    .line 152
    .line 153
    invoke-static {v9, v12, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 157
    .line 158
    iget-boolean v15, v2, Ll2/t;->S:Z

    .line 159
    .line 160
    if-nez v15, :cond_4

    .line 161
    .line 162
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v15

    .line 166
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v8

    .line 170
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v8

    .line 174
    if-nez v8, :cond_5

    .line 175
    .line 176
    :cond_4
    invoke-static {v11, v2, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 177
    .line 178
    .line 179
    :cond_5
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 180
    .line 181
    invoke-static {v8, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 182
    .line 183
    .line 184
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    sget-object v11, Lx2/c;->e:Lx2/j;

    .line 189
    .line 190
    sget-object v15, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 191
    .line 192
    invoke-virtual {v15, v1, v11}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    invoke-static {v6, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    iget-wide v4, v2, Ll2/t;->T:J

    .line 201
    .line 202
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 203
    .line 204
    .line 205
    move-result v4

    .line 206
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 215
    .line 216
    .line 217
    iget-boolean v7, v2, Ll2/t;->S:Z

    .line 218
    .line 219
    if-eqz v7, :cond_6

    .line 220
    .line 221
    invoke-virtual {v2, v13}, Ll2/t;->l(Lay0/a;)V

    .line 222
    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_6
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 226
    .line 227
    .line 228
    :goto_3
    invoke-static {v14, v6, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 229
    .line 230
    .line 231
    invoke-static {v9, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 232
    .line 233
    .line 234
    iget-boolean v5, v2, Ll2/t;->S:Z

    .line 235
    .line 236
    if-nez v5, :cond_7

    .line 237
    .line 238
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v5

    .line 242
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    if-nez v5, :cond_8

    .line 251
    .line 252
    :cond_7
    invoke-static {v4, v2, v4, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 253
    .line 254
    .line 255
    :cond_8
    invoke-static {v8, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 256
    .line 257
    .line 258
    const/high16 v1, 0x3f800000    # 1.0f

    .line 259
    .line 260
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    invoke-virtual {v2, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    check-cast v3, Lh71/t;

    .line 269
    .line 270
    iget v3, v3, Lh71/t;->e:F

    .line 271
    .line 272
    const/4 v4, 0x0

    .line 273
    const/4 v5, 0x2

    .line 274
    invoke-static {v1, v3, v4, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    const-string v1, "touch_diagnosis_button_normal_state"

    .line 279
    .line 280
    invoke-static {v1, v2}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v10

    .line 284
    sget-object v1, Lh71/m;->a:Ll2/u2;

    .line 285
    .line 286
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    check-cast v1, Lh71/l;

    .line 291
    .line 292
    iget-object v1, v1, Lh71/l;->c:Lh71/f;

    .line 293
    .line 294
    iget-object v13, v1, Lh71/f;->b:Lh71/w;

    .line 295
    .line 296
    const/16 v19, 0x0

    .line 297
    .line 298
    const/16 v20, 0x42

    .line 299
    .line 300
    iget-boolean v11, v0, Lz61/l;->e:Z

    .line 301
    .line 302
    iget-boolean v12, v0, Lz61/l;->f:Z

    .line 303
    .line 304
    const/4 v14, 0x0

    .line 305
    iget-object v15, v0, Lz61/l;->g:Lay0/a;

    .line 306
    .line 307
    iget-object v1, v0, Lz61/l;->h:Lay0/a;

    .line 308
    .line 309
    iget-object v0, v0, Lz61/l;->i:Lay0/a;

    .line 310
    .line 311
    move-object/from16 v17, v0

    .line 312
    .line 313
    move-object/from16 v16, v1

    .line 314
    .line 315
    move-object/from16 v18, v2

    .line 316
    .line 317
    invoke-static/range {v9 .. v20}, Lkp/h0;->b(Lx2/s;Ljava/lang/String;ZZLh71/w;Le71/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 318
    .line 319
    .line 320
    const/4 v0, 0x1

    .line 321
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 325
    .line 326
    .line 327
    goto :goto_4

    .line 328
    :cond_9
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 329
    .line 330
    .line 331
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 332
    .line 333
    return-object v0

    .line 334
    :pswitch_0
    move-object/from16 v1, p1

    .line 335
    .line 336
    check-cast v1, Lk1/t;

    .line 337
    .line 338
    move-object/from16 v2, p2

    .line 339
    .line 340
    check-cast v2, Ll2/o;

    .line 341
    .line 342
    move-object/from16 v3, p3

    .line 343
    .line 344
    check-cast v3, Ljava/lang/Integer;

    .line 345
    .line 346
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 347
    .line 348
    .line 349
    move-result v3

    .line 350
    const-string v4, "$this$RpaScaffold"

    .line 351
    .line 352
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 353
    .line 354
    .line 355
    and-int/lit8 v4, v3, 0x6

    .line 356
    .line 357
    if-nez v4, :cond_b

    .line 358
    .line 359
    move-object v4, v2

    .line 360
    check-cast v4, Ll2/t;

    .line 361
    .line 362
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 363
    .line 364
    .line 365
    move-result v4

    .line 366
    if-eqz v4, :cond_a

    .line 367
    .line 368
    const/4 v4, 0x4

    .line 369
    goto :goto_5

    .line 370
    :cond_a
    const/4 v4, 0x2

    .line 371
    :goto_5
    or-int/2addr v3, v4

    .line 372
    :cond_b
    and-int/lit8 v4, v3, 0x13

    .line 373
    .line 374
    const/16 v5, 0x12

    .line 375
    .line 376
    const/4 v6, 0x0

    .line 377
    const/4 v7, 0x1

    .line 378
    if-eq v4, v5, :cond_c

    .line 379
    .line 380
    move v4, v7

    .line 381
    goto :goto_6

    .line 382
    :cond_c
    move v4, v6

    .line 383
    :goto_6
    and-int/2addr v3, v7

    .line 384
    move-object v11, v2

    .line 385
    check-cast v11, Ll2/t;

    .line 386
    .line 387
    invoke-virtual {v11, v3, v4}, Ll2/t;->O(IZ)Z

    .line 388
    .line 389
    .line 390
    move-result v2

    .line 391
    if-eqz v2, :cond_11

    .line 392
    .line 393
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 394
    .line 395
    const/high16 v3, 0x3f800000    # 1.0f

    .line 396
    .line 397
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 398
    .line 399
    .line 400
    move-result-object v4

    .line 401
    invoke-static {v1, v4}, Lk1/t;->c(Lk1/t;Lx2/s;)Lx2/s;

    .line 402
    .line 403
    .line 404
    move-result-object v1

    .line 405
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 406
    .line 407
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 408
    .line 409
    invoke-static {v4, v5, v11, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 410
    .line 411
    .line 412
    move-result-object v4

    .line 413
    iget-wide v8, v11, Ll2/t;->T:J

    .line 414
    .line 415
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 416
    .line 417
    .line 418
    move-result v5

    .line 419
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 420
    .line 421
    .line 422
    move-result-object v8

    .line 423
    invoke-static {v11, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 428
    .line 429
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 430
    .line 431
    .line 432
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 433
    .line 434
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 435
    .line 436
    .line 437
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 438
    .line 439
    if-eqz v10, :cond_d

    .line 440
    .line 441
    invoke-virtual {v11, v9}, Ll2/t;->l(Lay0/a;)V

    .line 442
    .line 443
    .line 444
    goto :goto_7

    .line 445
    :cond_d
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 446
    .line 447
    .line 448
    :goto_7
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 449
    .line 450
    invoke-static {v9, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 451
    .line 452
    .line 453
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 454
    .line 455
    invoke-static {v4, v8, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 456
    .line 457
    .line 458
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 459
    .line 460
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 461
    .line 462
    if-nez v8, :cond_e

    .line 463
    .line 464
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v8

    .line 468
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 469
    .line 470
    .line 471
    move-result-object v9

    .line 472
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    move-result v8

    .line 476
    if-nez v8, :cond_f

    .line 477
    .line 478
    :cond_e
    invoke-static {v5, v11, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 479
    .line 480
    .line 481
    :cond_f
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 482
    .line 483
    invoke-static {v4, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 484
    .line 485
    .line 486
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 487
    .line 488
    .line 489
    move-result-object v1

    .line 490
    sget-object v4, Lh71/u;->a:Ll2/u2;

    .line 491
    .line 492
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v4

    .line 496
    check-cast v4, Lh71/t;

    .line 497
    .line 498
    iget v4, v4, Lh71/t;->e:F

    .line 499
    .line 500
    const/4 v5, 0x0

    .line 501
    invoke-static {v1, v5, v4, v7}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 502
    .line 503
    .line 504
    move-result-object v1

    .line 505
    invoke-static {v1, v11, v6}, Lz61/m;->b(Lx2/s;Ll2/o;I)V

    .line 506
    .line 507
    .line 508
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 509
    .line 510
    .line 511
    move-result-object v1

    .line 512
    float-to-double v4, v3

    .line 513
    const-wide/16 v8, 0x0

    .line 514
    .line 515
    cmpl-double v2, v4, v8

    .line 516
    .line 517
    if-lez v2, :cond_10

    .line 518
    .line 519
    goto :goto_8

    .line 520
    :cond_10
    const-string v2, "invalid weight; must be greater than zero"

    .line 521
    .line 522
    invoke-static {v2}, Ll1/a;->a(Ljava/lang/String;)V

    .line 523
    .line 524
    .line 525
    :goto_8
    new-instance v2, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 526
    .line 527
    invoke-direct {v2, v3, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 528
    .line 529
    .line 530
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 531
    .line 532
    .line 533
    move-result-object v8

    .line 534
    new-instance v1, Lz61/l;

    .line 535
    .line 536
    const/4 v6, 0x1

    .line 537
    move-object v2, v1

    .line 538
    iget-boolean v1, v0, Lz61/l;->e:Z

    .line 539
    .line 540
    move-object v3, v2

    .line 541
    iget-boolean v2, v0, Lz61/l;->f:Z

    .line 542
    .line 543
    move-object v4, v3

    .line 544
    iget-object v3, v0, Lz61/l;->g:Lay0/a;

    .line 545
    .line 546
    move-object v5, v4

    .line 547
    iget-object v4, v0, Lz61/l;->h:Lay0/a;

    .line 548
    .line 549
    iget-object v0, v0, Lz61/l;->i:Lay0/a;

    .line 550
    .line 551
    move-object/from16 v21, v5

    .line 552
    .line 553
    move-object v5, v0

    .line 554
    move-object/from16 v0, v21

    .line 555
    .line 556
    invoke-direct/range {v0 .. v6}, Lz61/l;-><init>(ZZLay0/a;Lay0/a;Lay0/a;I)V

    .line 557
    .line 558
    .line 559
    const v1, -0x45249519

    .line 560
    .line 561
    .line 562
    invoke-static {v1, v11, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 563
    .line 564
    .line 565
    move-result-object v10

    .line 566
    const/16 v12, 0x180

    .line 567
    .line 568
    const/4 v13, 0x2

    .line 569
    const/4 v9, 0x0

    .line 570
    invoke-static/range {v8 .. v13}, Lc71/a;->a(Lx2/s;Lay0/o;Lt2/b;Ll2/o;II)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v11, v7}, Ll2/t;->q(Z)V

    .line 574
    .line 575
    .line 576
    goto :goto_9

    .line 577
    :cond_11
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 578
    .line 579
    .line 580
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 581
    .line 582
    return-object v0

    .line 583
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
