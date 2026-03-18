.class public final synthetic Lwk/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhh/e;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lhh/e;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lwk/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lwk/c;->e:Lhh/e;

    iput-object p2, p0, Lwk/c;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lhh/e;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Lwk/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lwk/c;->e:Lhh/e;

    iput-object p2, p0, Lwk/c;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lwk/c;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lwk/c;->f:Lay0/k;

    .line 8
    .line 9
    iget-object v0, v0, Lwk/c;->e:Lhh/e;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    move-object/from16 v1, p1

    .line 15
    .line 16
    check-cast v1, Ll2/o;

    .line 17
    .line 18
    move-object/from16 v4, p2

    .line 19
    .line 20
    check-cast v4, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    const/16 v4, 0x9

    .line 26
    .line 27
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    invoke-static {v0, v3, v1, v4}, Lwk/a;->g(Lhh/e;Lay0/k;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    return-object v2

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v4, p2

    .line 40
    .line 41
    check-cast v4, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    and-int/lit8 v5, v4, 0x3

    .line 48
    .line 49
    const/4 v6, 0x1

    .line 50
    const/4 v7, 0x0

    .line 51
    const/4 v8, 0x2

    .line 52
    if-eq v5, v8, :cond_0

    .line 53
    .line 54
    move v5, v6

    .line 55
    goto :goto_0

    .line 56
    :cond_0
    move v5, v7

    .line 57
    :goto_0
    and-int/2addr v4, v6

    .line 58
    check-cast v1, Ll2/t;

    .line 59
    .line 60
    invoke-virtual {v1, v4, v5}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_f

    .line 65
    .line 66
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 67
    .line 68
    invoke-static {v4, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    iget-wide v9, v1, Ll2/t;->T:J

    .line 73
    .line 74
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 83
    .line 84
    invoke-static {v1, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v11

    .line 88
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 89
    .line 90
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 94
    .line 95
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 96
    .line 97
    .line 98
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 99
    .line 100
    if-eqz v13, :cond_1

    .line 101
    .line 102
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 107
    .line 108
    .line 109
    :goto_1
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 110
    .line 111
    invoke-static {v13, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 112
    .line 113
    .line 114
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 115
    .line 116
    invoke-static {v4, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 120
    .line 121
    iget-boolean v14, v1, Ll2/t;->S:Z

    .line 122
    .line 123
    if-nez v14, :cond_2

    .line 124
    .line 125
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v14

    .line 129
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v15

    .line 133
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v14

    .line 137
    if-nez v14, :cond_3

    .line 138
    .line 139
    :cond_2
    invoke-static {v5, v1, v5, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 140
    .line 141
    .line 142
    :cond_3
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 143
    .line 144
    invoke-static {v5, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v7, v6, v1}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 148
    .line 149
    .line 150
    move-result-object v11

    .line 151
    const/16 v14, 0xe

    .line 152
    .line 153
    invoke-static {v10, v11, v14}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 154
    .line 155
    .line 156
    move-result-object v11

    .line 157
    sget-object v14, Lj91/a;->a:Ll2/u2;

    .line 158
    .line 159
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v15

    .line 163
    check-cast v15, Lj91/c;

    .line 164
    .line 165
    iget v15, v15, Lj91/c;->d:F

    .line 166
    .line 167
    invoke-static {v11, v15}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 168
    .line 169
    .line 170
    move-result-object v11

    .line 171
    sget-object v15, Lk1/j;->c:Lk1/e;

    .line 172
    .line 173
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 174
    .line 175
    invoke-static {v15, v8, v1, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 176
    .line 177
    .line 178
    move-result-object v8

    .line 179
    iget-wide v6, v1, Ll2/t;->T:J

    .line 180
    .line 181
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 182
    .line 183
    .line 184
    move-result v6

    .line 185
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 186
    .line 187
    .line 188
    move-result-object v7

    .line 189
    invoke-static {v1, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 190
    .line 191
    .line 192
    move-result-object v11

    .line 193
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 194
    .line 195
    .line 196
    move-object/from16 v16, v2

    .line 197
    .line 198
    iget-boolean v2, v1, Ll2/t;->S:Z

    .line 199
    .line 200
    if-eqz v2, :cond_4

    .line 201
    .line 202
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 203
    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 207
    .line 208
    .line 209
    :goto_2
    invoke-static {v13, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 210
    .line 211
    .line 212
    invoke-static {v4, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 213
    .line 214
    .line 215
    iget-boolean v2, v1, Ll2/t;->S:Z

    .line 216
    .line 217
    if-nez v2, :cond_5

    .line 218
    .line 219
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v2

    .line 223
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 224
    .line 225
    .line 226
    move-result-object v7

    .line 227
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v2

    .line 231
    if-nez v2, :cond_6

    .line 232
    .line 233
    :cond_5
    invoke-static {v6, v1, v6, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 234
    .line 235
    .line 236
    :cond_6
    invoke-static {v5, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 237
    .line 238
    .line 239
    const/16 v2, 0x8

    .line 240
    .line 241
    invoke-static {v0, v3, v1, v2}, Lwk/a;->g(Lhh/e;Lay0/k;Ll2/o;I)V

    .line 242
    .line 243
    .line 244
    const/4 v2, 0x1

    .line 245
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 246
    .line 247
    .line 248
    iget-boolean v2, v0, Lhh/e;->c:Z

    .line 249
    .line 250
    if-eqz v2, :cond_e

    .line 251
    .line 252
    const v2, -0x1dcd10fb

    .line 253
    .line 254
    .line 255
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 256
    .line 257
    .line 258
    const/high16 v2, 0x3f800000    # 1.0f

    .line 259
    .line 260
    invoke-static {v10, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 265
    .line 266
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v6

    .line 270
    check-cast v6, Lj91/e;

    .line 271
    .line 272
    invoke-virtual {v6}, Lj91/e;->b()J

    .line 273
    .line 274
    .line 275
    move-result-wide v6

    .line 276
    sget-object v8, Le3/j0;->a:Le3/i0;

    .line 277
    .line 278
    invoke-static {v2, v6, v7, v8}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v6

    .line 286
    check-cast v6, Lj91/c;

    .line 287
    .line 288
    iget v6, v6, Lj91/c;->g:F

    .line 289
    .line 290
    const/4 v7, 0x0

    .line 291
    const/4 v8, 0x2

    .line 292
    invoke-static {v2, v6, v7, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    sget-object v6, Lx2/c;->k:Lx2/j;

    .line 297
    .line 298
    sget-object v7, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 299
    .line 300
    invoke-virtual {v7, v2, v6}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    sget-object v6, Lzb/l;->a:Ll2/u2;

    .line 305
    .line 306
    const-string v6, "<this>"

    .line 307
    .line 308
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    new-instance v6, Lxf0/i2;

    .line 312
    .line 313
    const/16 v7, 0x1a

    .line 314
    .line 315
    invoke-direct {v6, v7}, Lxf0/i2;-><init>(I)V

    .line 316
    .line 317
    .line 318
    invoke-static {v2, v6}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    sget-object v6, Lx2/c;->q:Lx2/h;

    .line 323
    .line 324
    const/16 v7, 0x30

    .line 325
    .line 326
    invoke-static {v15, v6, v1, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 327
    .line 328
    .line 329
    move-result-object v6

    .line 330
    iget-wide v7, v1, Ll2/t;->T:J

    .line 331
    .line 332
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 333
    .line 334
    .line 335
    move-result v7

    .line 336
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 337
    .line 338
    .line 339
    move-result-object v8

    .line 340
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 341
    .line 342
    .line 343
    move-result-object v2

    .line 344
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 345
    .line 346
    .line 347
    iget-boolean v11, v1, Ll2/t;->S:Z

    .line 348
    .line 349
    if-eqz v11, :cond_7

    .line 350
    .line 351
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 352
    .line 353
    .line 354
    goto :goto_3

    .line 355
    :cond_7
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 356
    .line 357
    .line 358
    :goto_3
    invoke-static {v13, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 359
    .line 360
    .line 361
    invoke-static {v4, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 362
    .line 363
    .line 364
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 365
    .line 366
    if-nez v4, :cond_8

    .line 367
    .line 368
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v4

    .line 372
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 373
    .line 374
    .line 375
    move-result-object v6

    .line 376
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 377
    .line 378
    .line 379
    move-result v4

    .line 380
    if-nez v4, :cond_9

    .line 381
    .line 382
    :cond_8
    invoke-static {v7, v1, v7, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 383
    .line 384
    .line 385
    :cond_9
    invoke-static {v5, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 386
    .line 387
    .line 388
    iget-object v0, v0, Lhh/e;->d:Lgh/a;

    .line 389
    .line 390
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 391
    .line 392
    .line 393
    move-result v0

    .line 394
    if-eqz v0, :cond_b

    .line 395
    .line 396
    const/4 v2, 0x3

    .line 397
    if-eq v0, v2, :cond_a

    .line 398
    .line 399
    const v0, 0x430f4528

    .line 400
    .line 401
    .line 402
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 403
    .line 404
    .line 405
    const/4 v0, 0x0

    .line 406
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 407
    .line 408
    .line 409
    :goto_4
    const/4 v2, 0x1

    .line 410
    goto :goto_6

    .line 411
    :cond_a
    const/4 v0, 0x0

    .line 412
    const v2, 0x1ed4f8d5

    .line 413
    .line 414
    .line 415
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 416
    .line 417
    .line 418
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    check-cast v2, Lj91/c;

    .line 423
    .line 424
    iget v2, v2, Lj91/c;->e:F

    .line 425
    .line 426
    invoke-static {v10, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 427
    .line 428
    .line 429
    move-result-object v2

    .line 430
    invoke-static {v1, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 431
    .line 432
    .line 433
    invoke-static {v1, v0}, Llp/qe;->c(Ll2/o;I)V

    .line 434
    .line 435
    .line 436
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v2

    .line 440
    check-cast v2, Lj91/c;

    .line 441
    .line 442
    iget v2, v2, Lj91/c;->d:F

    .line 443
    .line 444
    :goto_5
    invoke-static {v10, v2, v1, v0}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 445
    .line 446
    .line 447
    goto :goto_4

    .line 448
    :cond_b
    const v0, 0x1ecf9dee

    .line 449
    .line 450
    .line 451
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 452
    .line 453
    .line 454
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    check-cast v0, Lj91/c;

    .line 459
    .line 460
    iget v0, v0, Lj91/c;->e:F

    .line 461
    .line 462
    invoke-static {v10, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 463
    .line 464
    .line 465
    move-result-object v0

    .line 466
    invoke-static {v1, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 467
    .line 468
    .line 469
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    move-result v0

    .line 473
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v2

    .line 477
    if-nez v0, :cond_c

    .line 478
    .line 479
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 480
    .line 481
    if-ne v2, v0, :cond_d

    .line 482
    .line 483
    :cond_c
    new-instance v2, Lw00/c;

    .line 484
    .line 485
    const/4 v0, 0x7

    .line 486
    invoke-direct {v2, v0, v3}, Lw00/c;-><init>(ILay0/k;)V

    .line 487
    .line 488
    .line 489
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 490
    .line 491
    .line 492
    :cond_d
    check-cast v2, Lay0/a;

    .line 493
    .line 494
    const/4 v0, 0x0

    .line 495
    invoke-static {v2, v1, v0}, Llp/qe;->a(Lay0/a;Ll2/o;I)V

    .line 496
    .line 497
    .line 498
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v2

    .line 502
    check-cast v2, Lj91/c;

    .line 503
    .line 504
    iget v2, v2, Lj91/c;->d:F

    .line 505
    .line 506
    goto :goto_5

    .line 507
    :goto_6
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 508
    .line 509
    .line 510
    :goto_7
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 511
    .line 512
    .line 513
    goto :goto_8

    .line 514
    :cond_e
    const/4 v0, 0x0

    .line 515
    const/4 v2, 0x1

    .line 516
    const v3, -0x1e44c5b1

    .line 517
    .line 518
    .line 519
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 520
    .line 521
    .line 522
    goto :goto_7

    .line 523
    :goto_8
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 524
    .line 525
    .line 526
    goto :goto_9

    .line 527
    :cond_f
    move-object/from16 v16, v2

    .line 528
    .line 529
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 530
    .line 531
    .line 532
    :goto_9
    return-object v16

    .line 533
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
