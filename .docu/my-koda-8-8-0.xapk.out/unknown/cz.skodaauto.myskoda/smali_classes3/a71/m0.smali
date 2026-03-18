.class public final synthetic La71/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 1
    iput p4, p0, La71/m0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La71/m0;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, La71/m0;->g:Ljava/lang/Object;

    .line 6
    .line 7
    iput-boolean p3, p0, La71/m0;->e:Z

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La71/m0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, La71/m0;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-object v2, v0, La71/m0;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lay0/k;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Lp1/p;

    .line 19
    .line 20
    move-object/from16 v4, p2

    .line 21
    .line 22
    check-cast v4, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    move-object/from16 v10, p3

    .line 29
    .line 30
    check-cast v10, Ll2/o;

    .line 31
    .line 32
    move-object/from16 v5, p4

    .line 33
    .line 34
    check-cast v5, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    const-string v6, "$this$HorizontalPager"

    .line 41
    .line 42
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    move v3, v5

    .line 46
    sget-object v5, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 47
    .line 48
    sget-object v6, Lx2/c;->d:Lx2/j;

    .line 49
    .line 50
    const/4 v13, 0x0

    .line 51
    invoke-static {v6, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    move-object v14, v10

    .line 56
    check-cast v14, Ll2/t;

    .line 57
    .line 58
    iget-wide v7, v14, Ll2/t;->T:J

    .line 59
    .line 60
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    invoke-static {v10, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 73
    .line 74
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 78
    .line 79
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 80
    .line 81
    .line 82
    iget-boolean v12, v14, Ll2/t;->S:Z

    .line 83
    .line 84
    if-eqz v12, :cond_0

    .line 85
    .line 86
    invoke-virtual {v14, v11}, Ll2/t;->l(Lay0/a;)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 91
    .line 92
    .line 93
    :goto_0
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 94
    .line 95
    invoke-static {v11, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 96
    .line 97
    .line 98
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 99
    .line 100
    invoke-static {v6, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 101
    .line 102
    .line 103
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 104
    .line 105
    iget-boolean v8, v14, Ll2/t;->S:Z

    .line 106
    .line 107
    if-nez v8, :cond_1

    .line 108
    .line 109
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v11

    .line 117
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-nez v8, :cond_2

    .line 122
    .line 123
    :cond_1
    invoke-static {v7, v14, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 124
    .line 125
    .line 126
    :cond_2
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 127
    .line 128
    invoke-static {v6, v9, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    move-object v6, v1

    .line 136
    check-cast v6, Lhp0/e;

    .line 137
    .line 138
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    and-int/lit8 v7, v3, 0x70

    .line 143
    .line 144
    xor-int/lit8 v7, v7, 0x30

    .line 145
    .line 146
    const/16 v8, 0x20

    .line 147
    .line 148
    const/4 v15, 0x1

    .line 149
    if-le v7, v8, :cond_3

    .line 150
    .line 151
    invoke-virtual {v14, v4}, Ll2/t;->e(I)Z

    .line 152
    .line 153
    .line 154
    move-result v7

    .line 155
    if-nez v7, :cond_4

    .line 156
    .line 157
    :cond_3
    and-int/lit8 v3, v3, 0x30

    .line 158
    .line 159
    if-ne v3, v8, :cond_5

    .line 160
    .line 161
    :cond_4
    move v3, v15

    .line 162
    goto :goto_1

    .line 163
    :cond_5
    move v3, v13

    .line 164
    :goto_1
    or-int/2addr v1, v3

    .line 165
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    if-nez v1, :cond_6

    .line 170
    .line 171
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 172
    .line 173
    if-ne v3, v1, :cond_7

    .line 174
    .line 175
    :cond_6
    new-instance v3, Lcz/k;

    .line 176
    .line 177
    const/4 v1, 0x5

    .line 178
    invoke-direct {v3, v4, v1, v2}, Lcz/k;-><init>(IILay0/k;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    :cond_7
    move-object v9, v3

    .line 185
    check-cast v9, Lay0/a;

    .line 186
    .line 187
    const/16 v11, 0xc06

    .line 188
    .line 189
    const/4 v12, 0x4

    .line 190
    const/4 v7, 0x0

    .line 191
    sget-object v8, Lt3/j;->d:Lt3/x0;

    .line 192
    .line 193
    invoke-static/range {v5 .. v12}, Llp/xa;->c(Lx2/s;Lhp0/e;ILt3/k;Lay0/a;Ll2/o;II)V

    .line 194
    .line 195
    .line 196
    iget-boolean v0, v0, La71/m0;->e:Z

    .line 197
    .line 198
    if-eqz v0, :cond_8

    .line 199
    .line 200
    const v0, -0x73916b82

    .line 201
    .line 202
    .line 203
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 204
    .line 205
    .line 206
    const-wide v0, 0x99000000L

    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 212
    .line 213
    .line 214
    move-result-wide v0

    .line 215
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 216
    .line 217
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 218
    .line 219
    invoke-static {v3, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    invoke-interface {v0, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    const/4 v1, 0x6

    .line 228
    invoke-static {v0, v10, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 229
    .line 230
    .line 231
    :goto_2
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 232
    .line 233
    .line 234
    goto :goto_3

    .line 235
    :cond_8
    const v0, -0x73c64c56

    .line 236
    .line 237
    .line 238
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 239
    .line 240
    .line 241
    goto :goto_2

    .line 242
    :goto_3
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 243
    .line 244
    .line 245
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 246
    .line 247
    return-object v0

    .line 248
    :pswitch_0
    iget-object v1, v0, La71/m0;->f:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v1, Ly1/i;

    .line 251
    .line 252
    iget-object v2, v0, La71/m0;->g:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v2, Lxh/e;

    .line 255
    .line 256
    move-object/from16 v3, p1

    .line 257
    .line 258
    check-cast v3, Lb1/n;

    .line 259
    .line 260
    move-object/from16 v4, p2

    .line 261
    .line 262
    check-cast v4, Lz9/k;

    .line 263
    .line 264
    move-object/from16 v5, p3

    .line 265
    .line 266
    check-cast v5, Ll2/o;

    .line 267
    .line 268
    move-object/from16 v6, p4

    .line 269
    .line 270
    check-cast v6, Ljava/lang/Integer;

    .line 271
    .line 272
    const-string v7, "$this$composable"

    .line 273
    .line 274
    const-string v8, "it"

    .line 275
    .line 276
    invoke-static {v6, v3, v7, v4, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    iget-boolean v0, v0, La71/m0;->e:Z

    .line 280
    .line 281
    if-eqz v0, :cond_9

    .line 282
    .line 283
    move-object v0, v1

    .line 284
    goto :goto_5

    .line 285
    :cond_9
    const/4 v0, 0x0

    .line 286
    :goto_5
    if-nez v0, :cond_a

    .line 287
    .line 288
    sget-object v0, Lfc/a;->a:Lz81/g;

    .line 289
    .line 290
    :cond_a
    const/4 v3, 0x0

    .line 291
    invoke-static {v1, v0, v2, v5, v3}, Llp/ca;->a(Ly1/i;Lay0/a;Lxh/e;Ll2/o;I)V

    .line 292
    .line 293
    .line 294
    goto :goto_4

    .line 295
    :pswitch_1
    iget-object v1, v0, La71/m0;->f:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v1, Lx61/b;

    .line 298
    .line 299
    iget-object v2, v0, La71/m0;->g:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast v2, Lt71/d;

    .line 302
    .line 303
    move-object/from16 v3, p1

    .line 304
    .line 305
    check-cast v3, Lk1/q;

    .line 306
    .line 307
    move-object/from16 v4, p2

    .line 308
    .line 309
    check-cast v4, Lh71/a;

    .line 310
    .line 311
    move-object/from16 v5, p3

    .line 312
    .line 313
    check-cast v5, Ll2/o;

    .line 314
    .line 315
    move-object/from16 v6, p4

    .line 316
    .line 317
    check-cast v6, Ljava/lang/Integer;

    .line 318
    .line 319
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 320
    .line 321
    .line 322
    move-result v6

    .line 323
    const-string v7, "$this$DriveScaffold"

    .line 324
    .line 325
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    const-string v3, "backgroundTheme"

    .line 329
    .line 330
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    and-int/lit8 v3, v6, 0x30

    .line 334
    .line 335
    if-nez v3, :cond_c

    .line 336
    .line 337
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 338
    .line 339
    .line 340
    move-result v3

    .line 341
    move-object v7, v5

    .line 342
    check-cast v7, Ll2/t;

    .line 343
    .line 344
    invoke-virtual {v7, v3}, Ll2/t;->e(I)Z

    .line 345
    .line 346
    .line 347
    move-result v3

    .line 348
    if-eqz v3, :cond_b

    .line 349
    .line 350
    const/16 v3, 0x20

    .line 351
    .line 352
    goto :goto_6

    .line 353
    :cond_b
    const/16 v3, 0x10

    .line 354
    .line 355
    :goto_6
    or-int/2addr v6, v3

    .line 356
    :cond_c
    and-int/lit16 v3, v6, 0x91

    .line 357
    .line 358
    const/16 v7, 0x90

    .line 359
    .line 360
    const/4 v8, 0x1

    .line 361
    const/4 v9, 0x0

    .line 362
    if-eq v3, v7, :cond_d

    .line 363
    .line 364
    move v3, v8

    .line 365
    goto :goto_7

    .line 366
    :cond_d
    move v3, v9

    .line 367
    :goto_7
    and-int/lit8 v7, v6, 0x1

    .line 368
    .line 369
    check-cast v5, Ll2/t;

    .line 370
    .line 371
    invoke-virtual {v5, v7, v3}, Ll2/t;->O(IZ)Z

    .line 372
    .line 373
    .line 374
    move-result v3

    .line 375
    if-eqz v3, :cond_10

    .line 376
    .line 377
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 378
    .line 379
    .line 380
    move-result v1

    .line 381
    if-eqz v1, :cond_f

    .line 382
    .line 383
    if-ne v1, v8, :cond_e

    .line 384
    .line 385
    const v1, -0x444531

    .line 386
    .line 387
    .line 388
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 389
    .line 390
    .line 391
    shl-int/lit8 v1, v6, 0x3

    .line 392
    .line 393
    and-int/lit16 v1, v1, 0x380

    .line 394
    .line 395
    or-int/lit8 v1, v1, 0x6

    .line 396
    .line 397
    iget-boolean v0, v0, La71/m0;->e:Z

    .line 398
    .line 399
    invoke-static {v0, v4, v5, v1}, La71/s0;->f(ZLh71/a;Ll2/o;I)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 403
    .line 404
    .line 405
    goto :goto_8

    .line 406
    :cond_e
    const v0, -0x4a54efd5

    .line 407
    .line 408
    .line 409
    invoke-static {v0, v5, v9}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 410
    .line 411
    .line 412
    move-result-object v0

    .line 413
    throw v0

    .line 414
    :cond_f
    const v0, -0x4a54ea27

    .line 415
    .line 416
    .line 417
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 418
    .line 419
    .line 420
    shl-int/lit8 v0, v6, 0x3

    .line 421
    .line 422
    and-int/lit16 v0, v0, 0x380

    .line 423
    .line 424
    or-int/lit8 v0, v0, 0x6

    .line 425
    .line 426
    invoke-static {v2, v4, v5, v0}, La71/s0;->a(Lt71/d;Lh71/a;Ll2/o;I)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 430
    .line 431
    .line 432
    goto :goto_8

    .line 433
    :cond_10
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 434
    .line 435
    .line 436
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 437
    .line 438
    return-object v0

    .line 439
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
