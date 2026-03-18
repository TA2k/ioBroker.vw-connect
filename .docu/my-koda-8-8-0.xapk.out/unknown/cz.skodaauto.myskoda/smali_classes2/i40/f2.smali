.class public final synthetic Li40/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:I

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/util/ArrayList;ILvy0/b0;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li40/f2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/f2;->h:Ljava/lang/Object;

    iput-object p2, p0, Li40/f2;->e:Ljava/util/ArrayList;

    iput p3, p0, Li40/f2;->f:I

    iput-object p4, p0, Li40/f2;->i:Ljava/lang/Object;

    iput-object p5, p0, Li40/f2;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/ArrayList;ILay0/k;Ll2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li40/f2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/f2;->h:Ljava/lang/Object;

    iput-object p2, p0, Li40/f2;->e:Ljava/util/ArrayList;

    iput p3, p0, Li40/f2;->f:I

    iput-object p4, p0, Li40/f2;->g:Lay0/k;

    iput-object p5, p0, Li40/f2;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/f2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li40/f2;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-object v2, v0, Li40/f2;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ll2/b1;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Lxf0/d2;

    .line 19
    .line 20
    move-object/from16 v4, p2

    .line 21
    .line 22
    check-cast v4, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v5, p3

    .line 25
    .line 26
    check-cast v5, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const-string v6, "$this$ModalBottomSheetDialog"

    .line 33
    .line 34
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    and-int/lit8 v3, v5, 0x11

    .line 38
    .line 39
    const/16 v6, 0x10

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v8, 0x1

    .line 43
    if-eq v3, v6, :cond_0

    .line 44
    .line 45
    move v3, v8

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move v3, v7

    .line 48
    :goto_0
    and-int/2addr v5, v8

    .line 49
    move-object v14, v4

    .line 50
    check-cast v14, Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v14, v5, v3}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_e

    .line 57
    .line 58
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    iget v3, v3, Lj91/c;->j:F

    .line 63
    .line 64
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 65
    .line 66
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 71
    .line 72
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 73
    .line 74
    invoke-static {v5, v6, v14, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    iget-wide v9, v14, Ll2/t;->T:J

    .line 79
    .line 80
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 85
    .line 86
    .line 87
    move-result-object v9

    .line 88
    invoke-static {v14, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 93
    .line 94
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 98
    .line 99
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 100
    .line 101
    .line 102
    iget-boolean v11, v14, Ll2/t;->S:Z

    .line 103
    .line 104
    if-eqz v11, :cond_1

    .line 105
    .line 106
    invoke-virtual {v14, v10}, Ll2/t;->l(Lay0/a;)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_1
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 111
    .line 112
    .line 113
    :goto_1
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 114
    .line 115
    invoke-static {v10, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 119
    .line 120
    invoke-static {v5, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 121
    .line 122
    .line 123
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 124
    .line 125
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 126
    .line 127
    if-nez v9, :cond_2

    .line 128
    .line 129
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 134
    .line 135
    .line 136
    move-result-object v10

    .line 137
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v9

    .line 141
    if-nez v9, :cond_3

    .line 142
    .line 143
    :cond_2
    invoke-static {v6, v14, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 144
    .line 145
    .line 146
    :cond_3
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 147
    .line 148
    invoke-static {v5, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    const v3, 0x7f120428

    .line 152
    .line 153
    .line 154
    invoke-static {v14, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v9

    .line 158
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    invoke-virtual {v3}, Lj91/f;->k()Lg4/p0;

    .line 163
    .line 164
    .line 165
    move-result-object v10

    .line 166
    const/high16 v3, 0x3f800000    # 1.0f

    .line 167
    .line 168
    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    const-string v5, "charging_settings_max_charge_current_title"

    .line 173
    .line 174
    invoke-static {v3, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v11

    .line 178
    const/16 v29, 0x0

    .line 179
    .line 180
    const v30, 0xfff8

    .line 181
    .line 182
    .line 183
    const-wide/16 v12, 0x0

    .line 184
    .line 185
    move-object/from16 v27, v14

    .line 186
    .line 187
    const-wide/16 v14, 0x0

    .line 188
    .line 189
    const/16 v16, 0x0

    .line 190
    .line 191
    const-wide/16 v17, 0x0

    .line 192
    .line 193
    const/16 v19, 0x0

    .line 194
    .line 195
    const/16 v20, 0x0

    .line 196
    .line 197
    const-wide/16 v21, 0x0

    .line 198
    .line 199
    const/16 v23, 0x0

    .line 200
    .line 201
    const/16 v24, 0x0

    .line 202
    .line 203
    const/16 v25, 0x0

    .line 204
    .line 205
    const/16 v26, 0x0

    .line 206
    .line 207
    const/16 v28, 0x180

    .line 208
    .line 209
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 210
    .line 211
    .line 212
    move-object/from16 v14, v27

    .line 213
    .line 214
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v3

    .line 218
    check-cast v3, Lrd0/d0;

    .line 219
    .line 220
    iget v3, v3, Lrd0/d0;->a:I

    .line 221
    .line 222
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    const v5, 0x7f12042a

    .line 231
    .line 232
    .line 233
    invoke-static {v5, v3, v14}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v9

    .line 237
    invoke-static {v14}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 242
    .line 243
    .line 244
    move-result-object v10

    .line 245
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 246
    .line 247
    .line 248
    move-result-object v3

    .line 249
    iget v3, v3, Lj91/c;->b:F

    .line 250
    .line 251
    const/16 v19, 0x0

    .line 252
    .line 253
    const/16 v20, 0xd

    .line 254
    .line 255
    const/16 v16, 0x0

    .line 256
    .line 257
    const/16 v18, 0x0

    .line 258
    .line 259
    move/from16 v17, v3

    .line 260
    .line 261
    move-object v15, v4

    .line 262
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    const-string v5, "charging_settings_max_charge_current_description"

    .line 267
    .line 268
    invoke-static {v3, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 269
    .line 270
    .line 271
    move-result-object v11

    .line 272
    const-wide/16 v14, 0x0

    .line 273
    .line 274
    const/16 v16, 0x0

    .line 275
    .line 276
    const-wide/16 v17, 0x0

    .line 277
    .line 278
    const/16 v19, 0x0

    .line 279
    .line 280
    const/16 v20, 0x0

    .line 281
    .line 282
    const/16 v28, 0x0

    .line 283
    .line 284
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 285
    .line 286
    .line 287
    move-object/from16 v14, v27

    .line 288
    .line 289
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 290
    .line 291
    .line 292
    move-result v3

    .line 293
    add-int/lit8 v5, v3, -0x1

    .line 294
    .line 295
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    check-cast v6, Lrd0/d0;

    .line 300
    .line 301
    iget v6, v6, Lrd0/d0;->a:I

    .line 302
    .line 303
    new-instance v9, Lrd0/d0;

    .line 304
    .line 305
    invoke-direct {v9, v6}, Lrd0/d0;-><init>(I)V

    .line 306
    .line 307
    .line 308
    invoke-interface {v1, v9}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 309
    .line 310
    .line 311
    move-result v6

    .line 312
    if-gez v6, :cond_4

    .line 313
    .line 314
    move v6, v7

    .line 315
    :cond_4
    int-to-float v9, v6

    .line 316
    int-to-float v5, v5

    .line 317
    new-instance v12, Lgy0/e;

    .line 318
    .line 319
    const/4 v6, 0x0

    .line 320
    invoke-direct {v12, v6, v5}, Lgy0/e;-><init>(FF)V

    .line 321
    .line 322
    .line 323
    add-int/lit8 v3, v3, -0x2

    .line 324
    .line 325
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 326
    .line 327
    .line 328
    move-result-object v5

    .line 329
    iget v5, v5, Lj91/c;->e:F

    .line 330
    .line 331
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 332
    .line 333
    .line 334
    move-result-object v6

    .line 335
    iget v6, v6, Lj91/c;->d:F

    .line 336
    .line 337
    invoke-static {v4, v6, v5}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v4

    .line 341
    const-string v5, "charging_settings_max_charge_current_slider"

    .line 342
    .line 343
    invoke-static {v4, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 344
    .line 345
    .line 346
    move-result-object v11

    .line 347
    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    move-result v4

    .line 351
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v5

    .line 355
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 356
    .line 357
    if-nez v4, :cond_5

    .line 358
    .line 359
    if-ne v5, v6, :cond_6

    .line 360
    .line 361
    :cond_5
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 362
    .line 363
    const/16 v4, 0x12

    .line 364
    .line 365
    invoke-direct {v5, v4, v1, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    :cond_6
    move-object v10, v5

    .line 372
    check-cast v10, Lay0/k;

    .line 373
    .line 374
    iget-object v1, v0, Li40/f2;->e:Ljava/util/ArrayList;

    .line 375
    .line 376
    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 377
    .line 378
    .line 379
    move-result v4

    .line 380
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v5

    .line 384
    if-nez v4, :cond_7

    .line 385
    .line 386
    if-ne v5, v6, :cond_8

    .line 387
    .line 388
    :cond_7
    new-instance v5, Le2/j0;

    .line 389
    .line 390
    const/4 v4, 0x3

    .line 391
    invoke-direct {v5, v1, v4}, Le2/j0;-><init>(Ljava/util/ArrayList;I)V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 395
    .line 396
    .line 397
    :cond_8
    move-object v15, v5

    .line 398
    check-cast v15, Lay0/k;

    .line 399
    .line 400
    invoke-virtual {v14, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 401
    .line 402
    .line 403
    move-result v4

    .line 404
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v5

    .line 408
    if-nez v4, :cond_9

    .line 409
    .line 410
    if-ne v5, v6, :cond_a

    .line 411
    .line 412
    :cond_9
    new-instance v5, Le2/j0;

    .line 413
    .line 414
    const/4 v4, 0x4

    .line 415
    invoke-direct {v5, v1, v4}, Le2/j0;-><init>(Ljava/util/ArrayList;I)V

    .line 416
    .line 417
    .line 418
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 419
    .line 420
    .line 421
    :cond_a
    move-object/from16 v16, v5

    .line 422
    .line 423
    check-cast v16, Lay0/k;

    .line 424
    .line 425
    const/16 v19, 0x0

    .line 426
    .line 427
    const/16 v20, 0x110

    .line 428
    .line 429
    const/4 v13, 0x0

    .line 430
    const/16 v17, 0x0

    .line 431
    .line 432
    move-object/from16 v18, v14

    .line 433
    .line 434
    move v14, v3

    .line 435
    invoke-static/range {v9 .. v20}, Li91/u3;->b(FLay0/k;Lx2/s;Lgy0/f;ZILay0/k;Lay0/k;Lay0/a;Ll2/o;II)V

    .line 436
    .line 437
    .line 438
    move-object/from16 v14, v18

    .line 439
    .line 440
    const v1, 0x7f120427

    .line 441
    .line 442
    .line 443
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 444
    .line 445
    .line 446
    move-result-object v13

    .line 447
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 448
    .line 449
    .line 450
    move-result-object v1

    .line 451
    check-cast v1, Lrd0/d0;

    .line 452
    .line 453
    iget v1, v1, Lrd0/d0;->a:I

    .line 454
    .line 455
    iget v3, v0, Li40/f2;->f:I

    .line 456
    .line 457
    if-ne v3, v1, :cond_b

    .line 458
    .line 459
    move v7, v8

    .line 460
    :cond_b
    xor-int/lit8 v16, v7, 0x1

    .line 461
    .line 462
    sget-object v1, Lx2/c;->q:Lx2/h;

    .line 463
    .line 464
    new-instance v3, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 465
    .line 466
    invoke-direct {v3, v1}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Lx2/h;)V

    .line 467
    .line 468
    .line 469
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 470
    .line 471
    .line 472
    move-result-object v1

    .line 473
    iget v1, v1, Lj91/c;->c:F

    .line 474
    .line 475
    invoke-static {v14}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 476
    .line 477
    .line 478
    move-result-object v4

    .line 479
    iget v4, v4, Lj91/c;->d:F

    .line 480
    .line 481
    const/16 v22, 0x5

    .line 482
    .line 483
    const/16 v18, 0x0

    .line 484
    .line 485
    const/16 v20, 0x0

    .line 486
    .line 487
    move/from16 v19, v1

    .line 488
    .line 489
    move-object/from16 v17, v3

    .line 490
    .line 491
    move/from16 v21, v4

    .line 492
    .line 493
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 494
    .line 495
    .line 496
    move-result-object v1

    .line 497
    const-string v3, "charging_settings_max_charge_current_button_save"

    .line 498
    .line 499
    invoke-static {v1, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 500
    .line 501
    .line 502
    move-result-object v15

    .line 503
    iget-object v0, v0, Li40/f2;->g:Lay0/k;

    .line 504
    .line 505
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 506
    .line 507
    .line 508
    move-result v1

    .line 509
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v3

    .line 513
    if-nez v1, :cond_c

    .line 514
    .line 515
    if-ne v3, v6, :cond_d

    .line 516
    .line 517
    :cond_c
    new-instance v3, Lel/g;

    .line 518
    .line 519
    const/4 v1, 0x4

    .line 520
    invoke-direct {v3, v0, v2, v1}, Lel/g;-><init>(Lay0/k;Ll2/b1;I)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 524
    .line 525
    .line 526
    :cond_d
    move-object v11, v3

    .line 527
    check-cast v11, Lay0/a;

    .line 528
    .line 529
    const/4 v9, 0x0

    .line 530
    const/16 v10, 0x28

    .line 531
    .line 532
    const/4 v12, 0x0

    .line 533
    const/16 v17, 0x0

    .line 534
    .line 535
    invoke-static/range {v9 .. v17}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 536
    .line 537
    .line 538
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 539
    .line 540
    .line 541
    goto :goto_2

    .line 542
    :cond_e
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 543
    .line 544
    .line 545
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 546
    .line 547
    return-object v0

    .line 548
    :pswitch_0
    iget-object v1, v0, Li40/f2;->h:Ljava/lang/Object;

    .line 549
    .line 550
    move-object v2, v1

    .line 551
    check-cast v2, Ljava/lang/String;

    .line 552
    .line 553
    iget-object v1, v0, Li40/f2;->i:Ljava/lang/Object;

    .line 554
    .line 555
    check-cast v1, Lvy0/b0;

    .line 556
    .line 557
    move-object/from16 v3, p1

    .line 558
    .line 559
    check-cast v3, Lxf0/d2;

    .line 560
    .line 561
    move-object/from16 v4, p2

    .line 562
    .line 563
    check-cast v4, Ll2/o;

    .line 564
    .line 565
    move-object/from16 v5, p3

    .line 566
    .line 567
    check-cast v5, Ljava/lang/Integer;

    .line 568
    .line 569
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 570
    .line 571
    .line 572
    move-result v5

    .line 573
    const-string v6, "$this$ModalBottomSheetDialog"

    .line 574
    .line 575
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    and-int/lit8 v6, v5, 0x6

    .line 579
    .line 580
    const/4 v7, 0x4

    .line 581
    if-nez v6, :cond_11

    .line 582
    .line 583
    and-int/lit8 v6, v5, 0x8

    .line 584
    .line 585
    if-nez v6, :cond_f

    .line 586
    .line 587
    move-object v6, v4

    .line 588
    check-cast v6, Ll2/t;

    .line 589
    .line 590
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 591
    .line 592
    .line 593
    move-result v6

    .line 594
    goto :goto_3

    .line 595
    :cond_f
    move-object v6, v4

    .line 596
    check-cast v6, Ll2/t;

    .line 597
    .line 598
    invoke-virtual {v6, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 599
    .line 600
    .line 601
    move-result v6

    .line 602
    :goto_3
    if-eqz v6, :cond_10

    .line 603
    .line 604
    move v6, v7

    .line 605
    goto :goto_4

    .line 606
    :cond_10
    const/4 v6, 0x2

    .line 607
    :goto_4
    or-int/2addr v5, v6

    .line 608
    :cond_11
    and-int/lit8 v6, v5, 0x13

    .line 609
    .line 610
    const/16 v8, 0x12

    .line 611
    .line 612
    const/4 v9, 0x0

    .line 613
    const/4 v10, 0x1

    .line 614
    if-eq v6, v8, :cond_12

    .line 615
    .line 616
    move v6, v10

    .line 617
    goto :goto_5

    .line 618
    :cond_12
    move v6, v9

    .line 619
    :goto_5
    and-int/lit8 v8, v5, 0x1

    .line 620
    .line 621
    check-cast v4, Ll2/t;

    .line 622
    .line 623
    invoke-virtual {v4, v8, v6}, Ll2/t;->O(IZ)Z

    .line 624
    .line 625
    .line 626
    move-result v6

    .line 627
    if-eqz v6, :cond_17

    .line 628
    .line 629
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 630
    .line 631
    .line 632
    move-result v6

    .line 633
    and-int/lit8 v8, v5, 0xe

    .line 634
    .line 635
    if-eq v8, v7, :cond_13

    .line 636
    .line 637
    and-int/lit8 v5, v5, 0x8

    .line 638
    .line 639
    if-eqz v5, :cond_14

    .line 640
    .line 641
    invoke-virtual {v4, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 642
    .line 643
    .line 644
    move-result v5

    .line 645
    if-eqz v5, :cond_14

    .line 646
    .line 647
    :cond_13
    move v9, v10

    .line 648
    :cond_14
    or-int v5, v6, v9

    .line 649
    .line 650
    iget-object v6, v0, Li40/f2;->g:Lay0/k;

    .line 651
    .line 652
    invoke-virtual {v4, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 653
    .line 654
    .line 655
    move-result v7

    .line 656
    or-int/2addr v5, v7

    .line 657
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 658
    .line 659
    .line 660
    move-result-object v7

    .line 661
    if-nez v5, :cond_15

    .line 662
    .line 663
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 664
    .line 665
    if-ne v7, v5, :cond_16

    .line 666
    .line 667
    :cond_15
    new-instance v7, Li40/g2;

    .line 668
    .line 669
    const/4 v5, 0x0

    .line 670
    invoke-direct {v7, v1, v3, v6, v5}, Li40/g2;-><init>(Lvy0/b0;Lxf0/d2;Lay0/k;I)V

    .line 671
    .line 672
    .line 673
    invoke-virtual {v4, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 674
    .line 675
    .line 676
    :cond_16
    move-object v5, v7

    .line 677
    check-cast v5, Lay0/k;

    .line 678
    .line 679
    const/4 v7, 0x0

    .line 680
    iget-object v3, v0, Li40/f2;->e:Ljava/util/ArrayList;

    .line 681
    .line 682
    iget v0, v0, Li40/f2;->f:I

    .line 683
    .line 684
    move-object v6, v4

    .line 685
    move v4, v0

    .line 686
    invoke-static/range {v2 .. v7}, Li40/l1;->f0(Ljava/lang/String;Ljava/util/ArrayList;ILay0/k;Ll2/o;I)V

    .line 687
    .line 688
    .line 689
    goto :goto_6

    .line 690
    :cond_17
    move-object v6, v4

    .line 691
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 692
    .line 693
    .line 694
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 695
    .line 696
    return-object v0

    .line 697
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
