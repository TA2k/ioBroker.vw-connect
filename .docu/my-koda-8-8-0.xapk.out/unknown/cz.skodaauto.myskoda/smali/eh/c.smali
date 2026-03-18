.class public final synthetic Leh/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Leh/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Leh/c;->e:Ll2/b1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Leh/c;->d:I

    .line 4
    .line 5
    const-string v2, "wallbox"

    .line 6
    .line 7
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 8
    .line 9
    const/high16 v5, 0x3f800000    # 1.0f

    .line 10
    .line 11
    const-string v6, "/document"

    .line 12
    .line 13
    const-string v7, "doc"

    .line 14
    .line 15
    const-string v8, "id"

    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x1

    .line 19
    const-string v11, "/tariff_confirmation"

    .line 20
    .line 21
    const/4 v12, 0x2

    .line 22
    const-string v13, "result"

    .line 23
    .line 24
    const/4 v14, 0x6

    .line 25
    const/4 v15, 0x0

    .line 26
    const-string v4, "$this$navigator"

    .line 27
    .line 28
    sget-object v17, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    iget-object v0, v0, Leh/c;->e:Ll2/b1;

    .line 31
    .line 32
    packed-switch v1, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Lz9/y;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v3, "param"

    .line 47
    .line 48
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    const-string v0, "/requirements"

    .line 55
    .line 56
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 57
    .line 58
    .line 59
    return-object v17

    .line 60
    :pswitch_0
    move-object/from16 v1, p1

    .line 61
    .line 62
    check-cast v1, Lul0/e;

    .line 63
    .line 64
    move-object/from16 v1, p2

    .line 65
    .line 66
    check-cast v1, Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 69
    .line 70
    .line 71
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    return-object v17

    .line 75
    :pswitch_1
    move-object/from16 v1, p1

    .line 76
    .line 77
    check-cast v1, Ll2/o;

    .line 78
    .line 79
    move-object/from16 v2, p2

    .line 80
    .line 81
    check-cast v2, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    and-int/lit8 v3, v2, 0x3

    .line 88
    .line 89
    if-eq v3, v12, :cond_0

    .line 90
    .line 91
    move v3, v10

    .line 92
    goto :goto_0

    .line 93
    :cond_0
    move v3, v9

    .line 94
    :goto_0
    and-int/2addr v2, v10

    .line 95
    check-cast v1, Ll2/t;

    .line 96
    .line 97
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-eqz v2, :cond_1

    .line 102
    .line 103
    sget-object v2, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 104
    .line 105
    invoke-virtual {v2}, Landroidx/compose/foundation/layout/b;->b()Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    check-cast v0, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 120
    .line 121
    invoke-static {v2, v0, v3}, Lxf0/y1;->G(Lx2/s;ZLe3/n0;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-static {v0, v1, v9}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_1
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 130
    .line 131
    .line 132
    :goto_1
    return-object v17

    .line 133
    :pswitch_2
    move-object/from16 v1, p1

    .line 134
    .line 135
    check-cast v1, Lz9/y;

    .line 136
    .line 137
    move-object/from16 v11, p2

    .line 138
    .line 139
    check-cast v11, Lnc/z;

    .line 140
    .line 141
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    const-string v2, "option"

    .line 145
    .line 146
    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    move-object v5, v2

    .line 154
    check-cast v5, Lmg/c;

    .line 155
    .line 156
    const/4 v15, 0x0

    .line 157
    const/16 v16, 0x3df

    .line 158
    .line 159
    const/4 v6, 0x0

    .line 160
    const/4 v7, 0x0

    .line 161
    const/4 v8, 0x0

    .line 162
    const/4 v9, 0x0

    .line 163
    const/4 v10, 0x0

    .line 164
    const/4 v12, 0x0

    .line 165
    const/4 v13, 0x0

    .line 166
    const/4 v14, 0x0

    .line 167
    invoke-static/range {v5 .. v16}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    new-instance v0, Lmg/i;

    .line 175
    .line 176
    const/16 v2, 0xf

    .line 177
    .line 178
    invoke-direct {v0, v2}, Lmg/i;-><init>(I)V

    .line 179
    .line 180
    .line 181
    const-string v2, "/tariff_upgrade_follow_up_confirmation"

    .line 182
    .line 183
    invoke-virtual {v1, v2, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 184
    .line 185
    .line 186
    return-object v17

    .line 187
    :pswitch_3
    move-object/from16 v1, p1

    .line 188
    .line 189
    check-cast v1, Lz9/y;

    .line 190
    .line 191
    move-object/from16 v2, p2

    .line 192
    .line 193
    check-cast v2, Lpg/r;

    .line 194
    .line 195
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    iget-object v3, v2, Lpg/r;->e:Lug/a;

    .line 202
    .line 203
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    iget-object v0, v2, Lpg/r;->d:Lkg/d0;

    .line 207
    .line 208
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    const-string v2, "/overview"

    .line 212
    .line 213
    invoke-virtual {v1, v2}, Lz9/y;->b(Ljava/lang/String;)Lz9/k;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    iget-object v2, v2, Lz9/k;->l:Llx0/q;

    .line 218
    .line 219
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v2

    .line 223
    check-cast v2, Landroidx/lifecycle/s0;

    .line 224
    .line 225
    const-string v3, "navigate_with_result"

    .line 226
    .line 227
    invoke-virtual {v2, v0, v3}, Landroidx/lifecycle/s0;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    new-instance v0, Lmg/i;

    .line 231
    .line 232
    const/16 v2, 0xe

    .line 233
    .line 234
    invoke-direct {v0, v2}, Lmg/i;-><init>(I)V

    .line 235
    .line 236
    .line 237
    const-string v2, "/tariff_upgrade_follow_up_success"

    .line 238
    .line 239
    invoke-virtual {v1, v2, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 240
    .line 241
    .line 242
    return-object v17

    .line 243
    :pswitch_4
    move-object/from16 v1, p1

    .line 244
    .line 245
    check-cast v1, Lz9/y;

    .line 246
    .line 247
    move-object/from16 v2, p2

    .line 248
    .line 249
    check-cast v2, Lsg/q;

    .line 250
    .line 251
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    const-string v3, "it"

    .line 255
    .line 256
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    move-object/from16 v18, v3

    .line 264
    .line 265
    check-cast v18, Lmg/c;

    .line 266
    .line 267
    iget-object v3, v2, Lsg/q;->e:Ljava/util/List;

    .line 268
    .line 269
    iget-object v4, v2, Lsg/q;->d:Lkg/p0;

    .line 270
    .line 271
    iget-object v5, v2, Lsg/q;->f:Lnc/z;

    .line 272
    .line 273
    iget-object v2, v2, Lsg/q;->g:Ljava/lang/String;

    .line 274
    .line 275
    new-instance v6, Lac/a0;

    .line 276
    .line 277
    const-string v7, ""

    .line 278
    .line 279
    invoke-direct {v6, v7, v7}, Lac/a0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    const/16 v25, 0x0

    .line 283
    .line 284
    const/16 v29, 0x5c

    .line 285
    .line 286
    const/16 v21, 0x0

    .line 287
    .line 288
    const/16 v22, 0x0

    .line 289
    .line 290
    const/16 v23, 0x0

    .line 291
    .line 292
    sget-object v26, Lmx0/s;->d:Lmx0/s;

    .line 293
    .line 294
    move-object/from16 v28, v2

    .line 295
    .line 296
    move-object/from16 v19, v3

    .line 297
    .line 298
    move-object/from16 v20, v4

    .line 299
    .line 300
    move-object/from16 v24, v5

    .line 301
    .line 302
    move-object/from16 v27, v6

    .line 303
    .line 304
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 305
    .line 306
    .line 307
    move-result-object v2

    .line 308
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    const-string v0, "/tariff_upgrade_follow_up_details"

    .line 312
    .line 313
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 314
    .line 315
    .line 316
    return-object v17

    .line 317
    :pswitch_5
    move-object/from16 v1, p1

    .line 318
    .line 319
    check-cast v1, Lz9/y;

    .line 320
    .line 321
    move-object/from16 v2, p2

    .line 322
    .line 323
    check-cast v2, Lhc/a;

    .line 324
    .line 325
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    invoke-static {v1, v6, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 335
    .line 336
    .line 337
    return-object v17

    .line 338
    :pswitch_6
    move-object/from16 v1, p1

    .line 339
    .line 340
    check-cast v1, Lz9/y;

    .line 341
    .line 342
    move-object/from16 v2, p2

    .line 343
    .line 344
    check-cast v2, Lnc/z;

    .line 345
    .line 346
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v3

    .line 356
    move-object/from16 v18, v3

    .line 357
    .line 358
    check-cast v18, Lmg/c;

    .line 359
    .line 360
    const/16 v28, 0x0

    .line 361
    .line 362
    const/16 v29, 0x3df

    .line 363
    .line 364
    const/16 v19, 0x0

    .line 365
    .line 366
    const/16 v20, 0x0

    .line 367
    .line 368
    const/16 v21, 0x0

    .line 369
    .line 370
    const/16 v22, 0x0

    .line 371
    .line 372
    const/16 v23, 0x0

    .line 373
    .line 374
    const/16 v25, 0x0

    .line 375
    .line 376
    const/16 v26, 0x0

    .line 377
    .line 378
    const/16 v27, 0x0

    .line 379
    .line 380
    move-object/from16 v24, v2

    .line 381
    .line 382
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 383
    .line 384
    .line 385
    move-result-object v2

    .line 386
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 387
    .line 388
    .line 389
    new-instance v0, Lm40/e;

    .line 390
    .line 391
    const/16 v2, 0x1d

    .line 392
    .line 393
    invoke-direct {v0, v2}, Lm40/e;-><init>(I)V

    .line 394
    .line 395
    .line 396
    invoke-virtual {v1, v11, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 397
    .line 398
    .line 399
    return-object v17

    .line 400
    :pswitch_7
    move-object/from16 v1, p1

    .line 401
    .line 402
    check-cast v1, Lz9/y;

    .line 403
    .line 404
    move-object/from16 v2, p2

    .line 405
    .line 406
    check-cast v2, Log/a;

    .line 407
    .line 408
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v3

    .line 418
    move-object/from16 v18, v3

    .line 419
    .line 420
    check-cast v18, Lmg/c;

    .line 421
    .line 422
    iget-object v3, v2, Log/a;->a:Lac/e;

    .line 423
    .line 424
    iget-object v2, v2, Log/a;->b:Log/i;

    .line 425
    .line 426
    const/16 v28, 0x0

    .line 427
    .line 428
    const/16 v29, 0x3e7

    .line 429
    .line 430
    const/16 v19, 0x0

    .line 431
    .line 432
    const/16 v20, 0x0

    .line 433
    .line 434
    const/16 v21, 0x0

    .line 435
    .line 436
    const/16 v24, 0x0

    .line 437
    .line 438
    const/16 v25, 0x0

    .line 439
    .line 440
    const/16 v26, 0x0

    .line 441
    .line 442
    const/16 v27, 0x0

    .line 443
    .line 444
    move-object/from16 v22, v2

    .line 445
    .line 446
    move-object/from16 v23, v3

    .line 447
    .line 448
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 449
    .line 450
    .line 451
    move-result-object v2

    .line 452
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    new-instance v0, Lmg/i;

    .line 456
    .line 457
    const/4 v2, 0x3

    .line 458
    invoke-direct {v0, v2}, Lmg/i;-><init>(I)V

    .line 459
    .line 460
    .line 461
    invoke-virtual {v1, v11, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 462
    .line 463
    .line 464
    return-object v17

    .line 465
    :pswitch_8
    move-object/from16 v1, p1

    .line 466
    .line 467
    check-cast v1, Lz9/y;

    .line 468
    .line 469
    move-object/from16 v2, p2

    .line 470
    .line 471
    check-cast v2, Lng/a;

    .line 472
    .line 473
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 474
    .line 475
    .line 476
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 477
    .line 478
    .line 479
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v3

    .line 483
    move-object/from16 v18, v3

    .line 484
    .line 485
    check-cast v18, Lmg/c;

    .line 486
    .line 487
    iget-object v2, v2, Lng/a;->a:Lac/e;

    .line 488
    .line 489
    const/16 v28, 0x0

    .line 490
    .line 491
    const/16 v29, 0x3fb

    .line 492
    .line 493
    const/16 v19, 0x0

    .line 494
    .line 495
    const/16 v20, 0x0

    .line 496
    .line 497
    const/16 v22, 0x0

    .line 498
    .line 499
    const/16 v23, 0x0

    .line 500
    .line 501
    const/16 v24, 0x0

    .line 502
    .line 503
    const/16 v25, 0x0

    .line 504
    .line 505
    const/16 v26, 0x0

    .line 506
    .line 507
    const/16 v27, 0x0

    .line 508
    .line 509
    move-object/from16 v21, v2

    .line 510
    .line 511
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 512
    .line 513
    .line 514
    move-result-object v2

    .line 515
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 516
    .line 517
    .line 518
    new-instance v0, Lmg/i;

    .line 519
    .line 520
    invoke-direct {v0, v12}, Lmg/i;-><init>(I)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v1, v11, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 524
    .line 525
    .line 526
    return-object v17

    .line 527
    :pswitch_9
    move-object/from16 v1, p1

    .line 528
    .line 529
    check-cast v1, Lz9/y;

    .line 530
    .line 531
    move-object/from16 v2, p2

    .line 532
    .line 533
    check-cast v2, Lhc/a;

    .line 534
    .line 535
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 536
    .line 537
    .line 538
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 542
    .line 543
    .line 544
    const-string v0, "/consent"

    .line 545
    .line 546
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 547
    .line 548
    .line 549
    return-object v17

    .line 550
    :pswitch_a
    move-object/from16 v1, p1

    .line 551
    .line 552
    check-cast v1, Lz9/y;

    .line 553
    .line 554
    move-object/from16 v2, p2

    .line 555
    .line 556
    check-cast v2, Lnc/z;

    .line 557
    .line 558
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    const-string v3, "paymentOption"

    .line 562
    .line 563
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 564
    .line 565
    .line 566
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v3

    .line 570
    move-object/from16 v18, v3

    .line 571
    .line 572
    check-cast v18, Lmg/c;

    .line 573
    .line 574
    const/16 v28, 0x0

    .line 575
    .line 576
    const/16 v29, 0x3df

    .line 577
    .line 578
    const/16 v19, 0x0

    .line 579
    .line 580
    const/16 v20, 0x0

    .line 581
    .line 582
    const/16 v21, 0x0

    .line 583
    .line 584
    const/16 v22, 0x0

    .line 585
    .line 586
    const/16 v23, 0x0

    .line 587
    .line 588
    const/16 v25, 0x0

    .line 589
    .line 590
    const/16 v26, 0x0

    .line 591
    .line 592
    const/16 v27, 0x0

    .line 593
    .line 594
    move-object/from16 v24, v2

    .line 595
    .line 596
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 597
    .line 598
    .line 599
    move-result-object v2

    .line 600
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 601
    .line 602
    .line 603
    new-instance v0, Lmg/i;

    .line 604
    .line 605
    invoke-direct {v0, v10}, Lmg/i;-><init>(I)V

    .line 606
    .line 607
    .line 608
    invoke-virtual {v1, v11, v0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 609
    .line 610
    .line 611
    return-object v17

    .line 612
    :pswitch_b
    move-object/from16 v1, p1

    .line 613
    .line 614
    check-cast v1, Lz9/y;

    .line 615
    .line 616
    move-object/from16 v2, p2

    .line 617
    .line 618
    check-cast v2, Log/a;

    .line 619
    .line 620
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 621
    .line 622
    .line 623
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 624
    .line 625
    .line 626
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v3

    .line 630
    move-object/from16 v18, v3

    .line 631
    .line 632
    check-cast v18, Lmg/c;

    .line 633
    .line 634
    iget-object v3, v2, Log/a;->a:Lac/e;

    .line 635
    .line 636
    iget-object v2, v2, Log/a;->b:Log/i;

    .line 637
    .line 638
    const/16 v28, 0x0

    .line 639
    .line 640
    const/16 v29, 0x3e7

    .line 641
    .line 642
    const/16 v19, 0x0

    .line 643
    .line 644
    const/16 v20, 0x0

    .line 645
    .line 646
    const/16 v21, 0x0

    .line 647
    .line 648
    const/16 v24, 0x0

    .line 649
    .line 650
    const/16 v25, 0x0

    .line 651
    .line 652
    const/16 v26, 0x0

    .line 653
    .line 654
    const/16 v27, 0x0

    .line 655
    .line 656
    move-object/from16 v22, v2

    .line 657
    .line 658
    move-object/from16 v23, v3

    .line 659
    .line 660
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 661
    .line 662
    .line 663
    move-result-object v2

    .line 664
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 665
    .line 666
    .line 667
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 668
    .line 669
    .line 670
    move-result-object v0

    .line 671
    check-cast v0, Lmg/c;

    .line 672
    .line 673
    iget-object v0, v0, Lmg/c;->i:Lnc/z;

    .line 674
    .line 675
    if-eqz v0, :cond_2

    .line 676
    .line 677
    invoke-static {v1, v11, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 678
    .line 679
    .line 680
    goto :goto_2

    .line 681
    :cond_2
    const-string v0, "/payment"

    .line 682
    .line 683
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 684
    .line 685
    .line 686
    :goto_2
    return-object v17

    .line 687
    :pswitch_c
    move-object/from16 v1, p1

    .line 688
    .line 689
    check-cast v1, Lz9/y;

    .line 690
    .line 691
    move-object/from16 v2, p2

    .line 692
    .line 693
    check-cast v2, Lng/a;

    .line 694
    .line 695
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 696
    .line 697
    .line 698
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 699
    .line 700
    .line 701
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 702
    .line 703
    .line 704
    move-result-object v3

    .line 705
    move-object/from16 v18, v3

    .line 706
    .line 707
    check-cast v18, Lmg/c;

    .line 708
    .line 709
    iget-object v2, v2, Lng/a;->a:Lac/e;

    .line 710
    .line 711
    const/16 v28, 0x0

    .line 712
    .line 713
    const/16 v29, 0x3fb

    .line 714
    .line 715
    const/16 v19, 0x0

    .line 716
    .line 717
    const/16 v20, 0x0

    .line 718
    .line 719
    const/16 v22, 0x0

    .line 720
    .line 721
    const/16 v23, 0x0

    .line 722
    .line 723
    const/16 v24, 0x0

    .line 724
    .line 725
    const/16 v25, 0x0

    .line 726
    .line 727
    const/16 v26, 0x0

    .line 728
    .line 729
    const/16 v27, 0x0

    .line 730
    .line 731
    move-object/from16 v21, v2

    .line 732
    .line 733
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 734
    .line 735
    .line 736
    move-result-object v2

    .line 737
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 738
    .line 739
    .line 740
    const-string v0, "/card_delivery_address"

    .line 741
    .line 742
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 743
    .line 744
    .line 745
    return-object v17

    .line 746
    :pswitch_d
    move-object/from16 v1, p1

    .line 747
    .line 748
    check-cast v1, Lz9/y;

    .line 749
    .line 750
    move-object/from16 v2, p2

    .line 751
    .line 752
    check-cast v2, Lsg/i;

    .line 753
    .line 754
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 755
    .line 756
    .line 757
    invoke-static {v2, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 758
    .line 759
    .line 760
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v3

    .line 764
    move-object/from16 v18, v3

    .line 765
    .line 766
    check-cast v18, Lmg/c;

    .line 767
    .line 768
    iget-object v3, v2, Lsg/i;->e:Ljava/util/List;

    .line 769
    .line 770
    iget-object v4, v2, Lsg/i;->d:Lkg/p0;

    .line 771
    .line 772
    iget-boolean v5, v2, Lsg/i;->f:Z

    .line 773
    .line 774
    iget-object v6, v2, Lsg/i;->g:Ljava/util/List;

    .line 775
    .line 776
    iget-object v7, v2, Lsg/i;->h:Lac/a0;

    .line 777
    .line 778
    iget-object v2, v2, Lsg/i;->i:Lnc/z;

    .line 779
    .line 780
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 781
    .line 782
    .line 783
    move-result-object v25

    .line 784
    const/16 v28, 0x0

    .line 785
    .line 786
    const/16 v29, 0x21c

    .line 787
    .line 788
    const/16 v21, 0x0

    .line 789
    .line 790
    const/16 v22, 0x0

    .line 791
    .line 792
    const/16 v23, 0x0

    .line 793
    .line 794
    move-object/from16 v24, v2

    .line 795
    .line 796
    move-object/from16 v19, v3

    .line 797
    .line 798
    move-object/from16 v20, v4

    .line 799
    .line 800
    move-object/from16 v26, v6

    .line 801
    .line 802
    move-object/from16 v27, v7

    .line 803
    .line 804
    invoke-static/range {v18 .. v29}, Lmg/c;->i(Lmg/c;Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;I)Lmg/c;

    .line 805
    .line 806
    .line 807
    move-result-object v2

    .line 808
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 809
    .line 810
    .line 811
    const-string v0, "/tariff_details"

    .line 812
    .line 813
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 814
    .line 815
    .line 816
    return-object v17

    .line 817
    :pswitch_e
    move-object/from16 v1, p1

    .line 818
    .line 819
    check-cast v1, Lz9/y;

    .line 820
    .line 821
    move-object/from16 v2, p2

    .line 822
    .line 823
    check-cast v2, Ldd/f;

    .line 824
    .line 825
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    const-string v3, "item"

    .line 829
    .line 830
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 831
    .line 832
    .line 833
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 834
    .line 835
    .line 836
    const-string v0, "/publicDetail"

    .line 837
    .line 838
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 839
    .line 840
    .line 841
    return-object v17

    .line 842
    :pswitch_f
    move-object/from16 v1, p1

    .line 843
    .line 844
    check-cast v1, Lt4/k;

    .line 845
    .line 846
    move-object/from16 v2, p2

    .line 847
    .line 848
    check-cast v2, Lt4/k;

    .line 849
    .line 850
    sget v3, Lh2/q5;->a:F

    .line 851
    .line 852
    iget v3, v2, Lt4/k;->a:I

    .line 853
    .line 854
    iget v4, v2, Lt4/k;->d:I

    .line 855
    .line 856
    iget v6, v2, Lt4/k;->c:I

    .line 857
    .line 858
    iget v7, v2, Lt4/k;->b:I

    .line 859
    .line 860
    iget v8, v1, Lt4/k;->c:I

    .line 861
    .line 862
    iget v9, v1, Lt4/k;->b:I

    .line 863
    .line 864
    iget v10, v1, Lt4/k;->d:I

    .line 865
    .line 866
    iget v11, v1, Lt4/k;->a:I

    .line 867
    .line 868
    if-lt v3, v8, :cond_3

    .line 869
    .line 870
    :goto_3
    const/4 v1, 0x0

    .line 871
    goto :goto_4

    .line 872
    :cond_3
    if-gt v6, v11, :cond_4

    .line 873
    .line 874
    move v1, v5

    .line 875
    goto :goto_4

    .line 876
    :cond_4
    invoke-virtual {v2}, Lt4/k;->d()I

    .line 877
    .line 878
    .line 879
    move-result v8

    .line 880
    if-nez v8, :cond_5

    .line 881
    .line 882
    goto :goto_3

    .line 883
    :cond_5
    invoke-static {v11, v3}, Ljava/lang/Math;->max(II)I

    .line 884
    .line 885
    .line 886
    move-result v8

    .line 887
    iget v1, v1, Lt4/k;->c:I

    .line 888
    .line 889
    invoke-static {v1, v6}, Ljava/lang/Math;->min(II)I

    .line 890
    .line 891
    .line 892
    move-result v1

    .line 893
    add-int/2addr v1, v8

    .line 894
    div-int/2addr v1, v12

    .line 895
    sub-int/2addr v1, v3

    .line 896
    int-to-float v1, v1

    .line 897
    invoke-virtual {v2}, Lt4/k;->d()I

    .line 898
    .line 899
    .line 900
    move-result v3

    .line 901
    int-to-float v3, v3

    .line 902
    div-float/2addr v1, v3

    .line 903
    :goto_4
    if-lt v7, v10, :cond_6

    .line 904
    .line 905
    :goto_5
    const/4 v4, 0x0

    .line 906
    goto :goto_6

    .line 907
    :cond_6
    if-gt v4, v9, :cond_7

    .line 908
    .line 909
    move v4, v5

    .line 910
    goto :goto_6

    .line 911
    :cond_7
    invoke-virtual {v2}, Lt4/k;->b()I

    .line 912
    .line 913
    .line 914
    move-result v3

    .line 915
    if-nez v3, :cond_8

    .line 916
    .line 917
    goto :goto_5

    .line 918
    :cond_8
    invoke-static {v9, v7}, Ljava/lang/Math;->max(II)I

    .line 919
    .line 920
    .line 921
    move-result v3

    .line 922
    invoke-static {v10, v4}, Ljava/lang/Math;->min(II)I

    .line 923
    .line 924
    .line 925
    move-result v4

    .line 926
    add-int/2addr v4, v3

    .line 927
    div-int/2addr v4, v12

    .line 928
    sub-int/2addr v4, v7

    .line 929
    int-to-float v3, v4

    .line 930
    invoke-virtual {v2}, Lt4/k;->b()I

    .line 931
    .line 932
    .line 933
    move-result v2

    .line 934
    int-to-float v2, v2

    .line 935
    div-float v4, v3, v2

    .line 936
    .line 937
    :goto_6
    invoke-static {v1, v4}, Le3/j0;->i(FF)J

    .line 938
    .line 939
    .line 940
    move-result-wide v1

    .line 941
    new-instance v3, Le3/q0;

    .line 942
    .line 943
    invoke-direct {v3, v1, v2}, Le3/q0;-><init>(J)V

    .line 944
    .line 945
    .line 946
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 947
    .line 948
    .line 949
    return-object v17

    .line 950
    :pswitch_10
    move-object/from16 v1, p1

    .line 951
    .line 952
    check-cast v1, Lz9/y;

    .line 953
    .line 954
    move-object/from16 v2, p2

    .line 955
    .line 956
    check-cast v2, Lhc/a;

    .line 957
    .line 958
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 959
    .line 960
    .line 961
    const-string v3, "document"

    .line 962
    .line 963
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 964
    .line 965
    .line 966
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 967
    .line 968
    .line 969
    invoke-static {v1, v6, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 970
    .line 971
    .line 972
    return-object v17

    .line 973
    :pswitch_11
    move-object/from16 v1, p1

    .line 974
    .line 975
    check-cast v1, Lt4/k;

    .line 976
    .line 977
    move-object/from16 v2, p2

    .line 978
    .line 979
    check-cast v2, Lt4/k;

    .line 980
    .line 981
    sget v3, Lf2/d0;->a:F

    .line 982
    .line 983
    iget v3, v2, Lt4/k;->a:I

    .line 984
    .line 985
    iget v4, v2, Lt4/k;->d:I

    .line 986
    .line 987
    iget v6, v2, Lt4/k;->c:I

    .line 988
    .line 989
    iget v7, v2, Lt4/k;->b:I

    .line 990
    .line 991
    iget v8, v1, Lt4/k;->c:I

    .line 992
    .line 993
    iget v9, v1, Lt4/k;->b:I

    .line 994
    .line 995
    iget v10, v1, Lt4/k;->d:I

    .line 996
    .line 997
    iget v11, v1, Lt4/k;->a:I

    .line 998
    .line 999
    if-lt v3, v8, :cond_9

    .line 1000
    .line 1001
    :goto_7
    const/4 v1, 0x0

    .line 1002
    goto :goto_8

    .line 1003
    :cond_9
    if-gt v6, v11, :cond_a

    .line 1004
    .line 1005
    move v1, v5

    .line 1006
    goto :goto_8

    .line 1007
    :cond_a
    invoke-virtual {v2}, Lt4/k;->d()I

    .line 1008
    .line 1009
    .line 1010
    move-result v8

    .line 1011
    if-nez v8, :cond_b

    .line 1012
    .line 1013
    goto :goto_7

    .line 1014
    :cond_b
    invoke-static {v11, v3}, Ljava/lang/Math;->max(II)I

    .line 1015
    .line 1016
    .line 1017
    move-result v8

    .line 1018
    iget v1, v1, Lt4/k;->c:I

    .line 1019
    .line 1020
    invoke-static {v1, v6}, Ljava/lang/Math;->min(II)I

    .line 1021
    .line 1022
    .line 1023
    move-result v1

    .line 1024
    add-int/2addr v1, v8

    .line 1025
    div-int/2addr v1, v12

    .line 1026
    sub-int/2addr v1, v3

    .line 1027
    int-to-float v1, v1

    .line 1028
    invoke-virtual {v2}, Lt4/k;->d()I

    .line 1029
    .line 1030
    .line 1031
    move-result v3

    .line 1032
    int-to-float v3, v3

    .line 1033
    div-float/2addr v1, v3

    .line 1034
    :goto_8
    if-lt v7, v10, :cond_c

    .line 1035
    .line 1036
    :goto_9
    const/4 v4, 0x0

    .line 1037
    goto :goto_a

    .line 1038
    :cond_c
    if-gt v4, v9, :cond_d

    .line 1039
    .line 1040
    move v4, v5

    .line 1041
    goto :goto_a

    .line 1042
    :cond_d
    invoke-virtual {v2}, Lt4/k;->b()I

    .line 1043
    .line 1044
    .line 1045
    move-result v3

    .line 1046
    if-nez v3, :cond_e

    .line 1047
    .line 1048
    goto :goto_9

    .line 1049
    :cond_e
    invoke-static {v9, v7}, Ljava/lang/Math;->max(II)I

    .line 1050
    .line 1051
    .line 1052
    move-result v3

    .line 1053
    invoke-static {v10, v4}, Ljava/lang/Math;->min(II)I

    .line 1054
    .line 1055
    .line 1056
    move-result v4

    .line 1057
    add-int/2addr v4, v3

    .line 1058
    div-int/2addr v4, v12

    .line 1059
    sub-int/2addr v4, v7

    .line 1060
    int-to-float v3, v4

    .line 1061
    invoke-virtual {v2}, Lt4/k;->b()I

    .line 1062
    .line 1063
    .line 1064
    move-result v2

    .line 1065
    int-to-float v2, v2

    .line 1066
    div-float v4, v3, v2

    .line 1067
    .line 1068
    :goto_a
    invoke-static {v1, v4}, Le3/j0;->i(FF)J

    .line 1069
    .line 1070
    .line 1071
    move-result-wide v1

    .line 1072
    new-instance v3, Le3/q0;

    .line 1073
    .line 1074
    invoke-direct {v3, v1, v2}, Le3/q0;-><init>(J)V

    .line 1075
    .line 1076
    .line 1077
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1078
    .line 1079
    .line 1080
    return-object v17

    .line 1081
    :pswitch_12
    move-object/from16 v1, p1

    .line 1082
    .line 1083
    check-cast v1, Ll2/o;

    .line 1084
    .line 1085
    move-object/from16 v2, p2

    .line 1086
    .line 1087
    check-cast v2, Ljava/lang/Integer;

    .line 1088
    .line 1089
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1090
    .line 1091
    .line 1092
    move-result v2

    .line 1093
    and-int/lit8 v4, v2, 0x3

    .line 1094
    .line 1095
    if-eq v4, v12, :cond_f

    .line 1096
    .line 1097
    move v9, v10

    .line 1098
    :cond_f
    and-int/2addr v2, v10

    .line 1099
    check-cast v1, Ll2/t;

    .line 1100
    .line 1101
    invoke-virtual {v1, v2, v9}, Ll2/t;->O(IZ)Z

    .line 1102
    .line 1103
    .line 1104
    move-result v2

    .line 1105
    if-eqz v2, :cond_11

    .line 1106
    .line 1107
    const v2, 0x7f120bed

    .line 1108
    .line 1109
    .line 1110
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 1111
    .line 1112
    .line 1113
    move-result-object v18

    .line 1114
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v2

    .line 1118
    if-ne v2, v3, :cond_10

    .line 1119
    .line 1120
    new-instance v2, La2/h;

    .line 1121
    .line 1122
    const/16 v3, 0xb

    .line 1123
    .line 1124
    invoke-direct {v2, v0, v3}, La2/h;-><init>(Ll2/b1;I)V

    .line 1125
    .line 1126
    .line 1127
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1128
    .line 1129
    .line 1130
    :cond_10
    move-object/from16 v22, v2

    .line 1131
    .line 1132
    check-cast v22, Lay0/a;

    .line 1133
    .line 1134
    const/16 v24, 0x61b0

    .line 1135
    .line 1136
    const/16 v25, 0x0

    .line 1137
    .line 1138
    const/16 v19, 0x0

    .line 1139
    .line 1140
    const-string v20, "wallbox_elli_hyper_link"

    .line 1141
    .line 1142
    const v21, 0x7f0803a7

    .line 1143
    .line 1144
    .line 1145
    move-object/from16 v23, v1

    .line 1146
    .line 1147
    invoke-static/range {v18 .. v25}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 1148
    .line 1149
    .line 1150
    goto :goto_b

    .line 1151
    :cond_11
    move-object/from16 v23, v1

    .line 1152
    .line 1153
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 1154
    .line 1155
    .line 1156
    :goto_b
    return-object v17

    .line 1157
    :pswitch_13
    move-object/from16 v1, p1

    .line 1158
    .line 1159
    check-cast v1, Ll2/o;

    .line 1160
    .line 1161
    move-object/from16 v2, p2

    .line 1162
    .line 1163
    check-cast v2, Ljava/lang/Integer;

    .line 1164
    .line 1165
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1166
    .line 1167
    .line 1168
    move-result v2

    .line 1169
    and-int/lit8 v4, v2, 0x3

    .line 1170
    .line 1171
    if-eq v4, v12, :cond_12

    .line 1172
    .line 1173
    move v9, v10

    .line 1174
    :cond_12
    and-int/2addr v2, v10

    .line 1175
    check-cast v1, Ll2/t;

    .line 1176
    .line 1177
    invoke-virtual {v1, v2, v9}, Ll2/t;->O(IZ)Z

    .line 1178
    .line 1179
    .line 1180
    move-result v2

    .line 1181
    if-eqz v2, :cond_14

    .line 1182
    .line 1183
    const v2, 0x7f120be6

    .line 1184
    .line 1185
    .line 1186
    invoke-static {v1, v2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v18

    .line 1190
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v2

    .line 1194
    if-ne v2, v3, :cond_13

    .line 1195
    .line 1196
    new-instance v2, La2/h;

    .line 1197
    .line 1198
    const/16 v3, 0x11

    .line 1199
    .line 1200
    invoke-direct {v2, v0, v3}, La2/h;-><init>(Ll2/b1;I)V

    .line 1201
    .line 1202
    .line 1203
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1204
    .line 1205
    .line 1206
    :cond_13
    move-object/from16 v22, v2

    .line 1207
    .line 1208
    check-cast v22, Lay0/a;

    .line 1209
    .line 1210
    const/16 v24, 0x61b0

    .line 1211
    .line 1212
    const/16 v25, 0x0

    .line 1213
    .line 1214
    const/16 v19, 0x0

    .line 1215
    .line 1216
    const-string v20, "wallbox_elli_hyper_link"

    .line 1217
    .line 1218
    const v21, 0x7f0803a7

    .line 1219
    .line 1220
    .line 1221
    move-object/from16 v23, v1

    .line 1222
    .line 1223
    invoke-static/range {v18 .. v25}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 1224
    .line 1225
    .line 1226
    goto :goto_c

    .line 1227
    :cond_14
    move-object/from16 v23, v1

    .line 1228
    .line 1229
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 1230
    .line 1231
    .line 1232
    :goto_c
    return-object v17

    .line 1233
    :pswitch_14
    move-object/from16 v1, p1

    .line 1234
    .line 1235
    check-cast v1, Lz9/y;

    .line 1236
    .line 1237
    move-object/from16 v2, p2

    .line 1238
    .line 1239
    check-cast v2, Ljava/lang/String;

    .line 1240
    .line 1241
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1242
    .line 1243
    .line 1244
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1245
    .line 1246
    .line 1247
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1248
    .line 1249
    .line 1250
    const-string v0, "/detail"

    .line 1251
    .line 1252
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1253
    .line 1254
    .line 1255
    return-object v17

    .line 1256
    :pswitch_15
    move-object/from16 v1, p1

    .line 1257
    .line 1258
    check-cast v1, Lz9/y;

    .line 1259
    .line 1260
    move-object/from16 v2, p2

    .line 1261
    .line 1262
    check-cast v2, Ljava/lang/Boolean;

    .line 1263
    .line 1264
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1265
    .line 1266
    .line 1267
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1268
    .line 1269
    .line 1270
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1271
    .line 1272
    .line 1273
    const-string v0, "/charging_sessions"

    .line 1274
    .line 1275
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1276
    .line 1277
    .line 1278
    return-object v17

    .line 1279
    :pswitch_16
    move-object/from16 v1, p1

    .line 1280
    .line 1281
    check-cast v1, Lz9/y;

    .line 1282
    .line 1283
    move-object/from16 v3, p2

    .line 1284
    .line 1285
    check-cast v3, Lzg/h;

    .line 1286
    .line 1287
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1288
    .line 1289
    .line 1290
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1291
    .line 1292
    .line 1293
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1294
    .line 1295
    .line 1296
    const-string v0, "/pv_charging_trigger"

    .line 1297
    .line 1298
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1299
    .line 1300
    .line 1301
    return-object v17

    .line 1302
    :pswitch_17
    move-object/from16 v1, p1

    .line 1303
    .line 1304
    check-cast v1, Lz9/y;

    .line 1305
    .line 1306
    move-object/from16 v3, p2

    .line 1307
    .line 1308
    check-cast v3, Lzg/h;

    .line 1309
    .line 1310
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1311
    .line 1312
    .line 1313
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1314
    .line 1315
    .line 1316
    invoke-interface {v0, v3}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1317
    .line 1318
    .line 1319
    const-string v0, "/pv_charging"

    .line 1320
    .line 1321
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1322
    .line 1323
    .line 1324
    return-object v17

    .line 1325
    :pswitch_18
    move-object/from16 v1, p1

    .line 1326
    .line 1327
    check-cast v1, Lz9/y;

    .line 1328
    .line 1329
    move-object/from16 v2, p2

    .line 1330
    .line 1331
    check-cast v2, Ljava/lang/String;

    .line 1332
    .line 1333
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1334
    .line 1335
    .line 1336
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1337
    .line 1338
    .line 1339
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1340
    .line 1341
    .line 1342
    const-string v0, "/firmware"

    .line 1343
    .line 1344
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1345
    .line 1346
    .line 1347
    return-object v17

    .line 1348
    :pswitch_19
    move-object/from16 v1, p1

    .line 1349
    .line 1350
    check-cast v1, Lz9/y;

    .line 1351
    .line 1352
    move-object/from16 v2, p2

    .line 1353
    .line 1354
    check-cast v2, Ljava/lang/String;

    .line 1355
    .line 1356
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1357
    .line 1358
    .line 1359
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1360
    .line 1361
    .line 1362
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1363
    .line 1364
    .line 1365
    const-string v0, "/settings"

    .line 1366
    .line 1367
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1368
    .line 1369
    .line 1370
    return-object v17

    .line 1371
    :pswitch_1a
    move-object/from16 v1, p1

    .line 1372
    .line 1373
    check-cast v1, Lz9/y;

    .line 1374
    .line 1375
    move-object/from16 v2, p2

    .line 1376
    .line 1377
    check-cast v2, Ldi/a;

    .line 1378
    .line 1379
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1380
    .line 1381
    .line 1382
    const-string v3, "mode"

    .line 1383
    .line 1384
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1385
    .line 1386
    .line 1387
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1388
    .line 1389
    .line 1390
    const-string v0, "/change_auth_mode"

    .line 1391
    .line 1392
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1393
    .line 1394
    .line 1395
    return-object v17

    .line 1396
    :pswitch_1b
    move-object/from16 v1, p1

    .line 1397
    .line 1398
    check-cast v1, Lz9/y;

    .line 1399
    .line 1400
    move-object/from16 v2, p2

    .line 1401
    .line 1402
    check-cast v2, Ldi/b;

    .line 1403
    .line 1404
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1405
    .line 1406
    .line 1407
    const-string v3, "name"

    .line 1408
    .line 1409
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1410
    .line 1411
    .line 1412
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1413
    .line 1414
    .line 1415
    const-string v0, "/change_name"

    .line 1416
    .line 1417
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1418
    .line 1419
    .line 1420
    return-object v17

    .line 1421
    :pswitch_1c
    move-object/from16 v1, p1

    .line 1422
    .line 1423
    check-cast v1, Lz9/y;

    .line 1424
    .line 1425
    move-object/from16 v2, p2

    .line 1426
    .line 1427
    check-cast v2, Lai/a;

    .line 1428
    .line 1429
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1430
    .line 1431
    .line 1432
    const-string v3, "pv"

    .line 1433
    .line 1434
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1435
    .line 1436
    .line 1437
    invoke-interface {v0, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1438
    .line 1439
    .line 1440
    const-string v0, "/solar_system_details"

    .line 1441
    .line 1442
    invoke-static {v1, v0, v15, v14}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 1443
    .line 1444
    .line 1445
    return-object v17

    .line 1446
    nop

    .line 1447
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
