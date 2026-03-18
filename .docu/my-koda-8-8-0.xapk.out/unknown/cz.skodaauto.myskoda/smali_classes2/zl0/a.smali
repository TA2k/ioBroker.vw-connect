.class public final synthetic Lzl0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lzl0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Lzl0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lzl0/a;->d:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, "$this$factory"

    .line 7
    .line 8
    const-string v3, "$this$single"

    .line 9
    .line 10
    const/4 v4, 0x1

    .line 11
    const/4 v5, 0x0

    .line 12
    const-string v6, "it"

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object/from16 v0, p1

    .line 18
    .line 19
    check-cast v0, Ll2/o;

    .line 20
    .line 21
    move-object/from16 v1, p2

    .line 22
    .line 23
    check-cast v1, Ljava/lang/Integer;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-static {v0, v1}, Lzz/a;->e(Ll2/o;I)V

    .line 33
    .line 34
    .line 35
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object v0

    .line 38
    :pswitch_0
    move-object/from16 v0, p1

    .line 39
    .line 40
    check-cast v0, Ll2/o;

    .line 41
    .line 42
    move-object/from16 v2, p2

    .line 43
    .line 44
    check-cast v2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    and-int/lit8 v3, v2, 0x3

    .line 51
    .line 52
    const/4 v5, 0x2

    .line 53
    if-eq v3, v5, :cond_0

    .line 54
    .line 55
    move v1, v4

    .line 56
    :cond_0
    and-int/2addr v2, v4

    .line 57
    move-object v9, v0

    .line 58
    check-cast v9, Ll2/t;

    .line 59
    .line 60
    invoke-virtual {v9, v2, v1}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-eqz v0, :cond_2

    .line 65
    .line 66
    new-instance v6, Lyz/d;

    .line 67
    .line 68
    const-string v0, "English"

    .line 69
    .line 70
    invoke-direct {v6, v0}, Lyz/d;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 78
    .line 79
    if-ne v0, v1, :cond_1

    .line 80
    .line 81
    new-instance v0, Lz81/g;

    .line 82
    .line 83
    invoke-direct {v0, v5}, Lz81/g;-><init>(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_1
    move-object v7, v0

    .line 90
    check-cast v7, Lay0/a;

    .line 91
    .line 92
    const/16 v10, 0x30

    .line 93
    .line 94
    const/4 v11, 0x4

    .line 95
    const/4 v8, 0x0

    .line 96
    invoke-static/range {v6 .. v11}, Lzz/a;->d(Lyz/d;Lay0/a;Lx2/s;Ll2/o;II)V

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_2
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object v0

    .line 106
    :pswitch_1
    move-object/from16 v0, p1

    .line 107
    .line 108
    check-cast v0, Ll2/o;

    .line 109
    .line 110
    move-object/from16 v1, p2

    .line 111
    .line 112
    check-cast v1, Ljava/lang/Integer;

    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    invoke-static {v0, v1}, Lzz/a;->a(Ll2/o;I)V

    .line 122
    .line 123
    .line 124
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object v0

    .line 127
    :pswitch_2
    move-object/from16 v0, p1

    .line 128
    .line 129
    check-cast v0, Ljava/lang/Integer;

    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    move-object/from16 v1, p2

    .line 136
    .line 137
    check-cast v1, Lpx0/e;

    .line 138
    .line 139
    add-int/2addr v0, v4

    .line 140
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    return-object v0

    .line 145
    :pswitch_3
    move-object/from16 v0, p1

    .line 146
    .line 147
    check-cast v0, Lk21/a;

    .line 148
    .line 149
    move-object/from16 v1, p2

    .line 150
    .line 151
    check-cast v1, Lg21/a;

    .line 152
    .line 153
    const-string v2, "$this$viewModel"

    .line 154
    .line 155
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    new-instance v7, Lct0/h;

    .line 162
    .line 163
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 164
    .line 165
    const-class v2, Lij0/a;

    .line 166
    .line 167
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    move-object v8, v2

    .line 176
    check-cast v8, Lij0/a;

    .line 177
    .line 178
    const-class v2, Lat0/a;

    .line 179
    .line 180
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    move-object v9, v2

    .line 189
    check-cast v9, Lat0/a;

    .line 190
    .line 191
    const-class v2, Lat0/d;

    .line 192
    .line 193
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    move-object v10, v2

    .line 202
    check-cast v10, Lat0/d;

    .line 203
    .line 204
    const-class v2, Lat0/l;

    .line 205
    .line 206
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v2

    .line 214
    move-object v11, v2

    .line 215
    check-cast v11, Lat0/l;

    .line 216
    .line 217
    const-class v2, Lat0/h;

    .line 218
    .line 219
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 220
    .line 221
    .line 222
    move-result-object v2

    .line 223
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    move-object v12, v2

    .line 228
    check-cast v12, Lat0/h;

    .line 229
    .line 230
    const-class v2, Lpg0/c;

    .line 231
    .line 232
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v2

    .line 240
    move-object v13, v2

    .line 241
    check-cast v13, Lpg0/c;

    .line 242
    .line 243
    const-class v2, Lat0/g;

    .line 244
    .line 245
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    move-object v14, v2

    .line 254
    check-cast v14, Lat0/g;

    .line 255
    .line 256
    const-class v2, Lat0/n;

    .line 257
    .line 258
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 259
    .line 260
    .line 261
    move-result-object v2

    .line 262
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    move-object v15, v2

    .line 267
    check-cast v15, Lat0/n;

    .line 268
    .line 269
    const-class v2, Lat0/i;

    .line 270
    .line 271
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-virtual {v0, v1, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    move-object/from16 v16, v0

    .line 280
    .line 281
    check-cast v16, Lat0/i;

    .line 282
    .line 283
    invoke-direct/range {v7 .. v16}, Lct0/h;-><init>(Lij0/a;Lat0/a;Lat0/d;Lat0/l;Lat0/h;Lpg0/c;Lat0/g;Lat0/n;Lat0/i;)V

    .line 284
    .line 285
    .line 286
    return-object v7

    .line 287
    :pswitch_4
    move-object/from16 v0, p1

    .line 288
    .line 289
    check-cast v0, Lk21/a;

    .line 290
    .line 291
    move-object/from16 v2, p2

    .line 292
    .line 293
    check-cast v2, Lg21/a;

    .line 294
    .line 295
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    new-instance v2, Lcom/google/android/material/datepicker/d;

    .line 302
    .line 303
    :try_start_0
    const-class v3, Landroid/app/Application;

    .line 304
    .line 305
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 306
    .line 307
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 308
    .line 309
    .line 310
    move-result-object v3

    .line 311
    invoke-virtual {v0, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v3

    .line 315
    check-cast v3, Landroid/app/Application;
    :try_end_0
    .catch Lb21/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 316
    .line 317
    const/4 v1, 0x4

    .line 318
    invoke-direct {v2, v3, v1}, Lcom/google/android/material/datepicker/d;-><init>(Landroid/content/Context;I)V

    .line 319
    .line 320
    .line 321
    new-instance v3, Ljava/util/ArrayList;

    .line 322
    .line 323
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 324
    .line 325
    .line 326
    new-instance v5, Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 329
    .line 330
    .line 331
    new-instance v6, Ljava/util/ArrayList;

    .line 332
    .line 333
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 334
    .line 335
    .line 336
    new-instance v7, Ljava/util/ArrayList;

    .line 337
    .line 338
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 339
    .line 340
    .line 341
    new-instance v8, Ljava/util/ArrayList;

    .line 342
    .line 343
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 344
    .line 345
    .line 346
    new-instance v9, Lsc0/a;

    .line 347
    .line 348
    const/4 v10, 0x3

    .line 349
    invoke-direct {v9, v0, v10}, Lsc0/a;-><init>(Lk21/a;I)V

    .line 350
    .line 351
    .line 352
    new-instance v0, Lim/j;

    .line 353
    .line 354
    new-instance v10, Lha0/f;

    .line 355
    .line 356
    const/16 v11, 0xa

    .line 357
    .line 358
    invoke-direct {v10, v9, v11}, Lha0/f;-><init>(Lay0/a;I)V

    .line 359
    .line 360
    .line 361
    invoke-direct {v0, v10}, Lim/j;-><init>(Lay0/a;)V

    .line 362
    .line 363
    .line 364
    const-class v9, Lyl/t;

    .line 365
    .line 366
    invoke-virtual {v4, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 367
    .line 368
    .line 369
    move-result-object v4

    .line 370
    new-instance v9, Lyj/b;

    .line 371
    .line 372
    invoke-direct {v9, v1, v0, v4}, Lyj/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    new-instance v10, Lyl/d;

    .line 379
    .line 380
    invoke-static {v3}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 381
    .line 382
    .line 383
    move-result-object v11

    .line 384
    invoke-static {v5}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 385
    .line 386
    .line 387
    move-result-object v12

    .line 388
    invoke-static {v6}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 389
    .line 390
    .line 391
    move-result-object v13

    .line 392
    invoke-static {v7}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 393
    .line 394
    .line 395
    move-result-object v14

    .line 396
    invoke-static {v8}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 397
    .line 398
    .line 399
    move-result-object v15

    .line 400
    invoke-direct/range {v10 .. v15}, Lyl/d;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 401
    .line 402
    .line 403
    iput-object v10, v2, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 404
    .line 405
    sget-object v0, Lsm/e;->d:[Lsm/e;

    .line 406
    .line 407
    invoke-virtual {v2}, Lcom/google/android/material/datepicker/d;->f()Lyl/r;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    return-object v0

    .line 412
    :catch_0
    new-instance v0, Lt11/a;

    .line 413
    .line 414
    const-string v2, "Can\'t resolve Application instance. Please use androidContext() function in your KoinApplication configuration."

    .line 415
    .line 416
    invoke-direct {v0, v2, v1}, Lt11/a;-><init>(Ljava/lang/String;I)V

    .line 417
    .line 418
    .line 419
    throw v0

    .line 420
    :pswitch_5
    move-object/from16 v0, p1

    .line 421
    .line 422
    check-cast v0, Lk21/a;

    .line 423
    .line 424
    move-object/from16 v1, p2

    .line 425
    .line 426
    check-cast v1, Lg21/a;

    .line 427
    .line 428
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 432
    .line 433
    .line 434
    const/4 v9, 0x0

    .line 435
    const/16 v10, 0x7f

    .line 436
    .line 437
    const/4 v4, 0x0

    .line 438
    const/4 v5, 0x0

    .line 439
    const/4 v6, 0x0

    .line 440
    const/4 v7, 0x0

    .line 441
    const/4 v8, 0x0

    .line 442
    move-object v3, v0

    .line 443
    invoke-static/range {v3 .. v10}, Lzl0/b;->b(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;I)Ld01/h0;

    .line 444
    .line 445
    .line 446
    move-result-object v0

    .line 447
    return-object v0

    .line 448
    :pswitch_6
    move-object/from16 v0, p1

    .line 449
    .line 450
    check-cast v0, Lk21/a;

    .line 451
    .line 452
    move-object/from16 v1, p2

    .line 453
    .line 454
    check-cast v1, Lg21/a;

    .line 455
    .line 456
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    new-instance v1, Lt01/c;

    .line 463
    .line 464
    new-instance v2, Lyn/e;

    .line 465
    .line 466
    invoke-direct {v2, v0}, Lyn/e;-><init>(Lk21/a;)V

    .line 467
    .line 468
    .line 469
    invoke-direct {v1, v2}, Lt01/c;-><init>(Lt01/b;)V

    .line 470
    .line 471
    .line 472
    sget-object v0, Lt01/a;->f:Lt01/a;

    .line 473
    .line 474
    iput-object v0, v1, Lt01/c;->b:Lt01/a;

    .line 475
    .line 476
    return-object v1

    .line 477
    :pswitch_7
    move-object/from16 v0, p1

    .line 478
    .line 479
    check-cast v0, Lk21/a;

    .line 480
    .line 481
    move-object/from16 v1, p2

    .line 482
    .line 483
    check-cast v1, Lg21/a;

    .line 484
    .line 485
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    new-instance v1, Ldm0/b;

    .line 492
    .line 493
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 494
    .line 495
    const-class v3, Lam0/d;

    .line 496
    .line 497
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 498
    .line 499
    .line 500
    move-result-object v3

    .line 501
    invoke-virtual {v0, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v3

    .line 505
    check-cast v3, Lam0/d;

    .line 506
    .line 507
    const-class v4, Landroid/content/Context;

    .line 508
    .line 509
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 510
    .line 511
    .line 512
    move-result-object v2

    .line 513
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    check-cast v0, Landroid/content/Context;

    .line 518
    .line 519
    invoke-direct {v1, v3, v0}, Ldm0/b;-><init>(Lam0/d;Landroid/content/Context;)V

    .line 520
    .line 521
    .line 522
    return-object v1

    .line 523
    :pswitch_8
    move-object/from16 v0, p1

    .line 524
    .line 525
    check-cast v0, Lk21/a;

    .line 526
    .line 527
    move-object/from16 v1, p2

    .line 528
    .line 529
    check-cast v1, Lg21/a;

    .line 530
    .line 531
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 532
    .line 533
    .line 534
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    new-instance v1, Ldm0/k;

    .line 538
    .line 539
    invoke-static {v0}, Llp/va;->a(Lk21/a;)Landroid/content/Context;

    .line 540
    .line 541
    .line 542
    move-result-object v2

    .line 543
    const-class v3, Landroid/net/ConnectivityManager;

    .line 544
    .line 545
    invoke-virtual {v2, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v2

    .line 549
    const-string v3, "getSystemService(...)"

    .line 550
    .line 551
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    check-cast v2, Landroid/net/ConnectivityManager;

    .line 555
    .line 556
    const-class v3, Lyl0/a;

    .line 557
    .line 558
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 559
    .line 560
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 561
    .line 562
    .line 563
    move-result-object v3

    .line 564
    invoke-virtual {v0, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    check-cast v0, Lyl0/a;

    .line 569
    .line 570
    invoke-direct {v1, v2, v0}, Ldm0/k;-><init>(Landroid/net/ConnectivityManager;Lyl0/a;)V

    .line 571
    .line 572
    .line 573
    return-object v1

    .line 574
    :pswitch_9
    move-object/from16 v0, p1

    .line 575
    .line 576
    check-cast v0, Lk21/a;

    .line 577
    .line 578
    move-object/from16 v1, p2

    .line 579
    .line 580
    check-cast v1, Lg21/a;

    .line 581
    .line 582
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 583
    .line 584
    .line 585
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 586
    .line 587
    .line 588
    new-instance v1, Lam0/z;

    .line 589
    .line 590
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 591
    .line 592
    const-string v3, "null"

    .line 593
    .line 594
    const-class v4, Ldx/i;

    .line 595
    .line 596
    invoke-static {v2, v4, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 597
    .line 598
    .line 599
    move-result-object v3

    .line 600
    const-class v4, Lti0/a;

    .line 601
    .line 602
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 603
    .line 604
    .line 605
    move-result-object v4

    .line 606
    invoke-virtual {v0, v4, v3, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object v3

    .line 610
    check-cast v3, Lti0/a;

    .line 611
    .line 612
    const-class v4, Lam0/u;

    .line 613
    .line 614
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 615
    .line 616
    .line 617
    move-result-object v2

    .line 618
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 619
    .line 620
    .line 621
    move-result-object v0

    .line 622
    check-cast v0, Lam0/u;

    .line 623
    .line 624
    invoke-direct {v1, v3, v0}, Lam0/z;-><init>(Lti0/a;Lam0/u;)V

    .line 625
    .line 626
    .line 627
    return-object v1

    .line 628
    nop

    .line 629
    :pswitch_data_0
    .packed-switch 0x0
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
