.class public final synthetic Lw81/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw81/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw81/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lw81/c;->d:I

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const/4 v3, 0x4

    .line 7
    const/4 v4, 0x3

    .line 8
    const-string v5, "$this$LifecycleStartEffect"

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    const-string v7, "it"

    .line 12
    .line 13
    const/4 v8, 0x0

    .line 14
    const-string v9, "input"

    .line 15
    .line 16
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    const/4 v11, 0x0

    .line 19
    iget-object v0, v0, Lw81/c;->e:Ljava/lang/Object;

    .line 20
    .line 21
    packed-switch v1, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    check-cast v0, Ly70/y1;

    .line 25
    .line 26
    move-object/from16 v1, p1

    .line 27
    .line 28
    check-cast v1, Lcq0/w;

    .line 29
    .line 30
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, v0, Ly70/y1;->i:Lij0/a;

    .line 34
    .line 35
    invoke-static {v1}, Lo01/g;->b(Lcq0/w;)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    new-array v2, v11, [Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Ljj0/f;

    .line 42
    .line 43
    invoke-virtual {v0, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    return-object v0

    .line 48
    :pswitch_0
    check-cast v0, Ly70/j0;

    .line 49
    .line 50
    move-object/from16 v1, p1

    .line 51
    .line 52
    check-cast v1, Lcq0/w;

    .line 53
    .line 54
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, v0, Ly70/j0;->i:Lij0/a;

    .line 58
    .line 59
    invoke-static {v1}, Lo01/g;->b(Lcq0/w;)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    new-array v2, v11, [Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Ljj0/f;

    .line 66
    .line 67
    invoke-virtual {v0, v1, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    return-object v0

    .line 72
    :pswitch_1
    check-cast v0, Lq31/h;

    .line 73
    .line 74
    move-object/from16 v1, p1

    .line 75
    .line 76
    check-cast v1, Ln7/b;

    .line 77
    .line 78
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    sget-object v2, Lq31/c;->a:Lq31/c;

    .line 82
    .line 83
    invoke-virtual {v0, v2}, Lq31/h;->d(Lq31/f;)V

    .line 84
    .line 85
    .line 86
    new-instance v2, Ly21/e;

    .line 87
    .line 88
    invoke-direct {v2, v1, v0, v6}, Ly21/e;-><init>(Ln7/b;Lq41/b;I)V

    .line 89
    .line 90
    .line 91
    return-object v2

    .line 92
    :pswitch_2
    check-cast v0, Lr31/i;

    .line 93
    .line 94
    move-object/from16 v1, p1

    .line 95
    .line 96
    check-cast v1, Ln7/b;

    .line 97
    .line 98
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    sget-object v2, Lr31/c;->a:Lr31/c;

    .line 102
    .line 103
    invoke-virtual {v0, v2}, Lr31/i;->d(Lr31/g;)V

    .line 104
    .line 105
    .line 106
    new-instance v2, Ly21/e;

    .line 107
    .line 108
    invoke-direct {v2, v1, v0, v4}, Ly21/e;-><init>(Ln7/b;Lq41/b;I)V

    .line 109
    .line 110
    .line 111
    return-object v2

    .line 112
    :pswitch_3
    check-cast v0, Lz21/g;

    .line 113
    .line 114
    move-object/from16 v1, p1

    .line 115
    .line 116
    check-cast v1, Lz9/w;

    .line 117
    .line 118
    const-string v5, "$this$navigation"

    .line 119
    .line 120
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    new-instance v5, Ly21/a;

    .line 124
    .line 125
    invoke-direct {v5, v0, v4}, Ly21/a;-><init>(Lz21/g;I)V

    .line 126
    .line 127
    .line 128
    new-instance v4, Lt2/b;

    .line 129
    .line 130
    const v7, 0x3b6e93f6

    .line 131
    .line 132
    .line 133
    invoke-direct {v4, v5, v6, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 134
    .line 135
    .line 136
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 137
    .line 138
    const-class v7, Ll31/q;

    .line 139
    .line 140
    invoke-virtual {v5, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 141
    .line 142
    .line 143
    move-result-object v7

    .line 144
    invoke-static {v1, v7, v4}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 145
    .line 146
    .line 147
    new-instance v4, Ly21/a;

    .line 148
    .line 149
    const/4 v7, 0x6

    .line 150
    invoke-direct {v4, v0, v7}, Ly21/a;-><init>(Lz21/g;I)V

    .line 151
    .line 152
    .line 153
    new-instance v7, Lt2/b;

    .line 154
    .line 155
    const v8, 0x3cfbed2d

    .line 156
    .line 157
    .line 158
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 159
    .line 160
    .line 161
    const-class v4, Ll31/m;

    .line 162
    .line 163
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 168
    .line 169
    .line 170
    new-instance v4, Ly21/a;

    .line 171
    .line 172
    const/4 v7, 0x7

    .line 173
    invoke-direct {v4, v0, v7}, Ly21/a;-><init>(Lz21/g;I)V

    .line 174
    .line 175
    .line 176
    new-instance v7, Lt2/b;

    .line 177
    .line 178
    const v8, 0x2adf6dae

    .line 179
    .line 180
    .line 181
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 182
    .line 183
    .line 184
    const-class v4, Ll31/x;

    .line 185
    .line 186
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 191
    .line 192
    .line 193
    new-instance v4, Lny/r;

    .line 194
    .line 195
    const/16 v7, 0xd

    .line 196
    .line 197
    invoke-direct {v4, v7}, Lny/r;-><init>(I)V

    .line 198
    .line 199
    .line 200
    new-instance v7, Lt2/b;

    .line 201
    .line 202
    const v8, 0x18c2ee2f

    .line 203
    .line 204
    .line 205
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 206
    .line 207
    .line 208
    const-class v4, Ll31/c;

    .line 209
    .line 210
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 215
    .line 216
    .line 217
    new-instance v4, Ly21/a;

    .line 218
    .line 219
    const/16 v7, 0x8

    .line 220
    .line 221
    invoke-direct {v4, v0, v7}, Ly21/a;-><init>(Lz21/g;I)V

    .line 222
    .line 223
    .line 224
    new-instance v7, Lt2/b;

    .line 225
    .line 226
    const v8, 0x6a66eb0

    .line 227
    .line 228
    .line 229
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 230
    .line 231
    .line 232
    const-class v4, Ll31/j;

    .line 233
    .line 234
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 239
    .line 240
    .line 241
    new-instance v4, Ly21/a;

    .line 242
    .line 243
    const/16 v7, 0x9

    .line 244
    .line 245
    invoke-direct {v4, v0, v7}, Ly21/a;-><init>(Lz21/g;I)V

    .line 246
    .line 247
    .line 248
    new-instance v7, Lt2/b;

    .line 249
    .line 250
    const v8, -0xb7610cf

    .line 251
    .line 252
    .line 253
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 254
    .line 255
    .line 256
    const-class v4, Ll31/w;

    .line 257
    .line 258
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 263
    .line 264
    .line 265
    new-instance v4, Ly21/a;

    .line 266
    .line 267
    invoke-direct {v4, v0, v11}, Ly21/a;-><init>(Lz21/g;I)V

    .line 268
    .line 269
    .line 270
    new-instance v7, Lt2/b;

    .line 271
    .line 272
    const v8, -0x1d92904e

    .line 273
    .line 274
    .line 275
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 276
    .line 277
    .line 278
    const-class v4, Ll31/t;

    .line 279
    .line 280
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 281
    .line 282
    .line 283
    move-result-object v4

    .line 284
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 285
    .line 286
    .line 287
    new-instance v4, Lny/r;

    .line 288
    .line 289
    const/16 v7, 0xb

    .line 290
    .line 291
    invoke-direct {v4, v7}, Lny/r;-><init>(I)V

    .line 292
    .line 293
    .line 294
    new-instance v7, Lt2/b;

    .line 295
    .line 296
    const v8, -0x2faf0fcd

    .line 297
    .line 298
    .line 299
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 300
    .line 301
    .line 302
    const-class v4, Ll31/u;

    .line 303
    .line 304
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 305
    .line 306
    .line 307
    move-result-object v4

    .line 308
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 309
    .line 310
    .line 311
    new-instance v4, Ly21/a;

    .line 312
    .line 313
    invoke-direct {v4, v0, v6}, Ly21/a;-><init>(Lz21/g;I)V

    .line 314
    .line 315
    .line 316
    new-instance v7, Lt2/b;

    .line 317
    .line 318
    const v8, -0x41cb8f4c

    .line 319
    .line 320
    .line 321
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 322
    .line 323
    .line 324
    const-class v4, Ll31/f;

    .line 325
    .line 326
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 327
    .line 328
    .line 329
    move-result-object v4

    .line 330
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 331
    .line 332
    .line 333
    new-instance v4, Ly21/a;

    .line 334
    .line 335
    const/4 v7, 0x2

    .line 336
    invoke-direct {v4, v0, v7}, Ly21/a;-><init>(Lz21/g;I)V

    .line 337
    .line 338
    .line 339
    new-instance v7, Lt2/b;

    .line 340
    .line 341
    const v8, -0x53e80ecb

    .line 342
    .line 343
    .line 344
    invoke-direct {v7, v4, v6, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 345
    .line 346
    .line 347
    const-class v4, Ll31/n;

    .line 348
    .line 349
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    invoke-static {v1, v4, v7}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 354
    .line 355
    .line 356
    new-instance v4, Ly21/a;

    .line 357
    .line 358
    invoke-direct {v4, v0, v3}, Ly21/a;-><init>(Lz21/g;I)V

    .line 359
    .line 360
    .line 361
    new-instance v3, Lt2/b;

    .line 362
    .line 363
    const v7, 0xb9dc383

    .line 364
    .line 365
    .line 366
    invoke-direct {v3, v4, v6, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 367
    .line 368
    .line 369
    const-class v4, Ll31/g;

    .line 370
    .line 371
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 372
    .line 373
    .line 374
    move-result-object v4

    .line 375
    invoke-static {v1, v4, v3}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 376
    .line 377
    .line 378
    new-instance v3, Ly21/a;

    .line 379
    .line 380
    invoke-direct {v3, v0, v2}, Ly21/a;-><init>(Lz21/g;I)V

    .line 381
    .line 382
    .line 383
    new-instance v0, Lt2/b;

    .line 384
    .line 385
    const v2, -0x67ebbfc

    .line 386
    .line 387
    .line 388
    invoke-direct {v0, v3, v6, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 389
    .line 390
    .line 391
    const-class v2, Ll31/y;

    .line 392
    .line 393
    invoke-virtual {v5, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 394
    .line 395
    .line 396
    move-result-object v2

    .line 397
    invoke-static {v1, v2, v0}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 398
    .line 399
    .line 400
    new-instance v0, Lny/r;

    .line 401
    .line 402
    const/16 v2, 0xc

    .line 403
    .line 404
    invoke-direct {v0, v2}, Lny/r;-><init>(I)V

    .line 405
    .line 406
    .line 407
    new-instance v2, Lt2/b;

    .line 408
    .line 409
    const v3, -0x189b3b7b

    .line 410
    .line 411
    .line 412
    invoke-direct {v2, v0, v6, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 413
    .line 414
    .line 415
    const-class v0, Ll31/v;

    .line 416
    .line 417
    invoke-virtual {v5, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 418
    .line 419
    .line 420
    move-result-object v0

    .line 421
    invoke-static {v1, v0, v2}, Ljp/r0;->a(Lz9/w;Lhy0/d;Lt2/b;)V

    .line 422
    .line 423
    .line 424
    return-object v10

    .line 425
    :pswitch_4
    check-cast v0, Landroid/graphics/drawable/Drawable;

    .line 426
    .line 427
    move-object/from16 v1, p1

    .line 428
    .line 429
    check-cast v1, Lg3/d;

    .line 430
    .line 431
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 432
    .line 433
    .line 434
    move-result-object v2

    .line 435
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 436
    .line 437
    .line 438
    move-result-object v2

    .line 439
    invoke-interface {v1}, Lg3/d;->e()J

    .line 440
    .line 441
    .line 442
    move-result-wide v3

    .line 443
    const/16 v5, 0x20

    .line 444
    .line 445
    shr-long/2addr v3, v5

    .line 446
    long-to-int v3, v3

    .line 447
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 448
    .line 449
    .line 450
    move-result v3

    .line 451
    float-to-int v3, v3

    .line 452
    invoke-interface {v1}, Lg3/d;->e()J

    .line 453
    .line 454
    .line 455
    move-result-wide v4

    .line 456
    const-wide v6, 0xffffffffL

    .line 457
    .line 458
    .line 459
    .line 460
    .line 461
    and-long/2addr v4, v6

    .line 462
    long-to-int v1, v4

    .line 463
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 464
    .line 465
    .line 466
    move-result v1

    .line 467
    float-to-int v1, v1

    .line 468
    invoke-virtual {v0, v11, v11, v3, v1}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 469
    .line 470
    .line 471
    invoke-static {v2}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 472
    .line 473
    .line 474
    move-result-object v1

    .line 475
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 476
    .line 477
    .line 478
    return-object v10

    .line 479
    :pswitch_5
    check-cast v0, Lac/x;

    .line 480
    .line 481
    move-object/from16 v1, p1

    .line 482
    .line 483
    check-cast v1, Llx0/b0;

    .line 484
    .line 485
    new-instance v1, Lxc/f;

    .line 486
    .line 487
    iget-boolean v2, v0, Lac/x;->u:Z

    .line 488
    .line 489
    invoke-direct {v1, v0, v2}, Lxc/f;-><init>(Lac/x;Z)V

    .line 490
    .line 491
    .line 492
    return-object v1

    .line 493
    :pswitch_6
    check-cast v0, Lx41/u0;

    .line 494
    .line 495
    move-object/from16 v1, p1

    .line 496
    .line 497
    check-cast v1, Lx41/k1;

    .line 498
    .line 499
    const-string v4, "qrCodeResult"

    .line 500
    .line 501
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 502
    .line 503
    .line 504
    instance-of v4, v1, Lx41/k1;

    .line 505
    .line 506
    if-eqz v4, :cond_0

    .line 507
    .line 508
    iget-object v1, v1, Lx41/k1;->a:Ltechnology/cariad/cat/genx/QRCode;

    .line 509
    .line 510
    new-instance v14, Lh70/i;

    .line 511
    .line 512
    invoke-direct {v14, v1, v3}, Lh70/i;-><init>(Ltechnology/cariad/cat/genx/QRCode;I)V

    .line 513
    .line 514
    .line 515
    new-instance v11, Lt51/j;

    .line 516
    .line 517
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 518
    .line 519
    .line 520
    move-result-object v16

    .line 521
    const-string v3, "getName(...)"

    .line 522
    .line 523
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 524
    .line 525
    .line 526
    move-result-object v17

    .line 527
    const-string v12, "Car2PhonePairing"

    .line 528
    .line 529
    sget-object v13, Lt51/f;->a:Lt51/f;

    .line 530
    .line 531
    const/4 v15, 0x0

    .line 532
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 536
    .line 537
    .line 538
    new-instance v15, Lh70/i;

    .line 539
    .line 540
    invoke-direct {v15, v1, v2}, Lh70/i;-><init>(Ltechnology/cariad/cat/genx/QRCode;I)V

    .line 541
    .line 542
    .line 543
    new-instance v12, Lt51/j;

    .line 544
    .line 545
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 546
    .line 547
    .line 548
    move-result-object v17

    .line 549
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 550
    .line 551
    .line 552
    move-result-object v18

    .line 553
    const-string v13, "Car2PhonePairing"

    .line 554
    .line 555
    sget-object v14, Lt51/g;->a:Lt51/g;

    .line 556
    .line 557
    const/16 v16, 0x0

    .line 558
    .line 559
    invoke-direct/range {v12 .. v18}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 560
    .line 561
    .line 562
    invoke-static {v12}, Lt51/a;->a(Lt51/j;)V

    .line 563
    .line 564
    .line 565
    iget-object v2, v0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 566
    .line 567
    iget-object v0, v0, Lx41/u0;->u:Lx41/m0;

    .line 568
    .line 569
    invoke-interface {v2, v1, v0}, Ltechnology/cariad/cat/genx/VehicleManager;->startKeyExchange(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V

    .line 570
    .line 571
    .line 572
    return-object v10

    .line 573
    :cond_0
    new-instance v0, La8/r0;

    .line 574
    .line 575
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 576
    .line 577
    .line 578
    throw v0

    .line 579
    :pswitch_7
    check-cast v0, Lp31/f;

    .line 580
    .line 581
    move-object/from16 v1, p1

    .line 582
    .line 583
    check-cast v1, Lp31/f;

    .line 584
    .line 585
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 586
    .line 587
    .line 588
    iget-object v1, v1, Lp31/f;->a:Li31/e;

    .line 589
    .line 590
    iget-object v1, v1, Li31/e;->g:Ljava/lang/String;

    .line 591
    .line 592
    iget-object v0, v0, Lp31/f;->a:Li31/e;

    .line 593
    .line 594
    iget-object v0, v0, Li31/e;->g:Ljava/lang/String;

    .line 595
    .line 596
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 597
    .line 598
    .line 599
    move-result v0

    .line 600
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 601
    .line 602
    .line 603
    move-result-object v0

    .line 604
    return-object v0

    .line 605
    :pswitch_8
    check-cast v0, Lwz0/s;

    .line 606
    .line 607
    move-object/from16 v1, p1

    .line 608
    .line 609
    check-cast v1, Lvz0/n;

    .line 610
    .line 611
    const-string v2, "node"

    .line 612
    .line 613
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    iget-object v2, v0, Lwz0/s;->a:Ljava/util/ArrayList;

    .line 617
    .line 618
    invoke-static {v2}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 619
    .line 620
    .line 621
    move-result-object v2

    .line 622
    check-cast v2, Ljava/lang/String;

    .line 623
    .line 624
    invoke-virtual {v0, v2, v1}, Lwz0/s;->M(Ljava/lang/String;Lvz0/n;)V

    .line 625
    .line 626
    .line 627
    return-object v10

    .line 628
    :pswitch_9
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;

    .line 629
    .line 630
    move-object/from16 v1, p1

    .line 631
    .line 632
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 633
    .line 634
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$WaitingForNewFunctionState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    return-object v0

    .line 639
    :pswitch_a
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;

    .line 640
    .line 641
    move-object/from16 v1, p1

    .line 642
    .line 643
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 644
    .line 645
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockRequestedWaitingForResponseByCar;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 646
    .line 647
    .line 648
    move-result-object v0

    .line 649
    return-object v0

    .line 650
    :pswitch_b
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgressThresholdReached;

    .line 651
    .line 652
    move-object/from16 v1, p1

    .line 653
    .line 654
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 655
    .line 656
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgressThresholdReached;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgressThresholdReached;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 657
    .line 658
    .line 659
    move-result-object v0

    .line 660
    return-object v0

    .line 661
    :pswitch_c
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgress;

    .line 662
    .line 663
    move-object/from16 v1, p1

    .line 664
    .line 665
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 666
    .line 667
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgress;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$UnlockInProgress;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 668
    .line 669
    .line 670
    move-result-object v0

    .line 671
    return-object v0

    .line 672
    :pswitch_d
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;

    .line 673
    .line 674
    move-object/from16 v1, p1

    .line 675
    .line 676
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 677
    .line 678
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByDefault;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 679
    .line 680
    .line 681
    move-result-object v0

    .line 682
    return-object v0

    .line 683
    :pswitch_e
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;

    .line 684
    .line 685
    move-object/from16 v1, p1

    .line 686
    .line 687
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 688
    .line 689
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState$LockedByCar;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 690
    .line 691
    .line 692
    move-result-object v0

    .line 693
    return-object v0

    .line 694
    :pswitch_f
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/v;

    .line 695
    .line 696
    move-object/from16 v1, p1

    .line 697
    .line 698
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 699
    .line 700
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 701
    .line 702
    .line 703
    iget-object v2, v0, Lv81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 704
    .line 705
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object v2

    .line 709
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 710
    .line 711
    if-eqz v2, :cond_1

    .line 712
    .line 713
    move-object v8, v2

    .line 714
    goto :goto_0

    .line 715
    :cond_1
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 716
    .line 717
    if-eqz v2, :cond_2

    .line 718
    .line 719
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->l:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 720
    .line 721
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 722
    .line 723
    invoke-static {v1}, Llp/j1;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 724
    .line 725
    .line 726
    move-result-object v1

    .line 727
    iget-object v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 728
    .line 729
    iget-object v3, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;

    .line 730
    .line 731
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;->getDetectedStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 732
    .line 733
    .line 734
    move-result-object v3

    .line 735
    iget-object v1, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 736
    .line 737
    invoke-static {v2, v3, v1}, Lpt0/n;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z

    .line 738
    .line 739
    .line 740
    move-result v1

    .line 741
    if-eqz v1, :cond_2

    .line 742
    .line 743
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 744
    .line 745
    .line 746
    move-result-object v0

    .line 747
    sget-object v1, Ls71/m;->f:Ls71/m;

    .line 748
    .line 749
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 750
    .line 751
    .line 752
    :cond_2
    :goto_0
    return-object v8

    .line 753
    :pswitch_10
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/t;

    .line 754
    .line 755
    move-object/from16 v1, p1

    .line 756
    .line 757
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 758
    .line 759
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 763
    .line 764
    if-eqz v2, :cond_5

    .line 765
    .line 766
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 767
    .line 768
    invoke-static {v1}, Lps/t1;->i(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;

    .line 769
    .line 770
    .line 771
    move-result-object v2

    .line 772
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioVehicleInfoMessagePPE;->getHasOpenWindows$remoteparkassistcoremeb_release()Z

    .line 773
    .line 774
    .line 775
    move-result v2

    .line 776
    if-nez v2, :cond_3

    .line 777
    .line 778
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 779
    .line 780
    .line 781
    move-result-object v0

    .line 782
    sget-object v2, Ls71/m;->g:Ls71/m;

    .line 783
    .line 784
    invoke-interface {v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 785
    .line 786
    .line 787
    :cond_3
    invoke-static {v1}, Lps/t1;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z

    .line 788
    .line 789
    .line 790
    move-result v0

    .line 791
    if-eqz v0, :cond_4

    .line 792
    .line 793
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Timeout;

    .line 794
    .line 795
    invoke-direct {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Timeout;-><init>()V

    .line 796
    .line 797
    .line 798
    goto :goto_1

    .line 799
    :cond_4
    invoke-static {v1}, Lps/t1;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 800
    .line 801
    .line 802
    move-result-object v0

    .line 803
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->NOT_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 804
    .line 805
    if-ne v0, v1, :cond_5

    .line 806
    .line 807
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$NotActive;

    .line 808
    .line 809
    invoke-direct {v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$NotActive;-><init>()V

    .line 810
    .line 811
    .line 812
    :cond_5
    :goto_1
    return-object v8

    .line 813
    :pswitch_11
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;

    .line 814
    .line 815
    move-object/from16 v1, p1

    .line 816
    .line 817
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 818
    .line 819
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 820
    .line 821
    .line 822
    move-result-object v0

    .line 823
    return-object v0

    .line 824
    :pswitch_12
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;

    .line 825
    .line 826
    move-object/from16 v1, p1

    .line 827
    .line 828
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 829
    .line 830
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 831
    .line 832
    .line 833
    move-result-object v0

    .line 834
    return-object v0

    .line 835
    :pswitch_13
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;

    .line 836
    .line 837
    move-object/from16 v1, p1

    .line 838
    .line 839
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 840
    .line 841
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$PPEParkingFinishedSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Timeout;

    .line 842
    .line 843
    .line 844
    move-result-object v0

    .line 845
    return-object v0

    .line 846
    :pswitch_14
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;

    .line 847
    .line 848
    move-object/from16 v1, p1

    .line 849
    .line 850
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 851
    .line 852
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 853
    .line 854
    .line 855
    move-result-object v0

    .line 856
    return-object v0

    .line 857
    :pswitch_15
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$ClosingWindows;

    .line 858
    .line 859
    move-object/from16 v1, p1

    .line 860
    .line 861
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 862
    .line 863
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$ClosingWindows;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$ClosingWindows;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 864
    .line 865
    .line 866
    move-result-object v0

    .line 867
    return-object v0

    .line 868
    :pswitch_16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/p;

    .line 869
    .line 870
    move-object/from16 v1, p1

    .line 871
    .line 872
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 873
    .line 874
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 878
    .line 879
    if-eqz v2, :cond_8

    .line 880
    .line 881
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 882
    .line 883
    invoke-static {v1}, Lps/t1;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;

    .line 884
    .line 885
    .line 886
    move-result-object v2

    .line 887
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PHighPrioMessagePPE;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 888
    .line 889
    .line 890
    move-result-object v2

    .line 891
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;

    .line 892
    .line 893
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    move-result-object v4

    .line 897
    instance-of v5, v4, Lu81/a;

    .line 898
    .line 899
    if-eqz v5, :cond_6

    .line 900
    .line 901
    check-cast v4, Lu81/a;

    .line 902
    .line 903
    goto :goto_2

    .line 904
    :cond_6
    move-object v4, v8

    .line 905
    :goto_2
    if-eqz v4, :cond_7

    .line 906
    .line 907
    iget-object v4, v4, Lu81/a;->g:Ll71/c;

    .line 908
    .line 909
    goto :goto_3

    .line 910
    :cond_7
    move-object v4, v8

    .line 911
    :goto_3
    invoke-static {v1}, Lps/t1;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z

    .line 912
    .line 913
    .line 914
    move-result v1

    .line 915
    invoke-direct {v3, v2, v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;Z)V

    .line 916
    .line 917
    .line 918
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 919
    .line 920
    .line 921
    move-result-object v0

    .line 922
    invoke-virtual {v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState$ParkingFailed;->equals(Ljava/lang/Object;)Z

    .line 923
    .line 924
    .line 925
    move-result v0

    .line 926
    if-nez v0, :cond_8

    .line 927
    .line 928
    move-object v8, v3

    .line 929
    :cond_8
    return-object v8

    .line 930
    :pswitch_17
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/h;

    .line 931
    .line 932
    move-object/from16 v1, p1

    .line 933
    .line 934
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 935
    .line 936
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 937
    .line 938
    .line 939
    iget-object v2, v0, Lv81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 940
    .line 941
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    move-result-object v2

    .line 945
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 946
    .line 947
    if-eqz v2, :cond_9

    .line 948
    .line 949
    move-object v8, v2

    .line 950
    goto :goto_4

    .line 951
    :cond_9
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 952
    .line 953
    if-eqz v2, :cond_b

    .line 954
    .line 955
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->l:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 956
    .line 957
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 958
    .line 959
    invoke-static {v1}, Llp/j1;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 960
    .line 961
    .line 962
    move-result-object v1

    .line 963
    iget-object v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 964
    .line 965
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 966
    .line 967
    .line 968
    move-result-object v3

    .line 969
    instance-of v3, v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 970
    .line 971
    if-nez v3, :cond_a

    .line 972
    .line 973
    invoke-static {v2}, Lpt0/n;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z

    .line 974
    .line 975
    .line 976
    move-result v3

    .line 977
    if-eqz v3, :cond_a

    .line 978
    .line 979
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 980
    .line 981
    invoke-direct {v8, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 982
    .line 983
    .line 984
    goto :goto_4

    .line 985
    :cond_a
    iget-object v3, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 986
    .line 987
    iget-object v1, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;

    .line 988
    .line 989
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleStatusPPE;->getDetectedStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 990
    .line 991
    .line 992
    move-result-object v1

    .line 993
    invoke-static {v3, v1, v2}, Lpt0/n;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z

    .line 994
    .line 995
    .line 996
    move-result v1

    .line 997
    if-eqz v1, :cond_b

    .line 998
    .line 999
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getStateCallback$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v0

    .line 1003
    sget-object v1, Ls71/m;->f:Ls71/m;

    .line 1004
    .line 1005
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;->onSideEffect(Ljava/lang/Object;)V

    .line 1006
    .line 1007
    .line 1008
    :cond_b
    :goto_4
    return-object v8

    .line 1009
    :pswitch_18
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;

    .line 1010
    .line 1011
    move-object/from16 v1, p1

    .line 1012
    .line 1013
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1014
    .line 1015
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v0

    .line 1019
    return-object v0

    .line 1020
    :pswitch_19
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingBackward;

    .line 1021
    .line 1022
    move-object/from16 v1, p1

    .line 1023
    .line 1024
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1025
    .line 1026
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingBackward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingBackward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$DriveCorrectionSubState;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v0

    .line 1030
    return-object v0

    .line 1031
    :pswitch_1a
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 1032
    .line 1033
    move-object/from16 v1, p1

    .line 1034
    .line 1035
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1036
    .line 1037
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v0

    .line 1041
    return-object v0

    .line 1042
    :pswitch_1b
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 1043
    .line 1044
    move-object/from16 v1, p1

    .line 1045
    .line 1046
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1047
    .line 1048
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v0

    .line 1052
    return-object v0

    .line 1053
    :pswitch_1c
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;

    .line 1054
    .line 1055
    move-object/from16 v1, p1

    .line 1056
    .line 1057
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1058
    .line 1059
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v0

    .line 1063
    return-object v0

    .line 1064
    nop

    .line 1065
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
