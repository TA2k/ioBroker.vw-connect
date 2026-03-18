.class public final synthetic Lmg/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lmg/i;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lmg/i;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Lgi/c;

    .line 11
    .line 12
    const-string v1, "$this$log"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "Received request to refresh UserSubscription"

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object/from16 v0, p1

    .line 21
    .line 22
    check-cast v0, Lgi/c;

    .line 23
    .line 24
    const-string v1, "$this$log"

    .line 25
    .line 26
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "onSubscriptionHash, detected different hash than cached, requesting refresh"

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    move-object/from16 v0, p1

    .line 33
    .line 34
    check-cast v0, Lgi/c;

    .line 35
    .line 36
    const-string v1, "$this$log"

    .line 37
    .line 38
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v0, "Init new instance of the SubscriptionRepositoryImpl"

    .line 42
    .line 43
    return-object v0

    .line 44
    :pswitch_2
    move-object/from16 v0, p1

    .line 45
    .line 46
    check-cast v0, Lhi/a;

    .line 47
    .line 48
    const-string v1, "$this$single"

    .line 49
    .line 50
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Lmj/a;

    .line 54
    .line 55
    const-class v2, Landroid/content/Context;

    .line 56
    .line 57
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 58
    .line 59
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v0, Lii/a;

    .line 64
    .line 65
    invoke-virtual {v0, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Landroid/content/Context;

    .line 70
    .line 71
    invoke-direct {v1, v0}, Lmj/a;-><init>(Landroid/content/Context;)V

    .line 72
    .line 73
    .line 74
    return-object v1

    .line 75
    :pswitch_3
    move-object/from16 v0, p1

    .line 76
    .line 77
    check-cast v0, Lhi/a;

    .line 78
    .line 79
    const-string v1, "$this$single"

    .line 80
    .line 81
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const-class v1, Llj/f;

    .line 85
    .line 86
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 87
    .line 88
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    check-cast v0, Lii/a;

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    check-cast v0, Lmj/k;

    .line 99
    .line 100
    return-object v0

    .line 101
    :pswitch_4
    move-object/from16 v0, p1

    .line 102
    .line 103
    check-cast v0, Lhi/a;

    .line 104
    .line 105
    const-string v1, "$this$single"

    .line 106
    .line 107
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    new-instance v1, Lmj/c;

    .line 111
    .line 112
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 113
    .line 114
    const-class v3, Lvy0/b0;

    .line 115
    .line 116
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    check-cast v0, Lii/a;

    .line 121
    .line 122
    invoke-virtual {v0, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    check-cast v3, Lvy0/b0;

    .line 127
    .line 128
    const-class v4, Lrc/b;

    .line 129
    .line 130
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-virtual {v0, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Lrc/b;

    .line 139
    .line 140
    iget-object v0, v0, Lrc/b;->b:Lyy0/q1;

    .line 141
    .line 142
    invoke-direct {v1, v3, v0}, Lmj/c;-><init>(Lvy0/b0;Lyy0/n1;)V

    .line 143
    .line 144
    .line 145
    return-object v1

    .line 146
    :pswitch_5
    move-object/from16 v0, p1

    .line 147
    .line 148
    check-cast v0, Lhi/a;

    .line 149
    .line 150
    const-string v1, "$this$single"

    .line 151
    .line 152
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-class v1, Llj/f;

    .line 156
    .line 157
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 158
    .line 159
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    check-cast v0, Lii/a;

    .line 164
    .line 165
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    check-cast v0, Lmj/k;

    .line 170
    .line 171
    return-object v0

    .line 172
    :pswitch_6
    move-object/from16 v0, p1

    .line 173
    .line 174
    check-cast v0, Lhi/a;

    .line 175
    .line 176
    const-string v1, "$this$single"

    .line 177
    .line 178
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 182
    .line 183
    const-class v2, Lretrofit2/Retrofit;

    .line 184
    .line 185
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    check-cast v0, Lii/a;

    .line 190
    .line 191
    invoke-virtual {v0, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    check-cast v2, Lretrofit2/Retrofit;

    .line 196
    .line 197
    const-class v3, Loj/a;

    .line 198
    .line 199
    invoke-virtual {v2, v3}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    move-object v5, v2

    .line 204
    check-cast v5, Loj/a;

    .line 205
    .line 206
    const-class v2, Lmj/a;

    .line 207
    .line 208
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 209
    .line 210
    .line 211
    move-result-object v2

    .line 212
    invoke-virtual {v0, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    check-cast v2, Lmj/a;

    .line 217
    .line 218
    new-instance v14, Lmj/k;

    .line 219
    .line 220
    const-class v3, Lvy0/b0;

    .line 221
    .line 222
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 223
    .line 224
    .line 225
    move-result-object v3

    .line 226
    invoke-virtual {v0, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    move-object v15, v3

    .line 231
    check-cast v15, Lvy0/b0;

    .line 232
    .line 233
    new-instance v3, Ll20/g;

    .line 234
    .line 235
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    const/4 v9, 0x0

    .line 239
    const/16 v10, 0x11

    .line 240
    .line 241
    const/4 v4, 0x1

    .line 242
    const-class v6, Loj/a;

    .line 243
    .line 244
    const-string v7, "getSubscriptions"

    .line 245
    .line 246
    const-string v8, "getSubscriptions(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 247
    .line 248
    invoke-direct/range {v3 .. v10}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 249
    .line 250
    .line 251
    move-object/from16 v16, v3

    .line 252
    .line 253
    new-instance v3, Laj/a;

    .line 254
    .line 255
    const/4 v10, 0x1

    .line 256
    const/4 v4, 0x3

    .line 257
    const-class v6, Loj/a;

    .line 258
    .line 259
    const-string v7, "enablePlugAndCharge"

    .line 260
    .line 261
    const-string v8, "enablePlugAndCharge(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 262
    .line 263
    invoke-direct/range {v3 .. v10}, Laj/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 264
    .line 265
    .line 266
    move-object/from16 v17, v3

    .line 267
    .line 268
    new-instance v3, Ljd/b;

    .line 269
    .line 270
    const/16 v10, 0x9

    .line 271
    .line 272
    const/4 v4, 0x2

    .line 273
    const-class v6, Loj/a;

    .line 274
    .line 275
    const-string v7, "disablePlugAndCharge"

    .line 276
    .line 277
    const-string v8, "disablePlugAndCharge(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 278
    .line 279
    invoke-direct/range {v3 .. v10}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 280
    .line 281
    .line 282
    new-instance v4, Ll31/b;

    .line 283
    .line 284
    const/16 v5, 0x18

    .line 285
    .line 286
    invoke-direct {v4, v5}, Ll31/b;-><init>(I)V

    .line 287
    .line 288
    .line 289
    new-instance v6, Ll20/c;

    .line 290
    .line 291
    const/4 v12, 0x0

    .line 292
    const/16 v13, 0x1d

    .line 293
    .line 294
    const/4 v7, 0x0

    .line 295
    const-class v9, Lmj/a;

    .line 296
    .line 297
    const-string v10, "getData"

    .line 298
    .line 299
    const-string v11, "getData$headless_subscription_release()Lcariad/charging/multicharge/sdk/headless/subscription/internal/models/HeadlessSubscriptionGetResponse;"

    .line 300
    .line 301
    move-object v8, v2

    .line 302
    invoke-direct/range {v6 .. v13}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 303
    .line 304
    .line 305
    move-object v2, v6

    .line 306
    new-instance v6, Ljd/b;

    .line 307
    .line 308
    const/16 v13, 0xa

    .line 309
    .line 310
    const/4 v7, 0x2

    .line 311
    const-class v9, Lmj/a;

    .line 312
    .line 313
    const-string v10, "setData"

    .line 314
    .line 315
    const-string v11, "setData$headless_subscription_release(Lcariad/charging/multicharge/sdk/headless/subscription/internal/models/HeadlessSubscriptionGetResponse;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 316
    .line 317
    invoke-direct/range {v6 .. v13}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 318
    .line 319
    .line 320
    move-object v5, v6

    .line 321
    new-instance v6, Ll20/g;

    .line 322
    .line 323
    const/16 v13, 0x12

    .line 324
    .line 325
    const/4 v7, 0x1

    .line 326
    const-class v9, Lmj/a;

    .line 327
    .line 328
    const-string v10, "clear"

    .line 329
    .line 330
    const-string v11, "clear(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 331
    .line 332
    invoke-direct/range {v6 .. v13}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 333
    .line 334
    .line 335
    move-object v7, v14

    .line 336
    move-object v14, v6

    .line 337
    move-object v6, v7

    .line 338
    move-object v12, v2

    .line 339
    move-object v10, v3

    .line 340
    move-object v11, v4

    .line 341
    move-object v13, v5

    .line 342
    move-object v7, v15

    .line 343
    move-object/from16 v8, v16

    .line 344
    .line 345
    move-object/from16 v9, v17

    .line 346
    .line 347
    invoke-direct/range {v6 .. v14}, Lmj/k;-><init>(Lvy0/b0;Ll20/g;Laj/a;Ljd/b;Ll31/b;Ll20/c;Ljd/b;Ll20/g;)V

    .line 348
    .line 349
    .line 350
    const-class v2, Lmj/c;

    .line 351
    .line 352
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 353
    .line 354
    .line 355
    move-result-object v1

    .line 356
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    check-cast v0, Lmj/c;

    .line 361
    .line 362
    new-instance v11, Ll20/c;

    .line 363
    .line 364
    const/4 v12, 0x0

    .line 365
    const/16 v13, 0x1c

    .line 366
    .line 367
    const/4 v7, 0x0

    .line 368
    const-class v9, Lmj/k;

    .line 369
    .line 370
    const-string v10, "refresh"

    .line 371
    .line 372
    move-object v8, v6

    .line 373
    move-object v6, v11

    .line 374
    const-string v11, "refresh()V"

    .line 375
    .line 376
    invoke-direct/range {v6 .. v13}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 377
    .line 378
    .line 379
    move-object v11, v6

    .line 380
    move-object v6, v8

    .line 381
    new-instance v10, Lkotlin/jvm/internal/f0;

    .line 382
    .line 383
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 384
    .line 385
    .line 386
    iget-object v1, v0, Lmj/c;->a:Lvy0/b0;

    .line 387
    .line 388
    new-instance v7, Lk31/l;

    .line 389
    .line 390
    const/16 v8, 0x14

    .line 391
    .line 392
    const/4 v12, 0x0

    .line 393
    move-object v9, v0

    .line 394
    invoke-direct/range {v7 .. v12}, Lk31/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 395
    .line 396
    .line 397
    const/4 v0, 0x3

    .line 398
    invoke-static {v1, v12, v12, v7, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 399
    .line 400
    .line 401
    return-object v6

    .line 402
    :pswitch_7
    move-object/from16 v0, p1

    .line 403
    .line 404
    check-cast v0, Lhi/c;

    .line 405
    .line 406
    const-string v1, "$this$module"

    .line 407
    .line 408
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    new-instance v1, Lmg/i;

    .line 412
    .line 413
    const/16 v2, 0x16

    .line 414
    .line 415
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 416
    .line 417
    .line 418
    new-instance v2, Lii/b;

    .line 419
    .line 420
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 421
    .line 422
    const-class v4, Llj/f;

    .line 423
    .line 424
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 425
    .line 426
    .line 427
    move-result-object v4

    .line 428
    const/4 v5, 0x0

    .line 429
    invoke-direct {v2, v5, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 430
    .line 431
    .line 432
    iget-object v0, v0, Lhi/c;->a:Ljava/util/ArrayList;

    .line 433
    .line 434
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 435
    .line 436
    .line 437
    new-instance v1, Lmg/i;

    .line 438
    .line 439
    const/16 v2, 0x17

    .line 440
    .line 441
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 442
    .line 443
    .line 444
    new-instance v2, Lii/b;

    .line 445
    .line 446
    const-class v4, Lyi/a;

    .line 447
    .line 448
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 449
    .line 450
    .line 451
    move-result-object v4

    .line 452
    invoke-direct {v2, v5, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    new-instance v1, Lmg/i;

    .line 459
    .line 460
    const/16 v2, 0x18

    .line 461
    .line 462
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 463
    .line 464
    .line 465
    new-instance v2, Lii/b;

    .line 466
    .line 467
    const-class v4, Lmj/c;

    .line 468
    .line 469
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 470
    .line 471
    .line 472
    move-result-object v4

    .line 473
    invoke-direct {v2, v5, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 477
    .line 478
    .line 479
    new-instance v1, Lmg/i;

    .line 480
    .line 481
    const/16 v2, 0x19

    .line 482
    .line 483
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 484
    .line 485
    .line 486
    new-instance v2, Lii/b;

    .line 487
    .line 488
    const-class v4, Lmj/d;

    .line 489
    .line 490
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 491
    .line 492
    .line 493
    move-result-object v4

    .line 494
    invoke-direct {v2, v5, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 495
    .line 496
    .line 497
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 498
    .line 499
    .line 500
    new-instance v1, Lmg/i;

    .line 501
    .line 502
    const/16 v2, 0x1a

    .line 503
    .line 504
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 505
    .line 506
    .line 507
    new-instance v2, Lii/b;

    .line 508
    .line 509
    const-class v4, Lmj/a;

    .line 510
    .line 511
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 512
    .line 513
    .line 514
    move-result-object v3

    .line 515
    invoke-direct {v2, v5, v1, v3}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 516
    .line 517
    .line 518
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 519
    .line 520
    .line 521
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 522
    .line 523
    return-object v0

    .line 524
    :pswitch_8
    move-object/from16 v0, p1

    .line 525
    .line 526
    check-cast v0, Lvz0/i;

    .line 527
    .line 528
    const-string v1, "$this$Json"

    .line 529
    .line 530
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    const/4 v1, 0x1

    .line 534
    iput-boolean v1, v0, Lvz0/i;->c:Z

    .line 535
    .line 536
    const/4 v1, 0x0

    .line 537
    iput-boolean v1, v0, Lvz0/i;->b:Z

    .line 538
    .line 539
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 540
    .line 541
    return-object v0

    .line 542
    :pswitch_9
    move-object/from16 v0, p1

    .line 543
    .line 544
    check-cast v0, Lgi/c;

    .line 545
    .line 546
    const-string v1, "$this$log"

    .line 547
    .line 548
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 549
    .line 550
    .line 551
    const-string v0, "Ignoring subscription data without validity"

    .line 552
    .line 553
    return-object v0

    .line 554
    :pswitch_a
    move-object/from16 v0, p1

    .line 555
    .line 556
    check-cast v0, Lhi/a;

    .line 557
    .line 558
    const-string v1, "$this$sdkViewModel"

    .line 559
    .line 560
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 561
    .line 562
    .line 563
    new-instance v0, Lmh/t;

    .line 564
    .line 565
    invoke-direct {v0}, Lmh/t;-><init>()V

    .line 566
    .line 567
    .line 568
    iget-object v1, v0, Lmh/t;->d:Lyy0/c2;

    .line 569
    .line 570
    sget-object v2, Lmh/i;->b:Lmh/i;

    .line 571
    .line 572
    invoke-static {v1, v2}, Lmh/t;->a(Lyy0/j1;Lmh/j;)V

    .line 573
    .line 574
    .line 575
    return-object v0

    .line 576
    :pswitch_b
    move-object/from16 v0, p1

    .line 577
    .line 578
    check-cast v0, Lz9/l0;

    .line 579
    .line 580
    const-string v1, "$this$popUpTo"

    .line 581
    .line 582
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 583
    .line 584
    .line 585
    const/4 v1, 0x1

    .line 586
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 587
    .line 588
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 589
    .line 590
    return-object v0

    .line 591
    :pswitch_c
    move-object/from16 v0, p1

    .line 592
    .line 593
    check-cast v0, Lz9/l0;

    .line 594
    .line 595
    const-string v1, "$this$popUpTo"

    .line 596
    .line 597
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 598
    .line 599
    .line 600
    const/4 v1, 0x1

    .line 601
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 602
    .line 603
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 604
    .line 605
    return-object v0

    .line 606
    :pswitch_d
    move-object/from16 v0, p1

    .line 607
    .line 608
    check-cast v0, Lz9/c0;

    .line 609
    .line 610
    const-string v1, "$this$navigate"

    .line 611
    .line 612
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 613
    .line 614
    .line 615
    new-instance v1, Lmg/i;

    .line 616
    .line 617
    const/16 v2, 0x10

    .line 618
    .line 619
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 620
    .line 621
    .line 622
    const-string v2, "/tariff_upgrade_follow_up_confirmation"

    .line 623
    .line 624
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 625
    .line 626
    .line 627
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 628
    .line 629
    return-object v0

    .line 630
    :pswitch_e
    move-object/from16 v0, p1

    .line 631
    .line 632
    check-cast v0, Lz9/c0;

    .line 633
    .line 634
    const-string v1, "$this$navigate"

    .line 635
    .line 636
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    new-instance v1, Lmg/i;

    .line 640
    .line 641
    const/16 v2, 0x11

    .line 642
    .line 643
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 644
    .line 645
    .line 646
    const-string v2, "/tariff_upgrade_follow_up_selection"

    .line 647
    .line 648
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 649
    .line 650
    .line 651
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 652
    .line 653
    return-object v0

    .line 654
    :pswitch_f
    move-object/from16 v0, p1

    .line 655
    .line 656
    check-cast v0, Lz9/y;

    .line 657
    .line 658
    const-string v1, "$this$navigator"

    .line 659
    .line 660
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    const/4 v1, 0x0

    .line 664
    const/4 v2, 0x6

    .line 665
    const-string v3, "/payment/edit"

    .line 666
    .line 667
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 668
    .line 669
    .line 670
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 671
    .line 672
    return-object v0

    .line 673
    :pswitch_10
    move-object/from16 v0, p1

    .line 674
    .line 675
    check-cast v0, Lz9/y;

    .line 676
    .line 677
    const-string v1, "$this$navigator"

    .line 678
    .line 679
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 680
    .line 681
    .line 682
    const/4 v1, 0x0

    .line 683
    const/4 v2, 0x6

    .line 684
    const-string v3, "/tariff_upgrade_follow_up_confirmation"

    .line 685
    .line 686
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 687
    .line 688
    .line 689
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 690
    .line 691
    return-object v0

    .line 692
    :pswitch_11
    move-object/from16 v0, p1

    .line 693
    .line 694
    check-cast v0, Lz9/y;

    .line 695
    .line 696
    const-string v1, "$this$navigator"

    .line 697
    .line 698
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 699
    .line 700
    .line 701
    const/4 v1, 0x0

    .line 702
    const/4 v2, 0x6

    .line 703
    const-string v3, "/tariff_upgrade_or_follow_flow"

    .line 704
    .line 705
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 706
    .line 707
    .line 708
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 709
    .line 710
    return-object v0

    .line 711
    :pswitch_12
    move-object/from16 v0, p1

    .line 712
    .line 713
    check-cast v0, Lz9/y;

    .line 714
    .line 715
    const-string v1, "$this$navigator"

    .line 716
    .line 717
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 718
    .line 719
    .line 720
    const/4 v1, 0x0

    .line 721
    const/4 v2, 0x6

    .line 722
    const-string v3, "/card_delivery_address/edit"

    .line 723
    .line 724
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 725
    .line 726
    .line 727
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 728
    .line 729
    return-object v0

    .line 730
    :pswitch_13
    move-object/from16 v0, p1

    .line 731
    .line 732
    check-cast v0, Lz9/y;

    .line 733
    .line 734
    const-string v1, "$this$navigator"

    .line 735
    .line 736
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 737
    .line 738
    .line 739
    const/4 v1, 0x0

    .line 740
    const/4 v2, 0x6

    .line 741
    const-string v3, "/billing_address/edit"

    .line 742
    .line 743
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 744
    .line 745
    .line 746
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 747
    .line 748
    return-object v0

    .line 749
    :pswitch_14
    move-object/from16 v0, p1

    .line 750
    .line 751
    check-cast v0, Lz9/l0;

    .line 752
    .line 753
    const-string v1, "$this$popUpTo"

    .line 754
    .line 755
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 756
    .line 757
    .line 758
    const/4 v1, 0x1

    .line 759
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 760
    .line 761
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 762
    .line 763
    return-object v0

    .line 764
    :pswitch_15
    move-object/from16 v0, p1

    .line 765
    .line 766
    check-cast v0, Lz9/l0;

    .line 767
    .line 768
    const-string v1, "$this$popUpTo"

    .line 769
    .line 770
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 771
    .line 772
    .line 773
    const/4 v1, 0x1

    .line 774
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 775
    .line 776
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 777
    .line 778
    return-object v0

    .line 779
    :pswitch_16
    move-object/from16 v0, p1

    .line 780
    .line 781
    check-cast v0, Lz9/l0;

    .line 782
    .line 783
    const-string v1, "$this$popUpTo"

    .line 784
    .line 785
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 786
    .line 787
    .line 788
    const/4 v1, 0x1

    .line 789
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 790
    .line 791
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 792
    .line 793
    return-object v0

    .line 794
    :pswitch_17
    move-object/from16 v0, p1

    .line 795
    .line 796
    check-cast v0, Lz9/l0;

    .line 797
    .line 798
    const-string v1, "$this$popUpTo"

    .line 799
    .line 800
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 801
    .line 802
    .line 803
    const/4 v1, 0x1

    .line 804
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 805
    .line 806
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 807
    .line 808
    return-object v0

    .line 809
    :pswitch_18
    move-object/from16 v0, p1

    .line 810
    .line 811
    check-cast v0, Lz9/l0;

    .line 812
    .line 813
    const-string v1, "$this$popUpTo"

    .line 814
    .line 815
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 816
    .line 817
    .line 818
    const/4 v1, 0x1

    .line 819
    iput-boolean v1, v0, Lz9/l0;->a:Z

    .line 820
    .line 821
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 822
    .line 823
    return-object v0

    .line 824
    :pswitch_19
    move-object/from16 v0, p1

    .line 825
    .line 826
    check-cast v0, Lz9/c0;

    .line 827
    .line 828
    const-string v1, "$this$navigate"

    .line 829
    .line 830
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 831
    .line 832
    .line 833
    new-instance v1, Lmg/i;

    .line 834
    .line 835
    const/4 v2, 0x4

    .line 836
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 837
    .line 838
    .line 839
    const-string v2, "/tariff_confirmation"

    .line 840
    .line 841
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 842
    .line 843
    .line 844
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 845
    .line 846
    return-object v0

    .line 847
    :pswitch_1a
    move-object/from16 v0, p1

    .line 848
    .line 849
    check-cast v0, Lz9/c0;

    .line 850
    .line 851
    const-string v1, "$this$navigate"

    .line 852
    .line 853
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 854
    .line 855
    .line 856
    new-instance v1, Lmg/i;

    .line 857
    .line 858
    const/16 v2, 0x8

    .line 859
    .line 860
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 861
    .line 862
    .line 863
    const-string v2, "/tariff_confirmation"

    .line 864
    .line 865
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 866
    .line 867
    .line 868
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 869
    .line 870
    return-object v0

    .line 871
    :pswitch_1b
    move-object/from16 v0, p1

    .line 872
    .line 873
    check-cast v0, Lz9/c0;

    .line 874
    .line 875
    const-string v1, "$this$navigate"

    .line 876
    .line 877
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 878
    .line 879
    .line 880
    new-instance v1, Lmg/i;

    .line 881
    .line 882
    const/4 v2, 0x6

    .line 883
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 884
    .line 885
    .line 886
    const-string v2, "/payment"

    .line 887
    .line 888
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 889
    .line 890
    .line 891
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 892
    .line 893
    return-object v0

    .line 894
    :pswitch_1c
    move-object/from16 v0, p1

    .line 895
    .line 896
    check-cast v0, Lz9/y;

    .line 897
    .line 898
    const-string v1, "$this$navigator"

    .line 899
    .line 900
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 901
    .line 902
    .line 903
    const/4 v1, 0x0

    .line 904
    const/4 v2, 0x6

    .line 905
    const-string v3, "/payment/edit"

    .line 906
    .line 907
    invoke-static {v0, v3, v1, v2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 908
    .line 909
    .line 910
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 911
    .line 912
    return-object v0

    .line 913
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
