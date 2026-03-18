.class public final Lan0/a;
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
    iput p1, p0, Lan0/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lan0/a;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Lk21/a;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Lg21/a;

    .line 15
    .line 16
    const-string v2, "$this$factory"

    .line 17
    .line 18
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v2, "it"

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-class v1, Lkf0/k;

    .line 27
    .line 28
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 29
    .line 30
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    const/4 v2, 0x0

    .line 35
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lkf0/k;

    .line 40
    .line 41
    new-instance v1, Lc30/h;

    .line 42
    .line 43
    invoke-direct {v1, v0}, Lc30/h;-><init>(Lkf0/k;)V

    .line 44
    .line 45
    .line 46
    return-object v1

    .line 47
    :pswitch_0
    move-object/from16 v0, p1

    .line 48
    .line 49
    check-cast v0, Lk21/a;

    .line 50
    .line 51
    move-object/from16 v1, p2

    .line 52
    .line 53
    check-cast v1, Lg21/a;

    .line 54
    .line 55
    const-string v2, "$this$factory"

    .line 56
    .line 57
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    const-string v2, "it"

    .line 61
    .line 62
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 66
    .line 67
    const-class v2, Lkf0/o;

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    const/4 v3, 0x0

    .line 74
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    const-class v4, Lc30/p;

    .line 79
    .line 80
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    const-class v5, Lc30/i;

    .line 89
    .line 90
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    check-cast v0, Lc30/i;

    .line 99
    .line 100
    check-cast v4, Lc30/p;

    .line 101
    .line 102
    check-cast v2, Lkf0/o;

    .line 103
    .line 104
    new-instance v1, Lc30/a;

    .line 105
    .line 106
    invoke-direct {v1, v2, v4, v0}, Lc30/a;-><init>(Lkf0/o;Lc30/p;Lc30/i;)V

    .line 107
    .line 108
    .line 109
    return-object v1

    .line 110
    :pswitch_1
    move-object/from16 v0, p1

    .line 111
    .line 112
    check-cast v0, Lk21/a;

    .line 113
    .line 114
    move-object/from16 v1, p2

    .line 115
    .line 116
    check-cast v1, Lg21/a;

    .line 117
    .line 118
    const-string v2, "$this$factory"

    .line 119
    .line 120
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    const-string v2, "it"

    .line 124
    .line 125
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 129
    .line 130
    const-class v2, Lc30/f;

    .line 131
    .line 132
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    const/4 v3, 0x0

    .line 137
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    const-class v4, Lc30/i;

    .line 142
    .line 143
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    check-cast v0, Lc30/i;

    .line 152
    .line 153
    check-cast v2, Lc30/f;

    .line 154
    .line 155
    new-instance v1, Lc30/m;

    .line 156
    .line 157
    invoke-direct {v1, v2, v0}, Lc30/m;-><init>(Lc30/f;Lc30/i;)V

    .line 158
    .line 159
    .line 160
    return-object v1

    .line 161
    :pswitch_2
    move-object/from16 v0, p1

    .line 162
    .line 163
    check-cast v0, Lk21/a;

    .line 164
    .line 165
    move-object/from16 v1, p2

    .line 166
    .line 167
    check-cast v1, Lg21/a;

    .line 168
    .line 169
    const-string v2, "$this$viewModel"

    .line 170
    .line 171
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    const-string v2, "it"

    .line 175
    .line 176
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 180
    .line 181
    const-class v2, Ltr0/b;

    .line 182
    .line 183
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    const/4 v3, 0x0

    .line 188
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    const-class v4, Lbd0/c;

    .line 193
    .line 194
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    const-class v5, Lrq0/d;

    .line 203
    .line 204
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 205
    .line 206
    .line 207
    move-result-object v5

    .line 208
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v5

    .line 212
    const-class v6, Lc20/d;

    .line 213
    .line 214
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    check-cast v0, Lc20/d;

    .line 223
    .line 224
    check-cast v5, Lrq0/d;

    .line 225
    .line 226
    check-cast v4, Lbd0/c;

    .line 227
    .line 228
    check-cast v2, Ltr0/b;

    .line 229
    .line 230
    new-instance v1, Le20/d;

    .line 231
    .line 232
    invoke-direct {v1, v2, v4, v5, v0}, Le20/d;-><init>(Ltr0/b;Lbd0/c;Lrq0/d;Lc20/d;)V

    .line 233
    .line 234
    .line 235
    return-object v1

    .line 236
    :pswitch_3
    move-object/from16 v0, p1

    .line 237
    .line 238
    check-cast v0, Lk21/a;

    .line 239
    .line 240
    move-object/from16 v1, p2

    .line 241
    .line 242
    check-cast v1, Lg21/a;

    .line 243
    .line 244
    const-string v2, "$this$viewModel"

    .line 245
    .line 246
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    const-string v2, "it"

    .line 250
    .line 251
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 255
    .line 256
    const-class v2, Ltr0/b;

    .line 257
    .line 258
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 259
    .line 260
    .line 261
    move-result-object v2

    .line 262
    const/4 v3, 0x0

    .line 263
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    const-class v4, Lij0/a;

    .line 268
    .line 269
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 270
    .line 271
    .line 272
    move-result-object v4

    .line 273
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    const-class v5, Lc20/b;

    .line 278
    .line 279
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 280
    .line 281
    .line 282
    move-result-object v5

    .line 283
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v5

    .line 287
    const-class v6, Lrq0/d;

    .line 288
    .line 289
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 290
    .line 291
    .line 292
    move-result-object v6

    .line 293
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v6

    .line 297
    const-class v7, Lc20/e;

    .line 298
    .line 299
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 300
    .line 301
    .line 302
    move-result-object v7

    .line 303
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v7

    .line 307
    const-class v8, Lbd0/c;

    .line 308
    .line 309
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 310
    .line 311
    .line 312
    move-result-object v8

    .line 313
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v8

    .line 317
    const-class v9, Lc20/d;

    .line 318
    .line 319
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 320
    .line 321
    .line 322
    move-result-object v1

    .line 323
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    move-object/from16 v16, v0

    .line 328
    .line 329
    check-cast v16, Lc20/d;

    .line 330
    .line 331
    move-object v15, v8

    .line 332
    check-cast v15, Lbd0/c;

    .line 333
    .line 334
    move-object v14, v7

    .line 335
    check-cast v14, Lc20/e;

    .line 336
    .line 337
    move-object v13, v6

    .line 338
    check-cast v13, Lrq0/d;

    .line 339
    .line 340
    move-object v12, v5

    .line 341
    check-cast v12, Lc20/b;

    .line 342
    .line 343
    move-object v11, v4

    .line 344
    check-cast v11, Lij0/a;

    .line 345
    .line 346
    move-object v10, v2

    .line 347
    check-cast v10, Ltr0/b;

    .line 348
    .line 349
    new-instance v9, Le20/g;

    .line 350
    .line 351
    invoke-direct/range {v9 .. v16}, Le20/g;-><init>(Ltr0/b;Lij0/a;Lc20/b;Lrq0/d;Lc20/e;Lbd0/c;Lc20/d;)V

    .line 352
    .line 353
    .line 354
    return-object v9

    .line 355
    :pswitch_4
    move-object/from16 v0, p1

    .line 356
    .line 357
    check-cast v0, Lk21/a;

    .line 358
    .line 359
    move-object/from16 v1, p2

    .line 360
    .line 361
    check-cast v1, Lg21/a;

    .line 362
    .line 363
    const-string v2, "$this$viewModel"

    .line 364
    .line 365
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    const-string v2, "it"

    .line 369
    .line 370
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    const-class v1, Lc20/f;

    .line 374
    .line 375
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 376
    .line 377
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 378
    .line 379
    .line 380
    move-result-object v1

    .line 381
    const/4 v2, 0x0

    .line 382
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    check-cast v0, Lc20/f;

    .line 387
    .line 388
    new-instance v1, Le20/b;

    .line 389
    .line 390
    invoke-direct {v1, v0}, Le20/b;-><init>(Lc20/f;)V

    .line 391
    .line 392
    .line 393
    return-object v1

    .line 394
    :pswitch_5
    move-object/from16 v0, p1

    .line 395
    .line 396
    check-cast v0, Lk21/a;

    .line 397
    .line 398
    move-object/from16 v1, p2

    .line 399
    .line 400
    check-cast v1, Lg21/a;

    .line 401
    .line 402
    const-string v2, "$this$single"

    .line 403
    .line 404
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 405
    .line 406
    .line 407
    const-string v2, "it"

    .line 408
    .line 409
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 410
    .line 411
    .line 412
    const-class v1, Lwe0/a;

    .line 413
    .line 414
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 415
    .line 416
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    const/4 v2, 0x0

    .line 421
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v0

    .line 425
    check-cast v0, Lwe0/a;

    .line 426
    .line 427
    new-instance v1, La20/a;

    .line 428
    .line 429
    invoke-direct {v1, v0}, La20/a;-><init>(Lwe0/a;)V

    .line 430
    .line 431
    .line 432
    return-object v1

    .line 433
    :pswitch_6
    move-object/from16 v0, p1

    .line 434
    .line 435
    check-cast v0, Lk21/a;

    .line 436
    .line 437
    move-object/from16 v1, p2

    .line 438
    .line 439
    check-cast v1, Lg21/a;

    .line 440
    .line 441
    const-string v2, "$this$factory"

    .line 442
    .line 443
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    const-string v2, "it"

    .line 447
    .line 448
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 452
    .line 453
    const-class v2, Lc20/c;

    .line 454
    .line 455
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    const/4 v3, 0x0

    .line 460
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    move-result-object v2

    .line 464
    const-class v4, La20/b;

    .line 465
    .line 466
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 467
    .line 468
    .line 469
    move-result-object v4

    .line 470
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v4

    .line 474
    const-class v5, Lrs0/b;

    .line 475
    .line 476
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    check-cast v0, Lrs0/b;

    .line 485
    .line 486
    check-cast v4, La20/b;

    .line 487
    .line 488
    check-cast v2, Lc20/c;

    .line 489
    .line 490
    new-instance v1, Lc20/b;

    .line 491
    .line 492
    invoke-direct {v1, v2, v4, v0}, Lc20/b;-><init>(Lc20/c;La20/b;Lrs0/b;)V

    .line 493
    .line 494
    .line 495
    return-object v1

    .line 496
    :pswitch_7
    move-object/from16 v0, p1

    .line 497
    .line 498
    check-cast v0, Lk21/a;

    .line 499
    .line 500
    move-object/from16 v1, p2

    .line 501
    .line 502
    check-cast v1, Lg21/a;

    .line 503
    .line 504
    const-string v2, "$this$factory"

    .line 505
    .line 506
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    const-string v2, "it"

    .line 510
    .line 511
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 515
    .line 516
    const-class v2, Lc20/c;

    .line 517
    .line 518
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 519
    .line 520
    .line 521
    move-result-object v2

    .line 522
    const/4 v3, 0x0

    .line 523
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    move-result-object v2

    .line 527
    const-class v4, Lc20/b;

    .line 528
    .line 529
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v0

    .line 537
    check-cast v0, Lc20/b;

    .line 538
    .line 539
    check-cast v2, Lc20/c;

    .line 540
    .line 541
    new-instance v1, Lc20/d;

    .line 542
    .line 543
    invoke-direct {v1, v2, v0}, Lc20/d;-><init>(Lc20/c;Lc20/b;)V

    .line 544
    .line 545
    .line 546
    return-object v1

    .line 547
    :pswitch_8
    move-object/from16 v0, p1

    .line 548
    .line 549
    check-cast v0, Lk21/a;

    .line 550
    .line 551
    move-object/from16 v1, p2

    .line 552
    .line 553
    check-cast v1, Lg21/a;

    .line 554
    .line 555
    const-string v2, "$this$factory"

    .line 556
    .line 557
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 558
    .line 559
    .line 560
    const-string v2, "it"

    .line 561
    .line 562
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    const-class v1, Lc20/a;

    .line 566
    .line 567
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 568
    .line 569
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 570
    .line 571
    .line 572
    move-result-object v1

    .line 573
    const/4 v2, 0x0

    .line 574
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 575
    .line 576
    .line 577
    move-result-object v0

    .line 578
    check-cast v0, Lc20/a;

    .line 579
    .line 580
    new-instance v1, Lc20/e;

    .line 581
    .line 582
    invoke-direct {v1, v0}, Lc20/e;-><init>(Lc20/a;)V

    .line 583
    .line 584
    .line 585
    return-object v1

    .line 586
    :pswitch_9
    move-object/from16 v0, p1

    .line 587
    .line 588
    check-cast v0, Lk21/a;

    .line 589
    .line 590
    move-object/from16 v1, p2

    .line 591
    .line 592
    check-cast v1, Lg21/a;

    .line 593
    .line 594
    const-string v2, "$this$factory"

    .line 595
    .line 596
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    const-string v2, "it"

    .line 600
    .line 601
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 602
    .line 603
    .line 604
    const-class v1, Lc20/a;

    .line 605
    .line 606
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 607
    .line 608
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 609
    .line 610
    .line 611
    move-result-object v1

    .line 612
    const/4 v2, 0x0

    .line 613
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 614
    .line 615
    .line 616
    move-result-object v0

    .line 617
    check-cast v0, Lc20/a;

    .line 618
    .line 619
    new-instance v1, Lc20/f;

    .line 620
    .line 621
    invoke-direct {v1, v0}, Lc20/f;-><init>(Lc20/a;)V

    .line 622
    .line 623
    .line 624
    return-object v1

    .line 625
    :pswitch_a
    move-object/from16 v0, p1

    .line 626
    .line 627
    check-cast v0, Lk21/a;

    .line 628
    .line 629
    move-object/from16 v1, p2

    .line 630
    .line 631
    check-cast v1, Lg21/a;

    .line 632
    .line 633
    const-string v2, "$this$single"

    .line 634
    .line 635
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 636
    .line 637
    .line 638
    const-string v2, "it"

    .line 639
    .line 640
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 644
    .line 645
    const-class v2, Lve0/u;

    .line 646
    .line 647
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 648
    .line 649
    .line 650
    move-result-object v2

    .line 651
    const/4 v3, 0x0

    .line 652
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    move-result-object v2

    .line 656
    const-class v4, Lwe0/a;

    .line 657
    .line 658
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 659
    .line 660
    .line 661
    move-result-object v5

    .line 662
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object v5

    .line 666
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 667
    .line 668
    .line 669
    move-result-object v1

    .line 670
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 671
    .line 672
    .line 673
    move-result-object v0

    .line 674
    check-cast v0, Lwe0/a;

    .line 675
    .line 676
    check-cast v5, Lwe0/a;

    .line 677
    .line 678
    check-cast v2, Lve0/u;

    .line 679
    .line 680
    new-instance v1, Lzp0/c;

    .line 681
    .line 682
    invoke-direct {v1, v2, v5, v0}, Lzp0/c;-><init>(Lve0/u;Lwe0/a;Lwe0/a;)V

    .line 683
    .line 684
    .line 685
    return-object v1

    .line 686
    :pswitch_b
    move-object/from16 v0, p1

    .line 687
    .line 688
    check-cast v0, Lk21/a;

    .line 689
    .line 690
    move-object/from16 v1, p2

    .line 691
    .line 692
    check-cast v1, Lg21/a;

    .line 693
    .line 694
    const-string v2, "$this$factory"

    .line 695
    .line 696
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 697
    .line 698
    .line 699
    const-string v2, "it"

    .line 700
    .line 701
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 702
    .line 703
    .line 704
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 705
    .line 706
    const-class v2, Lzp0/e;

    .line 707
    .line 708
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 709
    .line 710
    .line 711
    move-result-object v2

    .line 712
    const/4 v3, 0x0

    .line 713
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 714
    .line 715
    .line 716
    move-result-object v2

    .line 717
    const-class v4, Lbq0/h;

    .line 718
    .line 719
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 720
    .line 721
    .line 722
    move-result-object v4

    .line 723
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v4

    .line 727
    const-class v5, Lkf0/o;

    .line 728
    .line 729
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 730
    .line 731
    .line 732
    move-result-object v1

    .line 733
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 734
    .line 735
    .line 736
    move-result-object v0

    .line 737
    check-cast v0, Lkf0/o;

    .line 738
    .line 739
    check-cast v4, Lbq0/h;

    .line 740
    .line 741
    check-cast v2, Lzp0/e;

    .line 742
    .line 743
    new-instance v1, Lbq0/b;

    .line 744
    .line 745
    invoke-direct {v1, v2, v4, v0}, Lbq0/b;-><init>(Lzp0/e;Lbq0/h;Lkf0/o;)V

    .line 746
    .line 747
    .line 748
    return-object v1

    .line 749
    :pswitch_c
    move-object/from16 v0, p1

    .line 750
    .line 751
    check-cast v0, Lk21/a;

    .line 752
    .line 753
    move-object/from16 v1, p2

    .line 754
    .line 755
    check-cast v1, Lg21/a;

    .line 756
    .line 757
    const-string v2, "$this$factory"

    .line 758
    .line 759
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    const-string v2, "it"

    .line 763
    .line 764
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 765
    .line 766
    .line 767
    const-class v1, Lbq0/h;

    .line 768
    .line 769
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 770
    .line 771
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 772
    .line 773
    .line 774
    move-result-object v1

    .line 775
    const/4 v2, 0x0

    .line 776
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 777
    .line 778
    .line 779
    move-result-object v0

    .line 780
    check-cast v0, Lbq0/h;

    .line 781
    .line 782
    new-instance v1, Lbq0/s;

    .line 783
    .line 784
    invoke-direct {v1, v0}, Lbq0/s;-><init>(Lbq0/h;)V

    .line 785
    .line 786
    .line 787
    return-object v1

    .line 788
    :pswitch_d
    move-object/from16 v0, p1

    .line 789
    .line 790
    check-cast v0, Lk21/a;

    .line 791
    .line 792
    move-object/from16 v1, p2

    .line 793
    .line 794
    check-cast v1, Lg21/a;

    .line 795
    .line 796
    const-string v2, "$this$factory"

    .line 797
    .line 798
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    const-string v2, "it"

    .line 802
    .line 803
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 804
    .line 805
    .line 806
    const-class v1, Lbq0/h;

    .line 807
    .line 808
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 809
    .line 810
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 811
    .line 812
    .line 813
    move-result-object v1

    .line 814
    const/4 v2, 0x0

    .line 815
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 816
    .line 817
    .line 818
    move-result-object v0

    .line 819
    check-cast v0, Lbq0/h;

    .line 820
    .line 821
    new-instance v1, Lbq0/k;

    .line 822
    .line 823
    invoke-direct {v1, v0}, Lbq0/k;-><init>(Lbq0/h;)V

    .line 824
    .line 825
    .line 826
    return-object v1

    .line 827
    :pswitch_e
    move-object/from16 v0, p1

    .line 828
    .line 829
    check-cast v0, Lk21/a;

    .line 830
    .line 831
    move-object/from16 v1, p2

    .line 832
    .line 833
    check-cast v1, Lg21/a;

    .line 834
    .line 835
    const-string v2, "$this$factory"

    .line 836
    .line 837
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 838
    .line 839
    .line 840
    const-string v2, "it"

    .line 841
    .line 842
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 843
    .line 844
    .line 845
    const-class v1, Lbq0/h;

    .line 846
    .line 847
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 848
    .line 849
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 850
    .line 851
    .line 852
    move-result-object v1

    .line 853
    const/4 v2, 0x0

    .line 854
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 855
    .line 856
    .line 857
    move-result-object v0

    .line 858
    check-cast v0, Lbq0/h;

    .line 859
    .line 860
    new-instance v1, Lbq0/u;

    .line 861
    .line 862
    invoke-direct {v1, v0}, Lbq0/u;-><init>(Lbq0/h;)V

    .line 863
    .line 864
    .line 865
    return-object v1

    .line 866
    :pswitch_f
    move-object/from16 v0, p1

    .line 867
    .line 868
    check-cast v0, Lk21/a;

    .line 869
    .line 870
    move-object/from16 v1, p2

    .line 871
    .line 872
    check-cast v1, Lg21/a;

    .line 873
    .line 874
    const-string v2, "$this$factory"

    .line 875
    .line 876
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 877
    .line 878
    .line 879
    const-string v2, "it"

    .line 880
    .line 881
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 882
    .line 883
    .line 884
    const-class v1, Lbq0/h;

    .line 885
    .line 886
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 887
    .line 888
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 889
    .line 890
    .line 891
    move-result-object v1

    .line 892
    const/4 v2, 0x0

    .line 893
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    move-result-object v0

    .line 897
    check-cast v0, Lbq0/h;

    .line 898
    .line 899
    new-instance v1, Lbq0/f;

    .line 900
    .line 901
    invoke-direct {v1, v0}, Lbq0/f;-><init>(Lbq0/h;)V

    .line 902
    .line 903
    .line 904
    return-object v1

    .line 905
    :pswitch_10
    move-object/from16 v0, p1

    .line 906
    .line 907
    check-cast v0, Lk21/a;

    .line 908
    .line 909
    move-object/from16 v1, p2

    .line 910
    .line 911
    check-cast v1, Lg21/a;

    .line 912
    .line 913
    const-string v2, "$this$factory"

    .line 914
    .line 915
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 916
    .line 917
    .line 918
    const-string v2, "it"

    .line 919
    .line 920
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 921
    .line 922
    .line 923
    const-class v1, Lbq0/h;

    .line 924
    .line 925
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 926
    .line 927
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 928
    .line 929
    .line 930
    move-result-object v1

    .line 931
    const/4 v2, 0x0

    .line 932
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 933
    .line 934
    .line 935
    move-result-object v0

    .line 936
    check-cast v0, Lbq0/h;

    .line 937
    .line 938
    new-instance v1, Lbq0/d;

    .line 939
    .line 940
    invoke-direct {v1, v0}, Lbq0/d;-><init>(Lbq0/h;)V

    .line 941
    .line 942
    .line 943
    return-object v1

    .line 944
    :pswitch_11
    move-object/from16 v0, p1

    .line 945
    .line 946
    check-cast v0, Lk21/a;

    .line 947
    .line 948
    move-object/from16 v1, p2

    .line 949
    .line 950
    check-cast v1, Lg21/a;

    .line 951
    .line 952
    const-string v2, "$this$factory"

    .line 953
    .line 954
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 955
    .line 956
    .line 957
    const-string v2, "it"

    .line 958
    .line 959
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 960
    .line 961
    .line 962
    const-class v1, Lbq0/h;

    .line 963
    .line 964
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 965
    .line 966
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 967
    .line 968
    .line 969
    move-result-object v1

    .line 970
    const/4 v2, 0x0

    .line 971
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 972
    .line 973
    .line 974
    move-result-object v0

    .line 975
    check-cast v0, Lbq0/h;

    .line 976
    .line 977
    new-instance v1, Lbq0/e;

    .line 978
    .line 979
    invoke-direct {v1, v0}, Lbq0/e;-><init>(Lbq0/h;)V

    .line 980
    .line 981
    .line 982
    return-object v1

    .line 983
    :pswitch_12
    move-object/from16 v0, p1

    .line 984
    .line 985
    check-cast v0, Lk21/a;

    .line 986
    .line 987
    move-object/from16 v1, p2

    .line 988
    .line 989
    check-cast v1, Lg21/a;

    .line 990
    .line 991
    const-string v2, "$this$factory"

    .line 992
    .line 993
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 994
    .line 995
    .line 996
    const-string v2, "it"

    .line 997
    .line 998
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 999
    .line 1000
    .line 1001
    const-class v1, Lbq0/h;

    .line 1002
    .line 1003
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1004
    .line 1005
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v1

    .line 1009
    const/4 v2, 0x0

    .line 1010
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v0

    .line 1014
    check-cast v0, Lbq0/h;

    .line 1015
    .line 1016
    new-instance v1, Lbq0/t;

    .line 1017
    .line 1018
    invoke-direct {v1, v0}, Lbq0/t;-><init>(Lbq0/h;)V

    .line 1019
    .line 1020
    .line 1021
    return-object v1

    .line 1022
    :pswitch_13
    move-object/from16 v0, p1

    .line 1023
    .line 1024
    check-cast v0, Lk21/a;

    .line 1025
    .line 1026
    move-object/from16 v1, p2

    .line 1027
    .line 1028
    check-cast v1, Lg21/a;

    .line 1029
    .line 1030
    const-string v2, "$this$factory"

    .line 1031
    .line 1032
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1033
    .line 1034
    .line 1035
    const-string v2, "it"

    .line 1036
    .line 1037
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1038
    .line 1039
    .line 1040
    const-class v1, Lbq0/h;

    .line 1041
    .line 1042
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1043
    .line 1044
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v1

    .line 1048
    const/4 v2, 0x0

    .line 1049
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v0

    .line 1053
    check-cast v0, Lbq0/h;

    .line 1054
    .line 1055
    new-instance v1, Lbq0/r;

    .line 1056
    .line 1057
    invoke-direct {v1, v0}, Lbq0/r;-><init>(Lbq0/h;)V

    .line 1058
    .line 1059
    .line 1060
    return-object v1

    .line 1061
    :pswitch_14
    move-object/from16 v0, p1

    .line 1062
    .line 1063
    check-cast v0, Lk21/a;

    .line 1064
    .line 1065
    move-object/from16 v1, p2

    .line 1066
    .line 1067
    check-cast v1, Lg21/a;

    .line 1068
    .line 1069
    const-string v2, "$this$factory"

    .line 1070
    .line 1071
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1072
    .line 1073
    .line 1074
    const-string v2, "it"

    .line 1075
    .line 1076
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1077
    .line 1078
    .line 1079
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1080
    .line 1081
    const-class v2, Lbq0/h;

    .line 1082
    .line 1083
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v2

    .line 1087
    const/4 v3, 0x0

    .line 1088
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v2

    .line 1092
    const-class v4, Lkf0/o;

    .line 1093
    .line 1094
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v4

    .line 1098
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v4

    .line 1102
    const-class v5, Lbq0/c;

    .line 1103
    .line 1104
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v1

    .line 1108
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v0

    .line 1112
    check-cast v0, Lbq0/c;

    .line 1113
    .line 1114
    check-cast v4, Lkf0/o;

    .line 1115
    .line 1116
    check-cast v2, Lbq0/h;

    .line 1117
    .line 1118
    new-instance v1, Lbq0/o;

    .line 1119
    .line 1120
    invoke-direct {v1, v2, v4, v0}, Lbq0/o;-><init>(Lbq0/h;Lkf0/o;Lbq0/c;)V

    .line 1121
    .line 1122
    .line 1123
    return-object v1

    .line 1124
    :pswitch_15
    move-object/from16 v0, p1

    .line 1125
    .line 1126
    check-cast v0, Lk21/a;

    .line 1127
    .line 1128
    move-object/from16 v1, p2

    .line 1129
    .line 1130
    check-cast v1, Lg21/a;

    .line 1131
    .line 1132
    const-string v2, "$this$factory"

    .line 1133
    .line 1134
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1135
    .line 1136
    .line 1137
    const-string v2, "it"

    .line 1138
    .line 1139
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1140
    .line 1141
    .line 1142
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1143
    .line 1144
    const-class v2, Lzp0/e;

    .line 1145
    .line 1146
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    const/4 v3, 0x0

    .line 1151
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v2

    .line 1155
    const-class v4, Lbq0/h;

    .line 1156
    .line 1157
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v4

    .line 1161
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v4

    .line 1165
    const-class v5, Lkf0/o;

    .line 1166
    .line 1167
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v1

    .line 1171
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v0

    .line 1175
    check-cast v0, Lkf0/o;

    .line 1176
    .line 1177
    check-cast v4, Lbq0/h;

    .line 1178
    .line 1179
    check-cast v2, Lzp0/e;

    .line 1180
    .line 1181
    new-instance v1, Lbq0/c;

    .line 1182
    .line 1183
    invoke-direct {v1, v2, v4, v0}, Lbq0/c;-><init>(Lzp0/e;Lbq0/h;Lkf0/o;)V

    .line 1184
    .line 1185
    .line 1186
    return-object v1

    .line 1187
    :pswitch_16
    move-object/from16 v0, p1

    .line 1188
    .line 1189
    check-cast v0, Lk21/a;

    .line 1190
    .line 1191
    move-object/from16 v1, p2

    .line 1192
    .line 1193
    check-cast v1, Lg21/a;

    .line 1194
    .line 1195
    const-string v2, "$this$factory"

    .line 1196
    .line 1197
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1198
    .line 1199
    .line 1200
    const-string v2, "it"

    .line 1201
    .line 1202
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1203
    .line 1204
    .line 1205
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1206
    .line 1207
    const-class v2, Lbq0/h;

    .line 1208
    .line 1209
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v2

    .line 1213
    const/4 v3, 0x0

    .line 1214
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v2

    .line 1218
    const-class v4, Lzp0/e;

    .line 1219
    .line 1220
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v4

    .line 1224
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v4

    .line 1228
    const-class v5, Lkf0/o;

    .line 1229
    .line 1230
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v5

    .line 1234
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v5

    .line 1238
    const-class v6, Lsf0/a;

    .line 1239
    .line 1240
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v1

    .line 1244
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1245
    .line 1246
    .line 1247
    move-result-object v0

    .line 1248
    check-cast v0, Lsf0/a;

    .line 1249
    .line 1250
    check-cast v5, Lkf0/o;

    .line 1251
    .line 1252
    check-cast v4, Lzp0/e;

    .line 1253
    .line 1254
    check-cast v2, Lbq0/h;

    .line 1255
    .line 1256
    new-instance v1, Lbq0/q;

    .line 1257
    .line 1258
    invoke-direct {v1, v2, v4, v5, v0}, Lbq0/q;-><init>(Lbq0/h;Lzp0/e;Lkf0/o;Lsf0/a;)V

    .line 1259
    .line 1260
    .line 1261
    return-object v1

    .line 1262
    :pswitch_17
    move-object/from16 v0, p1

    .line 1263
    .line 1264
    check-cast v0, Lk21/a;

    .line 1265
    .line 1266
    move-object/from16 v1, p2

    .line 1267
    .line 1268
    check-cast v1, Lg21/a;

    .line 1269
    .line 1270
    const-string v2, "$this$factory"

    .line 1271
    .line 1272
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1273
    .line 1274
    .line 1275
    const-string v2, "it"

    .line 1276
    .line 1277
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1278
    .line 1279
    .line 1280
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1281
    .line 1282
    const-class v2, Lbq0/h;

    .line 1283
    .line 1284
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1285
    .line 1286
    .line 1287
    move-result-object v2

    .line 1288
    const/4 v3, 0x0

    .line 1289
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1290
    .line 1291
    .line 1292
    move-result-object v2

    .line 1293
    const-class v4, Lzp0/e;

    .line 1294
    .line 1295
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v4

    .line 1299
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v4

    .line 1303
    const-class v5, Lkf0/o;

    .line 1304
    .line 1305
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v5

    .line 1309
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1310
    .line 1311
    .line 1312
    move-result-object v5

    .line 1313
    const-class v6, Lsf0/a;

    .line 1314
    .line 1315
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v6

    .line 1319
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v6

    .line 1323
    const-class v7, Lat0/k;

    .line 1324
    .line 1325
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v1

    .line 1329
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1330
    .line 1331
    .line 1332
    move-result-object v0

    .line 1333
    move-object v12, v0

    .line 1334
    check-cast v12, Lat0/k;

    .line 1335
    .line 1336
    move-object v11, v6

    .line 1337
    check-cast v11, Lsf0/a;

    .line 1338
    .line 1339
    move-object v10, v5

    .line 1340
    check-cast v10, Lkf0/o;

    .line 1341
    .line 1342
    move-object v9, v4

    .line 1343
    check-cast v9, Lzp0/e;

    .line 1344
    .line 1345
    move-object v8, v2

    .line 1346
    check-cast v8, Lbq0/h;

    .line 1347
    .line 1348
    new-instance v7, Lbq0/p;

    .line 1349
    .line 1350
    invoke-direct/range {v7 .. v12}, Lbq0/p;-><init>(Lbq0/h;Lzp0/e;Lkf0/o;Lsf0/a;Lat0/k;)V

    .line 1351
    .line 1352
    .line 1353
    return-object v7

    .line 1354
    :pswitch_18
    move-object/from16 v0, p1

    .line 1355
    .line 1356
    check-cast v0, Lk21/a;

    .line 1357
    .line 1358
    move-object/from16 v1, p2

    .line 1359
    .line 1360
    check-cast v1, Lg21/a;

    .line 1361
    .line 1362
    const-string v2, "$this$factory"

    .line 1363
    .line 1364
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1365
    .line 1366
    .line 1367
    const-string v2, "it"

    .line 1368
    .line 1369
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1370
    .line 1371
    .line 1372
    const-class v1, Lbq0/h;

    .line 1373
    .line 1374
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1375
    .line 1376
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1377
    .line 1378
    .line 1379
    move-result-object v1

    .line 1380
    const/4 v2, 0x0

    .line 1381
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1382
    .line 1383
    .line 1384
    move-result-object v0

    .line 1385
    check-cast v0, Lbq0/h;

    .line 1386
    .line 1387
    new-instance v1, Lbq0/g;

    .line 1388
    .line 1389
    invoke-direct {v1, v0}, Lbq0/g;-><init>(Lbq0/h;)V

    .line 1390
    .line 1391
    .line 1392
    return-object v1

    .line 1393
    :pswitch_19
    move-object/from16 v0, p1

    .line 1394
    .line 1395
    check-cast v0, Lk21/a;

    .line 1396
    .line 1397
    move-object/from16 v1, p2

    .line 1398
    .line 1399
    check-cast v1, Lg21/a;

    .line 1400
    .line 1401
    const-string v2, "$this$factory"

    .line 1402
    .line 1403
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1404
    .line 1405
    .line 1406
    const-string v2, "it"

    .line 1407
    .line 1408
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1409
    .line 1410
    .line 1411
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1412
    .line 1413
    const-class v2, Lbq0/h;

    .line 1414
    .line 1415
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1416
    .line 1417
    .line 1418
    move-result-object v2

    .line 1419
    const/4 v3, 0x0

    .line 1420
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v2

    .line 1424
    const-class v4, Lbq0/b;

    .line 1425
    .line 1426
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v1

    .line 1430
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1431
    .line 1432
    .line 1433
    move-result-object v0

    .line 1434
    check-cast v0, Lbq0/b;

    .line 1435
    .line 1436
    check-cast v2, Lbq0/h;

    .line 1437
    .line 1438
    new-instance v1, Lbq0/j;

    .line 1439
    .line 1440
    invoke-direct {v1, v2, v0}, Lbq0/j;-><init>(Lbq0/h;Lbq0/b;)V

    .line 1441
    .line 1442
    .line 1443
    return-object v1

    .line 1444
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1445
    .line 1446
    check-cast v0, Lk21/a;

    .line 1447
    .line 1448
    move-object/from16 v1, p2

    .line 1449
    .line 1450
    check-cast v1, Lg21/a;

    .line 1451
    .line 1452
    const-string v2, "$this$single"

    .line 1453
    .line 1454
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1455
    .line 1456
    .line 1457
    const-string v0, "it"

    .line 1458
    .line 1459
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1460
    .line 1461
    .line 1462
    new-instance v0, Lzm0/b;

    .line 1463
    .line 1464
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1465
    .line 1466
    .line 1467
    return-object v0

    .line 1468
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1469
    .line 1470
    check-cast v0, Lk21/a;

    .line 1471
    .line 1472
    move-object/from16 v1, p2

    .line 1473
    .line 1474
    check-cast v1, Lg21/a;

    .line 1475
    .line 1476
    const-string v2, "$this$factory"

    .line 1477
    .line 1478
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1479
    .line 1480
    .line 1481
    const-string v2, "it"

    .line 1482
    .line 1483
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1484
    .line 1485
    .line 1486
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1487
    .line 1488
    const-class v2, Lkf0/b0;

    .line 1489
    .line 1490
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1491
    .line 1492
    .line 1493
    move-result-object v2

    .line 1494
    const/4 v3, 0x0

    .line 1495
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1496
    .line 1497
    .line 1498
    move-result-object v2

    .line 1499
    const-class v4, Lwr0/h;

    .line 1500
    .line 1501
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1502
    .line 1503
    .line 1504
    move-result-object v4

    .line 1505
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v4

    .line 1509
    const-class v5, Lcc0/g;

    .line 1510
    .line 1511
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1512
    .line 1513
    .line 1514
    move-result-object v5

    .line 1515
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1516
    .line 1517
    .line 1518
    move-result-object v5

    .line 1519
    const-class v6, Lcc0/e;

    .line 1520
    .line 1521
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v6

    .line 1525
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v6

    .line 1529
    const-class v7, Lbn0/b;

    .line 1530
    .line 1531
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1532
    .line 1533
    .line 1534
    move-result-object v7

    .line 1535
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v7

    .line 1539
    const-class v8, Lbn0/h;

    .line 1540
    .line 1541
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1542
    .line 1543
    .line 1544
    move-result-object v1

    .line 1545
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1546
    .line 1547
    .line 1548
    move-result-object v0

    .line 1549
    move-object v14, v0

    .line 1550
    check-cast v14, Lbn0/h;

    .line 1551
    .line 1552
    move-object v13, v7

    .line 1553
    check-cast v13, Lbn0/b;

    .line 1554
    .line 1555
    move-object v12, v6

    .line 1556
    check-cast v12, Lcc0/e;

    .line 1557
    .line 1558
    move-object v11, v5

    .line 1559
    check-cast v11, Lcc0/g;

    .line 1560
    .line 1561
    move-object v10, v4

    .line 1562
    check-cast v10, Lwr0/h;

    .line 1563
    .line 1564
    move-object v9, v2

    .line 1565
    check-cast v9, Lkf0/b0;

    .line 1566
    .line 1567
    new-instance v8, Lbn0/g;

    .line 1568
    .line 1569
    invoke-direct/range {v8 .. v14}, Lbn0/g;-><init>(Lkf0/b0;Lwr0/h;Lcc0/g;Lcc0/e;Lbn0/b;Lbn0/h;)V

    .line 1570
    .line 1571
    .line 1572
    return-object v8

    .line 1573
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1574
    .line 1575
    check-cast v0, Lk21/a;

    .line 1576
    .line 1577
    move-object/from16 v1, p2

    .line 1578
    .line 1579
    check-cast v1, Lg21/a;

    .line 1580
    .line 1581
    const-string v2, "$this$factory"

    .line 1582
    .line 1583
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1584
    .line 1585
    .line 1586
    const-string v2, "it"

    .line 1587
    .line 1588
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1589
    .line 1590
    .line 1591
    const-class v1, Lgm0/m;

    .line 1592
    .line 1593
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1594
    .line 1595
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1596
    .line 1597
    .line 1598
    move-result-object v1

    .line 1599
    const/4 v2, 0x0

    .line 1600
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1601
    .line 1602
    .line 1603
    move-result-object v0

    .line 1604
    check-cast v0, Lgm0/m;

    .line 1605
    .line 1606
    new-instance v1, Lbn0/b;

    .line 1607
    .line 1608
    invoke-direct {v1, v0}, Lbn0/b;-><init>(Lgm0/m;)V

    .line 1609
    .line 1610
    .line 1611
    return-object v1

    .line 1612
    nop

    .line 1613
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
