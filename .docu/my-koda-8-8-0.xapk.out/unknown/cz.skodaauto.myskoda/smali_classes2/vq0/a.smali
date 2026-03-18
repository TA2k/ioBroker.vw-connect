.class public final Lvq0/a;
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
    iput p1, p0, Lvq0/a;->d:I

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
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lvq0/a;->d:I

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
    const-class v1, Ly50/f;

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
    check-cast v0, Ly50/f;

    .line 40
    .line 41
    new-instance v1, Ly50/g;

    .line 42
    .line 43
    invoke-direct {v1, v0}, Ly50/g;-><init>(Ly50/f;)V

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
    const-string v2, "$this$viewModel"

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
    const-class v2, Lrs0/g;

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
    const-class v4, Lgb0/l;

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
    const-class v5, Llp0/b;

    .line 89
    .line 90
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    const-class v6, Llp0/d;

    .line 99
    .line 100
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    const-class v7, Lxu0/b;

    .line 109
    .line 110
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 111
    .line 112
    .line 113
    move-result-object v7

    .line 114
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    const-class v8, Lwi0/h;

    .line 119
    .line 120
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v8

    .line 128
    const-class v9, Lwi0/f;

    .line 129
    .line 130
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 131
    .line 132
    .line 133
    move-result-object v9

    .line 134
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v9

    .line 138
    const-class v10, Lub0/g;

    .line 139
    .line 140
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    invoke-virtual {v0, v10, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v10

    .line 148
    const-class v11, Lub0/c;

    .line 149
    .line 150
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 151
    .line 152
    .line 153
    move-result-object v11

    .line 154
    invoke-virtual {v0, v11, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v11

    .line 158
    const-class v12, Lhh0/a;

    .line 159
    .line 160
    invoke-virtual {v1, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 161
    .line 162
    .line 163
    move-result-object v12

    .line 164
    invoke-virtual {v0, v12, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v12

    .line 168
    const-class v13, Lee0/h;

    .line 169
    .line 170
    invoke-virtual {v1, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 171
    .line 172
    .line 173
    move-result-object v13

    .line 174
    invoke-virtual {v0, v13, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v13

    .line 178
    const-class v14, Lee0/b;

    .line 179
    .line 180
    invoke-virtual {v1, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 181
    .line 182
    .line 183
    move-result-object v14

    .line 184
    invoke-virtual {v0, v14, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v14

    .line 188
    const-class v15, Lee0/d;

    .line 189
    .line 190
    invoke-virtual {v1, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    move-object/from16 v28, v0

    .line 199
    .line 200
    check-cast v28, Lee0/d;

    .line 201
    .line 202
    move-object/from16 v27, v14

    .line 203
    .line 204
    check-cast v27, Lee0/b;

    .line 205
    .line 206
    move-object/from16 v26, v13

    .line 207
    .line 208
    check-cast v26, Lee0/h;

    .line 209
    .line 210
    move-object/from16 v25, v12

    .line 211
    .line 212
    check-cast v25, Lhh0/a;

    .line 213
    .line 214
    move-object/from16 v24, v11

    .line 215
    .line 216
    check-cast v24, Lub0/c;

    .line 217
    .line 218
    move-object/from16 v23, v10

    .line 219
    .line 220
    check-cast v23, Lub0/g;

    .line 221
    .line 222
    move-object/from16 v22, v9

    .line 223
    .line 224
    check-cast v22, Lwi0/f;

    .line 225
    .line 226
    move-object/from16 v21, v8

    .line 227
    .line 228
    check-cast v21, Lwi0/h;

    .line 229
    .line 230
    move-object/from16 v20, v7

    .line 231
    .line 232
    check-cast v20, Lxu0/b;

    .line 233
    .line 234
    move-object/from16 v19, v6

    .line 235
    .line 236
    check-cast v19, Llp0/d;

    .line 237
    .line 238
    move-object/from16 v18, v5

    .line 239
    .line 240
    check-cast v18, Llp0/b;

    .line 241
    .line 242
    move-object/from16 v17, v4

    .line 243
    .line 244
    check-cast v17, Lgb0/l;

    .line 245
    .line 246
    move-object/from16 v16, v2

    .line 247
    .line 248
    check-cast v16, Lrs0/g;

    .line 249
    .line 250
    new-instance v15, Ldv0/e;

    .line 251
    .line 252
    invoke-direct/range {v15 .. v28}, Ldv0/e;-><init>(Lrs0/g;Lgb0/l;Llp0/b;Llp0/d;Lxu0/b;Lwi0/h;Lwi0/f;Lub0/g;Lub0/c;Lhh0/a;Lee0/h;Lee0/b;Lee0/d;)V

    .line 253
    .line 254
    .line 255
    return-object v15

    .line 256
    :pswitch_1
    move-object/from16 v0, p1

    .line 257
    .line 258
    check-cast v0, Lk21/a;

    .line 259
    .line 260
    move-object/from16 v1, p2

    .line 261
    .line 262
    check-cast v1, Lg21/a;

    .line 263
    .line 264
    const-string v2, "$this$factory"

    .line 265
    .line 266
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    const-string v2, "it"

    .line 270
    .line 271
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    const-class v1, Lxu0/a;

    .line 275
    .line 276
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 277
    .line 278
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    const/4 v2, 0x0

    .line 283
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    check-cast v0, Lxu0/a;

    .line 288
    .line 289
    new-instance v1, Lxu0/b;

    .line 290
    .line 291
    invoke-direct {v1, v0}, Lxu0/b;-><init>(Lxu0/a;)V

    .line 292
    .line 293
    .line 294
    return-object v1

    .line 295
    :pswitch_2
    move-object/from16 v0, p1

    .line 296
    .line 297
    check-cast v0, Lk21/a;

    .line 298
    .line 299
    move-object/from16 v1, p2

    .line 300
    .line 301
    check-cast v1, Lg21/a;

    .line 302
    .line 303
    const-string v2, "$this$single"

    .line 304
    .line 305
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    const-string v0, "it"

    .line 309
    .line 310
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    new-instance v0, Lvh0/a;

    .line 314
    .line 315
    invoke-direct {v0}, Lvh0/a;-><init>()V

    .line 316
    .line 317
    .line 318
    return-object v0

    .line 319
    :pswitch_3
    move-object/from16 v0, p1

    .line 320
    .line 321
    check-cast v0, Lk21/a;

    .line 322
    .line 323
    move-object/from16 v1, p2

    .line 324
    .line 325
    check-cast v1, Lg21/a;

    .line 326
    .line 327
    const-string v2, "$this$factory"

    .line 328
    .line 329
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    const-string v2, "it"

    .line 333
    .line 334
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 338
    .line 339
    const-class v2, Lxh0/d;

    .line 340
    .line 341
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 342
    .line 343
    .line 344
    move-result-object v2

    .line 345
    const/4 v3, 0x0

    .line 346
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    const-class v4, Landroid/app/NotificationManager;

    .line 351
    .line 352
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 353
    .line 354
    .line 355
    move-result-object v1

    .line 356
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    check-cast v0, Landroid/app/NotificationManager;

    .line 361
    .line 362
    check-cast v2, Lxh0/d;

    .line 363
    .line 364
    new-instance v1, Lzh0/a;

    .line 365
    .line 366
    invoke-direct {v1, v2, v0}, Lzh0/a;-><init>(Lxh0/d;Landroid/app/NotificationManager;)V

    .line 367
    .line 368
    .line 369
    return-object v1

    .line 370
    :pswitch_4
    move-object/from16 v0, p1

    .line 371
    .line 372
    check-cast v0, Lk21/a;

    .line 373
    .line 374
    move-object/from16 v1, p2

    .line 375
    .line 376
    check-cast v1, Lg21/a;

    .line 377
    .line 378
    const-string v2, "$this$viewModel"

    .line 379
    .line 380
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    const-string v2, "it"

    .line 384
    .line 385
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 389
    .line 390
    const-class v2, Lkf0/o;

    .line 391
    .line 392
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 393
    .line 394
    .line 395
    move-result-object v2

    .line 396
    const/4 v3, 0x0

    .line 397
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v2

    .line 401
    const-class v4, Lud0/b;

    .line 402
    .line 403
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 404
    .line 405
    .line 406
    move-result-object v4

    .line 407
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v4

    .line 411
    const-class v5, Lrq0/f;

    .line 412
    .line 413
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 414
    .line 415
    .line 416
    move-result-object v5

    .line 417
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    move-result-object v5

    .line 421
    const-class v6, Lij0/a;

    .line 422
    .line 423
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    check-cast v0, Lij0/a;

    .line 432
    .line 433
    check-cast v5, Lrq0/f;

    .line 434
    .line 435
    check-cast v4, Lud0/b;

    .line 436
    .line 437
    check-cast v2, Lkf0/o;

    .line 438
    .line 439
    new-instance v1, Lxg0/b;

    .line 440
    .line 441
    invoke-direct {v1, v2, v4, v5, v0}, Lxg0/b;-><init>(Lkf0/o;Lud0/b;Lrq0/f;Lij0/a;)V

    .line 442
    .line 443
    .line 444
    return-object v1

    .line 445
    :pswitch_5
    move-object/from16 v0, p1

    .line 446
    .line 447
    check-cast v0, Lk21/a;

    .line 448
    .line 449
    move-object/from16 v1, p2

    .line 450
    .line 451
    check-cast v1, Lg21/a;

    .line 452
    .line 453
    const-string v2, "$this$viewModel"

    .line 454
    .line 455
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    const-string v2, "it"

    .line 459
    .line 460
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 461
    .line 462
    .line 463
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 464
    .line 465
    const-class v2, Lfj0/g;

    .line 466
    .line 467
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 468
    .line 469
    .line 470
    move-result-object v2

    .line 471
    const/4 v3, 0x0

    .line 472
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v2

    .line 476
    const-class v4, Lwz/b;

    .line 477
    .line 478
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 479
    .line 480
    .line 481
    move-result-object v1

    .line 482
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v0

    .line 486
    check-cast v0, Lwz/b;

    .line 487
    .line 488
    check-cast v2, Lfj0/g;

    .line 489
    .line 490
    new-instance v1, Lyz/e;

    .line 491
    .line 492
    invoke-direct {v1, v2, v0}, Lyz/e;-><init>(Lfj0/g;Lwz/b;)V

    .line 493
    .line 494
    .line 495
    return-object v1

    .line 496
    :pswitch_6
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
    const-string v2, "$this$viewModel"

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
    const-class v2, Lfj0/b;

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
    const-class v4, Lfj0/c;

    .line 528
    .line 529
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 530
    .line 531
    .line 532
    move-result-object v4

    .line 533
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v4

    .line 537
    const-class v5, Ltr0/b;

    .line 538
    .line 539
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 540
    .line 541
    .line 542
    move-result-object v5

    .line 543
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 544
    .line 545
    .line 546
    move-result-object v5

    .line 547
    const-class v6, Lfj0/a;

    .line 548
    .line 549
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 550
    .line 551
    .line 552
    move-result-object v1

    .line 553
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v0

    .line 557
    check-cast v0, Lfj0/a;

    .line 558
    .line 559
    check-cast v5, Ltr0/b;

    .line 560
    .line 561
    check-cast v4, Lfj0/c;

    .line 562
    .line 563
    check-cast v2, Lfj0/b;

    .line 564
    .line 565
    new-instance v1, Lyz/c;

    .line 566
    .line 567
    invoke-direct {v1, v2, v4, v5, v0}, Lyz/c;-><init>(Lfj0/b;Lfj0/c;Ltr0/b;Lfj0/a;)V

    .line 568
    .line 569
    .line 570
    return-object v1

    .line 571
    :pswitch_7
    move-object/from16 v0, p1

    .line 572
    .line 573
    check-cast v0, Lk21/a;

    .line 574
    .line 575
    move-object/from16 v1, p2

    .line 576
    .line 577
    check-cast v1, Lg21/a;

    .line 578
    .line 579
    const-string v2, "$this$factory"

    .line 580
    .line 581
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 582
    .line 583
    .line 584
    const-string v2, "it"

    .line 585
    .line 586
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    const-class v1, Lwz/a;

    .line 590
    .line 591
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 592
    .line 593
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 594
    .line 595
    .line 596
    move-result-object v1

    .line 597
    const/4 v2, 0x0

    .line 598
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 599
    .line 600
    .line 601
    move-result-object v0

    .line 602
    check-cast v0, Lwz/a;

    .line 603
    .line 604
    new-instance v1, Lwz/b;

    .line 605
    .line 606
    invoke-direct {v1, v0}, Lwz/b;-><init>(Lwz/a;)V

    .line 607
    .line 608
    .line 609
    return-object v1

    .line 610
    :pswitch_8
    move-object/from16 v0, p1

    .line 611
    .line 612
    check-cast v0, Lk21/a;

    .line 613
    .line 614
    move-object/from16 v1, p2

    .line 615
    .line 616
    check-cast v1, Lg21/a;

    .line 617
    .line 618
    const-string v2, "$this$factory"

    .line 619
    .line 620
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 621
    .line 622
    .line 623
    const-string v2, "it"

    .line 624
    .line 625
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 626
    .line 627
    .line 628
    const-class v1, Lus0/b;

    .line 629
    .line 630
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 631
    .line 632
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 633
    .line 634
    .line 635
    move-result-object v1

    .line 636
    const/4 v2, 0x0

    .line 637
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 638
    .line 639
    .line 640
    move-result-object v0

    .line 641
    check-cast v0, Lus0/b;

    .line 642
    .line 643
    new-instance v1, Lws0/c;

    .line 644
    .line 645
    invoke-direct {v1, v0}, Lws0/c;-><init>(Lus0/b;)V

    .line 646
    .line 647
    .line 648
    return-object v1

    .line 649
    :pswitch_9
    move-object/from16 v0, p1

    .line 650
    .line 651
    check-cast v0, Lk21/a;

    .line 652
    .line 653
    move-object/from16 v1, p2

    .line 654
    .line 655
    check-cast v1, Lg21/a;

    .line 656
    .line 657
    const-string v2, "$this$factory"

    .line 658
    .line 659
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 660
    .line 661
    .line 662
    const-string v2, "it"

    .line 663
    .line 664
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 665
    .line 666
    .line 667
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 668
    .line 669
    const-class v2, Lkf0/b0;

    .line 670
    .line 671
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 672
    .line 673
    .line 674
    move-result-object v2

    .line 675
    const/4 v3, 0x0

    .line 676
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 677
    .line 678
    .line 679
    move-result-object v2

    .line 680
    const-class v4, Lus0/b;

    .line 681
    .line 682
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 683
    .line 684
    .line 685
    move-result-object v1

    .line 686
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 687
    .line 688
    .line 689
    move-result-object v0

    .line 690
    check-cast v0, Lus0/b;

    .line 691
    .line 692
    check-cast v2, Lkf0/b0;

    .line 693
    .line 694
    new-instance v1, Lws0/a;

    .line 695
    .line 696
    invoke-direct {v1, v2, v0}, Lws0/a;-><init>(Lkf0/b0;Lus0/b;)V

    .line 697
    .line 698
    .line 699
    return-object v1

    .line 700
    :pswitch_a
    move-object/from16 v0, p1

    .line 701
    .line 702
    check-cast v0, Lk21/a;

    .line 703
    .line 704
    move-object/from16 v1, p2

    .line 705
    .line 706
    check-cast v1, Lg21/a;

    .line 707
    .line 708
    const-string v2, "$this$factory"

    .line 709
    .line 710
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 711
    .line 712
    .line 713
    const-string v2, "it"

    .line 714
    .line 715
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 716
    .line 717
    .line 718
    const-class v1, Lus0/g;

    .line 719
    .line 720
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 721
    .line 722
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 723
    .line 724
    .line 725
    move-result-object v1

    .line 726
    const/4 v2, 0x0

    .line 727
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 728
    .line 729
    .line 730
    move-result-object v0

    .line 731
    check-cast v0, Lus0/g;

    .line 732
    .line 733
    new-instance v1, Lws0/n;

    .line 734
    .line 735
    invoke-direct {v1, v0}, Lws0/n;-><init>(Lus0/g;)V

    .line 736
    .line 737
    .line 738
    return-object v1

    .line 739
    :pswitch_b
    move-object/from16 v0, p1

    .line 740
    .line 741
    check-cast v0, Lk21/a;

    .line 742
    .line 743
    move-object/from16 v1, p2

    .line 744
    .line 745
    check-cast v1, Lg21/a;

    .line 746
    .line 747
    const-string v2, "$this$factory"

    .line 748
    .line 749
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 750
    .line 751
    .line 752
    const-string v2, "it"

    .line 753
    .line 754
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 755
    .line 756
    .line 757
    const-class v1, Lus0/g;

    .line 758
    .line 759
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 760
    .line 761
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 762
    .line 763
    .line 764
    move-result-object v1

    .line 765
    const/4 v2, 0x0

    .line 766
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 767
    .line 768
    .line 769
    move-result-object v0

    .line 770
    check-cast v0, Lus0/g;

    .line 771
    .line 772
    new-instance v1, Lws0/l;

    .line 773
    .line 774
    invoke-direct {v1, v0}, Lws0/l;-><init>(Lus0/g;)V

    .line 775
    .line 776
    .line 777
    return-object v1

    .line 778
    :pswitch_c
    move-object/from16 v0, p1

    .line 779
    .line 780
    check-cast v0, Lk21/a;

    .line 781
    .line 782
    move-object/from16 v1, p2

    .line 783
    .line 784
    check-cast v1, Lg21/a;

    .line 785
    .line 786
    const-string v2, "$this$factory"

    .line 787
    .line 788
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 789
    .line 790
    .line 791
    const-string v2, "it"

    .line 792
    .line 793
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 797
    .line 798
    const-class v2, Lws0/f;

    .line 799
    .line 800
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 801
    .line 802
    .line 803
    move-result-object v2

    .line 804
    const/4 v3, 0x0

    .line 805
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 806
    .line 807
    .line 808
    move-result-object v2

    .line 809
    const-class v4, Lkf0/b0;

    .line 810
    .line 811
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 812
    .line 813
    .line 814
    move-result-object v4

    .line 815
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 816
    .line 817
    .line 818
    move-result-object v4

    .line 819
    const-class v5, Lkf0/k;

    .line 820
    .line 821
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 822
    .line 823
    .line 824
    move-result-object v5

    .line 825
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 826
    .line 827
    .line 828
    move-result-object v5

    .line 829
    const-class v6, Lkf0/y;

    .line 830
    .line 831
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 832
    .line 833
    .line 834
    move-result-object v6

    .line 835
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 836
    .line 837
    .line 838
    move-result-object v6

    .line 839
    const-class v7, Lws0/l;

    .line 840
    .line 841
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 842
    .line 843
    .line 844
    move-result-object v7

    .line 845
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 846
    .line 847
    .line 848
    move-result-object v7

    .line 849
    const-class v8, Lws0/e;

    .line 850
    .line 851
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 852
    .line 853
    .line 854
    move-result-object v1

    .line 855
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 856
    .line 857
    .line 858
    move-result-object v0

    .line 859
    move-object v14, v0

    .line 860
    check-cast v14, Lws0/e;

    .line 861
    .line 862
    move-object v13, v7

    .line 863
    check-cast v13, Lws0/l;

    .line 864
    .line 865
    move-object v12, v6

    .line 866
    check-cast v12, Lkf0/y;

    .line 867
    .line 868
    move-object v11, v5

    .line 869
    check-cast v11, Lkf0/k;

    .line 870
    .line 871
    move-object v10, v4

    .line 872
    check-cast v10, Lkf0/b0;

    .line 873
    .line 874
    move-object v9, v2

    .line 875
    check-cast v9, Lws0/f;

    .line 876
    .line 877
    new-instance v8, Lws0/k;

    .line 878
    .line 879
    invoke-direct/range {v8 .. v14}, Lws0/k;-><init>(Lws0/f;Lkf0/b0;Lkf0/k;Lkf0/y;Lws0/l;Lws0/e;)V

    .line 880
    .line 881
    .line 882
    return-object v8

    .line 883
    :pswitch_d
    move-object/from16 v0, p1

    .line 884
    .line 885
    check-cast v0, Lk21/a;

    .line 886
    .line 887
    move-object/from16 v1, p2

    .line 888
    .line 889
    check-cast v1, Lg21/a;

    .line 890
    .line 891
    const-string v2, "$this$factory"

    .line 892
    .line 893
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 894
    .line 895
    .line 896
    const-string v2, "it"

    .line 897
    .line 898
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 899
    .line 900
    .line 901
    const-class v1, Lus0/b;

    .line 902
    .line 903
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 904
    .line 905
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 906
    .line 907
    .line 908
    move-result-object v1

    .line 909
    const/4 v2, 0x0

    .line 910
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 911
    .line 912
    .line 913
    move-result-object v0

    .line 914
    check-cast v0, Lus0/b;

    .line 915
    .line 916
    new-instance v1, Lws0/f;

    .line 917
    .line 918
    invoke-direct {v1, v0}, Lws0/f;-><init>(Lus0/b;)V

    .line 919
    .line 920
    .line 921
    return-object v1

    .line 922
    :pswitch_e
    move-object/from16 v0, p1

    .line 923
    .line 924
    check-cast v0, Lk21/a;

    .line 925
    .line 926
    move-object/from16 v1, p2

    .line 927
    .line 928
    check-cast v1, Lg21/a;

    .line 929
    .line 930
    const-string v2, "$this$factory"

    .line 931
    .line 932
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 933
    .line 934
    .line 935
    const-string v2, "it"

    .line 936
    .line 937
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 938
    .line 939
    .line 940
    const-class v1, Lus0/g;

    .line 941
    .line 942
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 943
    .line 944
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 945
    .line 946
    .line 947
    move-result-object v1

    .line 948
    const/4 v2, 0x0

    .line 949
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 950
    .line 951
    .line 952
    move-result-object v0

    .line 953
    check-cast v0, Lus0/g;

    .line 954
    .line 955
    new-instance v1, Lws0/e;

    .line 956
    .line 957
    invoke-direct {v1, v0}, Lws0/e;-><init>(Lus0/g;)V

    .line 958
    .line 959
    .line 960
    return-object v1

    .line 961
    :pswitch_f
    move-object/from16 v0, p1

    .line 962
    .line 963
    check-cast v0, Lk21/a;

    .line 964
    .line 965
    move-object/from16 v1, p2

    .line 966
    .line 967
    check-cast v1, Lg21/a;

    .line 968
    .line 969
    const-string v2, "$this$factory"

    .line 970
    .line 971
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 972
    .line 973
    .line 974
    const-string v2, "it"

    .line 975
    .line 976
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 977
    .line 978
    .line 979
    const-class v1, Lwr0/q;

    .line 980
    .line 981
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 982
    .line 983
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 984
    .line 985
    .line 986
    move-result-object v1

    .line 987
    const/4 v2, 0x0

    .line 988
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 989
    .line 990
    .line 991
    move-result-object v0

    .line 992
    check-cast v0, Lwr0/q;

    .line 993
    .line 994
    new-instance v1, Lwr0/l;

    .line 995
    .line 996
    invoke-direct {v1, v0}, Lwr0/l;-><init>(Lwr0/q;)V

    .line 997
    .line 998
    .line 999
    return-object v1

    .line 1000
    :pswitch_10
    move-object/from16 v0, p1

    .line 1001
    .line 1002
    check-cast v0, Lk21/a;

    .line 1003
    .line 1004
    move-object/from16 v1, p2

    .line 1005
    .line 1006
    check-cast v1, Lg21/a;

    .line 1007
    .line 1008
    const-string v2, "$this$factory"

    .line 1009
    .line 1010
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1011
    .line 1012
    .line 1013
    const-string v2, "it"

    .line 1014
    .line 1015
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1016
    .line 1017
    .line 1018
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1019
    .line 1020
    const-class v2, Lam0/c;

    .line 1021
    .line 1022
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v2

    .line 1026
    const/4 v3, 0x0

    .line 1027
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v2

    .line 1031
    const-class v4, Lwr0/e;

    .line 1032
    .line 1033
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v4

    .line 1037
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v4

    .line 1041
    const-class v5, Lbd0/c;

    .line 1042
    .line 1043
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1044
    .line 1045
    .line 1046
    move-result-object v1

    .line 1047
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v0

    .line 1051
    check-cast v0, Lbd0/c;

    .line 1052
    .line 1053
    check-cast v4, Lwr0/e;

    .line 1054
    .line 1055
    check-cast v2, Lam0/c;

    .line 1056
    .line 1057
    new-instance v1, Lwr0/k;

    .line 1058
    .line 1059
    invoke-direct {v1, v2, v0, v4}, Lwr0/k;-><init>(Lam0/c;Lbd0/c;Lwr0/e;)V

    .line 1060
    .line 1061
    .line 1062
    return-object v1

    .line 1063
    :pswitch_11
    move-object/from16 v0, p1

    .line 1064
    .line 1065
    check-cast v0, Lk21/a;

    .line 1066
    .line 1067
    move-object/from16 v1, p2

    .line 1068
    .line 1069
    check-cast v1, Lg21/a;

    .line 1070
    .line 1071
    const-string v2, "$this$factory"

    .line 1072
    .line 1073
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1074
    .line 1075
    .line 1076
    const-string v2, "it"

    .line 1077
    .line 1078
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1079
    .line 1080
    .line 1081
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1082
    .line 1083
    const-class v2, Lur0/b;

    .line 1084
    .line 1085
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v2

    .line 1089
    const/4 v3, 0x0

    .line 1090
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v2

    .line 1094
    const-class v4, Lwr0/g;

    .line 1095
    .line 1096
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v1

    .line 1100
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v0

    .line 1104
    check-cast v0, Lwr0/g;

    .line 1105
    .line 1106
    check-cast v2, Lur0/b;

    .line 1107
    .line 1108
    new-instance v1, Lwr0/c;

    .line 1109
    .line 1110
    invoke-direct {v1, v2, v0}, Lwr0/c;-><init>(Lur0/b;Lwr0/g;)V

    .line 1111
    .line 1112
    .line 1113
    return-object v1

    .line 1114
    :pswitch_12
    move-object/from16 v0, p1

    .line 1115
    .line 1116
    check-cast v0, Lk21/a;

    .line 1117
    .line 1118
    move-object/from16 v1, p2

    .line 1119
    .line 1120
    check-cast v1, Lg21/a;

    .line 1121
    .line 1122
    const-string v2, "$this$factory"

    .line 1123
    .line 1124
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1125
    .line 1126
    .line 1127
    const-string v2, "it"

    .line 1128
    .line 1129
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1130
    .line 1131
    .line 1132
    const-class v1, Lwr0/g;

    .line 1133
    .line 1134
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1135
    .line 1136
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v1

    .line 1140
    const/4 v2, 0x0

    .line 1141
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1142
    .line 1143
    .line 1144
    move-result-object v0

    .line 1145
    check-cast v0, Lwr0/g;

    .line 1146
    .line 1147
    new-instance v1, Lwr0/o;

    .line 1148
    .line 1149
    invoke-direct {v1, v0}, Lwr0/o;-><init>(Lwr0/g;)V

    .line 1150
    .line 1151
    .line 1152
    return-object v1

    .line 1153
    :pswitch_13
    move-object/from16 v0, p1

    .line 1154
    .line 1155
    check-cast v0, Lk21/a;

    .line 1156
    .line 1157
    move-object/from16 v1, p2

    .line 1158
    .line 1159
    check-cast v1, Lg21/a;

    .line 1160
    .line 1161
    const-string v2, "$this$factory"

    .line 1162
    .line 1163
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1164
    .line 1165
    .line 1166
    const-string v2, "it"

    .line 1167
    .line 1168
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1169
    .line 1170
    .line 1171
    const-class v1, Lwr0/g;

    .line 1172
    .line 1173
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1174
    .line 1175
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v1

    .line 1179
    const/4 v2, 0x0

    .line 1180
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v0

    .line 1184
    check-cast v0, Lwr0/g;

    .line 1185
    .line 1186
    new-instance v1, Lwr0/h;

    .line 1187
    .line 1188
    invoke-direct {v1, v0}, Lwr0/h;-><init>(Lwr0/g;)V

    .line 1189
    .line 1190
    .line 1191
    return-object v1

    .line 1192
    :pswitch_14
    move-object/from16 v0, p1

    .line 1193
    .line 1194
    check-cast v0, Lk21/a;

    .line 1195
    .line 1196
    move-object/from16 v1, p2

    .line 1197
    .line 1198
    check-cast v1, Lg21/a;

    .line 1199
    .line 1200
    const-string v2, "$this$factory"

    .line 1201
    .line 1202
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1203
    .line 1204
    .line 1205
    const-string v2, "it"

    .line 1206
    .line 1207
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1208
    .line 1209
    .line 1210
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1211
    .line 1212
    const-class v2, Lwr0/g;

    .line 1213
    .line 1214
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v2

    .line 1218
    const/4 v3, 0x0

    .line 1219
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1220
    .line 1221
    .line 1222
    move-result-object v2

    .line 1223
    const-class v4, Lwr0/c;

    .line 1224
    .line 1225
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v1

    .line 1229
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v0

    .line 1233
    check-cast v0, Lwr0/c;

    .line 1234
    .line 1235
    check-cast v2, Lwr0/g;

    .line 1236
    .line 1237
    new-instance v1, Lwr0/i;

    .line 1238
    .line 1239
    invoke-direct {v1, v2, v0}, Lwr0/i;-><init>(Lwr0/g;Lwr0/c;)V

    .line 1240
    .line 1241
    .line 1242
    return-object v1

    .line 1243
    :pswitch_15
    move-object/from16 v0, p1

    .line 1244
    .line 1245
    check-cast v0, Lk21/a;

    .line 1246
    .line 1247
    move-object/from16 v1, p2

    .line 1248
    .line 1249
    check-cast v1, Lg21/a;

    .line 1250
    .line 1251
    const-string v2, "$this$factory"

    .line 1252
    .line 1253
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1254
    .line 1255
    .line 1256
    const-string v2, "it"

    .line 1257
    .line 1258
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1259
    .line 1260
    .line 1261
    const-class v1, Lwr0/g;

    .line 1262
    .line 1263
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1264
    .line 1265
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1266
    .line 1267
    .line 1268
    move-result-object v1

    .line 1269
    const/4 v2, 0x0

    .line 1270
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v0

    .line 1274
    check-cast v0, Lwr0/g;

    .line 1275
    .line 1276
    new-instance v1, Lwr0/d;

    .line 1277
    .line 1278
    invoke-direct {v1, v0}, Lwr0/d;-><init>(Lwr0/g;)V

    .line 1279
    .line 1280
    .line 1281
    return-object v1

    .line 1282
    :pswitch_16
    move-object/from16 v0, p1

    .line 1283
    .line 1284
    check-cast v0, Lk21/a;

    .line 1285
    .line 1286
    move-object/from16 v1, p2

    .line 1287
    .line 1288
    check-cast v1, Lg21/a;

    .line 1289
    .line 1290
    const-string v2, "$this$factory"

    .line 1291
    .line 1292
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1293
    .line 1294
    .line 1295
    const-string v2, "it"

    .line 1296
    .line 1297
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1298
    .line 1299
    .line 1300
    const-class v1, Lwr0/g;

    .line 1301
    .line 1302
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1303
    .line 1304
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v1

    .line 1308
    const/4 v2, 0x0

    .line 1309
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1310
    .line 1311
    .line 1312
    move-result-object v0

    .line 1313
    check-cast v0, Lwr0/g;

    .line 1314
    .line 1315
    new-instance v1, Lwr0/e;

    .line 1316
    .line 1317
    invoke-direct {v1, v0}, Lwr0/e;-><init>(Lwr0/g;)V

    .line 1318
    .line 1319
    .line 1320
    return-object v1

    .line 1321
    :pswitch_17
    move-object/from16 v0, p1

    .line 1322
    .line 1323
    check-cast v0, Lk21/a;

    .line 1324
    .line 1325
    move-object/from16 v1, p2

    .line 1326
    .line 1327
    check-cast v1, Lg21/a;

    .line 1328
    .line 1329
    const-string v2, "$this$factory"

    .line 1330
    .line 1331
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1332
    .line 1333
    .line 1334
    const-string v2, "it"

    .line 1335
    .line 1336
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1337
    .line 1338
    .line 1339
    const-class v1, Lur0/b;

    .line 1340
    .line 1341
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1342
    .line 1343
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v1

    .line 1347
    const/4 v2, 0x0

    .line 1348
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1349
    .line 1350
    .line 1351
    move-result-object v0

    .line 1352
    check-cast v0, Lur0/b;

    .line 1353
    .line 1354
    new-instance v1, Lwr0/a;

    .line 1355
    .line 1356
    invoke-direct {v1, v0}, Lwr0/a;-><init>(Lur0/b;)V

    .line 1357
    .line 1358
    .line 1359
    return-object v1

    .line 1360
    :pswitch_18
    move-object/from16 v0, p1

    .line 1361
    .line 1362
    check-cast v0, Lk21/a;

    .line 1363
    .line 1364
    move-object/from16 v1, p2

    .line 1365
    .line 1366
    check-cast v1, Lg21/a;

    .line 1367
    .line 1368
    const-string v2, "$this$factory"

    .line 1369
    .line 1370
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1371
    .line 1372
    .line 1373
    const-string v2, "it"

    .line 1374
    .line 1375
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1376
    .line 1377
    .line 1378
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1379
    .line 1380
    const-class v2, Lur0/b;

    .line 1381
    .line 1382
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1383
    .line 1384
    .line 1385
    move-result-object v2

    .line 1386
    const/4 v3, 0x0

    .line 1387
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1388
    .line 1389
    .line 1390
    move-result-object v2

    .line 1391
    const-class v4, Lwr0/g;

    .line 1392
    .line 1393
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1394
    .line 1395
    .line 1396
    move-result-object v4

    .line 1397
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1398
    .line 1399
    .line 1400
    move-result-object v4

    .line 1401
    const-class v5, Lsf0/a;

    .line 1402
    .line 1403
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1404
    .line 1405
    .line 1406
    move-result-object v1

    .line 1407
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v0

    .line 1411
    check-cast v0, Lsf0/a;

    .line 1412
    .line 1413
    check-cast v4, Lwr0/g;

    .line 1414
    .line 1415
    check-cast v2, Lur0/b;

    .line 1416
    .line 1417
    new-instance v1, Lwr0/p;

    .line 1418
    .line 1419
    invoke-direct {v1, v2, v4, v0}, Lwr0/p;-><init>(Lur0/b;Lwr0/g;Lsf0/a;)V

    .line 1420
    .line 1421
    .line 1422
    return-object v1

    .line 1423
    :pswitch_19
    move-object/from16 v0, p1

    .line 1424
    .line 1425
    check-cast v0, Lk21/a;

    .line 1426
    .line 1427
    move-object/from16 v1, p2

    .line 1428
    .line 1429
    check-cast v1, Lg21/a;

    .line 1430
    .line 1431
    const-string v2, "$this$factory"

    .line 1432
    .line 1433
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1434
    .line 1435
    .line 1436
    const-string v2, "it"

    .line 1437
    .line 1438
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1439
    .line 1440
    .line 1441
    const-class v1, Lwr0/g;

    .line 1442
    .line 1443
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1444
    .line 1445
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1446
    .line 1447
    .line 1448
    move-result-object v1

    .line 1449
    const/4 v2, 0x0

    .line 1450
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1451
    .line 1452
    .line 1453
    move-result-object v0

    .line 1454
    check-cast v0, Lwr0/g;

    .line 1455
    .line 1456
    new-instance v1, Lwr0/f;

    .line 1457
    .line 1458
    invoke-direct {v1, v0}, Lwr0/f;-><init>(Lwr0/g;)V

    .line 1459
    .line 1460
    .line 1461
    return-object v1

    .line 1462
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1463
    .line 1464
    check-cast v0, Lk21/a;

    .line 1465
    .line 1466
    move-object/from16 v1, p2

    .line 1467
    .line 1468
    check-cast v1, Lg21/a;

    .line 1469
    .line 1470
    const-string v2, "$this$single"

    .line 1471
    .line 1472
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1473
    .line 1474
    .line 1475
    const-string v0, "it"

    .line 1476
    .line 1477
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1478
    .line 1479
    .line 1480
    new-instance v0, Lzq0/h;

    .line 1481
    .line 1482
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1483
    .line 1484
    .line 1485
    return-object v0

    .line 1486
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1487
    .line 1488
    check-cast v0, Lk21/a;

    .line 1489
    .line 1490
    move-object/from16 v1, p2

    .line 1491
    .line 1492
    check-cast v1, Lg21/a;

    .line 1493
    .line 1494
    const-string v2, "$this$single"

    .line 1495
    .line 1496
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1497
    .line 1498
    .line 1499
    const-string v2, "it"

    .line 1500
    .line 1501
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1502
    .line 1503
    .line 1504
    const-class v1, Lve0/u;

    .line 1505
    .line 1506
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1507
    .line 1508
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v1

    .line 1512
    const/4 v2, 0x0

    .line 1513
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1514
    .line 1515
    .line 1516
    move-result-object v0

    .line 1517
    check-cast v0, Lve0/u;

    .line 1518
    .line 1519
    new-instance v1, Ltq0/i;

    .line 1520
    .line 1521
    invoke-direct {v1, v0}, Ltq0/i;-><init>(Lve0/u;)V

    .line 1522
    .line 1523
    .line 1524
    return-object v1

    .line 1525
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1526
    .line 1527
    check-cast v0, Lk21/a;

    .line 1528
    .line 1529
    move-object/from16 v1, p2

    .line 1530
    .line 1531
    check-cast v1, Lg21/a;

    .line 1532
    .line 1533
    const-string v2, "$this$single"

    .line 1534
    .line 1535
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1536
    .line 1537
    .line 1538
    const-string v2, "it"

    .line 1539
    .line 1540
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1541
    .line 1542
    .line 1543
    const-class v1, Lve0/u;

    .line 1544
    .line 1545
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1546
    .line 1547
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1548
    .line 1549
    .line 1550
    move-result-object v1

    .line 1551
    const/4 v2, 0x0

    .line 1552
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1553
    .line 1554
    .line 1555
    move-result-object v0

    .line 1556
    check-cast v0, Lve0/u;

    .line 1557
    .line 1558
    new-instance v1, Ltq0/d;

    .line 1559
    .line 1560
    invoke-direct {v1, v0}, Ltq0/d;-><init>(Lve0/u;)V

    .line 1561
    .line 1562
    .line 1563
    return-object v1

    .line 1564
    nop

    .line 1565
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
