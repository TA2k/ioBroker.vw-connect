.class public final Lr50/b;
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
    iput p1, p0, Lr50/b;->d:I

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
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lr50/b;->d:I

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
    new-instance v1, Ljy/h;

    .line 27
    .line 28
    const/16 v2, 0xd

    .line 29
    .line 30
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 31
    .line 32
    .line 33
    return-object v1

    .line 34
    :pswitch_0
    move-object/from16 v0, p1

    .line 35
    .line 36
    check-cast v0, Lk21/a;

    .line 37
    .line 38
    move-object/from16 v1, p2

    .line 39
    .line 40
    check-cast v1, Lg21/a;

    .line 41
    .line 42
    const-string v2, "$this$factory"

    .line 43
    .line 44
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v0, "it"

    .line 48
    .line 49
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Luc0/c;

    .line 53
    .line 54
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 55
    .line 56
    .line 57
    return-object v0

    .line 58
    :pswitch_1
    move-object/from16 v0, p1

    .line 59
    .line 60
    check-cast v0, Lk21/a;

    .line 61
    .line 62
    move-object/from16 v1, p2

    .line 63
    .line 64
    check-cast v1, Lg21/a;

    .line 65
    .line 66
    const-string v2, "$this$factory"

    .line 67
    .line 68
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const-string v0, "it"

    .line 72
    .line 73
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Luc0/b;

    .line 77
    .line 78
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 79
    .line 80
    .line 81
    return-object v0

    .line 82
    :pswitch_2
    move-object/from16 v0, p1

    .line 83
    .line 84
    check-cast v0, Lk21/a;

    .line 85
    .line 86
    move-object/from16 v1, p2

    .line 87
    .line 88
    check-cast v1, Lg21/a;

    .line 89
    .line 90
    const-string v2, "$this$viewModel"

    .line 91
    .line 92
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    const-string v2, "it"

    .line 96
    .line 97
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    const-class v1, Lbh0/d;

    .line 101
    .line 102
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 103
    .line 104
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    const/4 v2, 0x0

    .line 109
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    check-cast v0, Lbh0/d;

    .line 114
    .line 115
    new-instance v1, Lt20/b;

    .line 116
    .line 117
    invoke-direct {v1, v0}, Lt20/b;-><init>(Lbh0/d;)V

    .line 118
    .line 119
    .line 120
    return-object v1

    .line 121
    :pswitch_3
    move-object/from16 v0, p1

    .line 122
    .line 123
    check-cast v0, Lk21/a;

    .line 124
    .line 125
    move-object/from16 v1, p2

    .line 126
    .line 127
    check-cast v1, Lg21/a;

    .line 128
    .line 129
    const-string v2, "$this$viewModel"

    .line 130
    .line 131
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string v2, "it"

    .line 135
    .line 136
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 140
    .line 141
    const-class v2, Ls50/t;

    .line 142
    .line 143
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    const/4 v3, 0x0

    .line 148
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    const-class v4, Ls50/x;

    .line 153
    .line 154
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v4

    .line 162
    const-class v5, Ls50/d0;

    .line 163
    .line 164
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    const-class v6, Lbh0/f;

    .line 173
    .line 174
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v6

    .line 182
    const-class v7, Ltr0/b;

    .line 183
    .line 184
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    move-object v12, v0

    .line 193
    check-cast v12, Ltr0/b;

    .line 194
    .line 195
    move-object v11, v6

    .line 196
    check-cast v11, Lbh0/f;

    .line 197
    .line 198
    move-object v10, v5

    .line 199
    check-cast v10, Ls50/d0;

    .line 200
    .line 201
    move-object v9, v4

    .line 202
    check-cast v9, Ls50/x;

    .line 203
    .line 204
    move-object v8, v2

    .line 205
    check-cast v8, Ls50/t;

    .line 206
    .line 207
    new-instance v7, Lu50/e;

    .line 208
    .line 209
    invoke-direct/range {v7 .. v12}, Lu50/e;-><init>(Ls50/t;Ls50/x;Ls50/d0;Lbh0/f;Ltr0/b;)V

    .line 210
    .line 211
    .line 212
    return-object v7

    .line 213
    :pswitch_4
    move-object/from16 v0, p1

    .line 214
    .line 215
    check-cast v0, Lk21/a;

    .line 216
    .line 217
    move-object/from16 v1, p2

    .line 218
    .line 219
    check-cast v1, Lg21/a;

    .line 220
    .line 221
    const-string v2, "$this$viewModel"

    .line 222
    .line 223
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string v2, "it"

    .line 227
    .line 228
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 232
    .line 233
    const-class v2, Ltr0/b;

    .line 234
    .line 235
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    const/4 v3, 0x0

    .line 240
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v2

    .line 244
    const-class v4, Lrs0/b;

    .line 245
    .line 246
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 247
    .line 248
    .line 249
    move-result-object v4

    .line 250
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v4

    .line 254
    const-class v5, Ls50/p;

    .line 255
    .line 256
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v5

    .line 264
    const-class v6, Ls50/c0;

    .line 265
    .line 266
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 267
    .line 268
    .line 269
    move-result-object v6

    .line 270
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    const-class v7, Lij0/a;

    .line 275
    .line 276
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    move-object v12, v0

    .line 285
    check-cast v12, Lij0/a;

    .line 286
    .line 287
    move-object v11, v6

    .line 288
    check-cast v11, Ls50/c0;

    .line 289
    .line 290
    move-object v10, v5

    .line 291
    check-cast v10, Ls50/p;

    .line 292
    .line 293
    move-object v9, v4

    .line 294
    check-cast v9, Lrs0/b;

    .line 295
    .line 296
    move-object v8, v2

    .line 297
    check-cast v8, Ltr0/b;

    .line 298
    .line 299
    new-instance v7, Lu50/e0;

    .line 300
    .line 301
    invoke-direct/range {v7 .. v12}, Lu50/e0;-><init>(Ltr0/b;Lrs0/b;Ls50/p;Ls50/c0;Lij0/a;)V

    .line 302
    .line 303
    .line 304
    return-object v7

    .line 305
    :pswitch_5
    move-object/from16 v0, p1

    .line 306
    .line 307
    check-cast v0, Lk21/a;

    .line 308
    .line 309
    move-object/from16 v1, p2

    .line 310
    .line 311
    check-cast v1, Lg21/a;

    .line 312
    .line 313
    const-string v2, "$this$viewModel"

    .line 314
    .line 315
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    const-string v2, "it"

    .line 319
    .line 320
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 324
    .line 325
    const-class v2, Ls50/i;

    .line 326
    .line 327
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 328
    .line 329
    .line 330
    move-result-object v2

    .line 331
    const/4 v3, 0x0

    .line 332
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    const-class v4, Ls50/z;

    .line 337
    .line 338
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 339
    .line 340
    .line 341
    move-result-object v4

    .line 342
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v4

    .line 346
    const-class v5, Ltr0/b;

    .line 347
    .line 348
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    check-cast v0, Ltr0/b;

    .line 357
    .line 358
    check-cast v4, Ls50/z;

    .line 359
    .line 360
    check-cast v2, Ls50/i;

    .line 361
    .line 362
    new-instance v1, Lu50/y;

    .line 363
    .line 364
    invoke-direct {v1, v2, v4, v0}, Lu50/y;-><init>(Ls50/i;Ls50/z;Ltr0/b;)V

    .line 365
    .line 366
    .line 367
    return-object v1

    .line 368
    :pswitch_6
    move-object/from16 v0, p1

    .line 369
    .line 370
    check-cast v0, Lk21/a;

    .line 371
    .line 372
    move-object/from16 v1, p2

    .line 373
    .line 374
    check-cast v1, Lg21/a;

    .line 375
    .line 376
    const-string v2, "$this$viewModel"

    .line 377
    .line 378
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    const-string v2, "it"

    .line 382
    .line 383
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    const-class v1, Ltr0/b;

    .line 387
    .line 388
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 389
    .line 390
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 391
    .line 392
    .line 393
    move-result-object v1

    .line 394
    const/4 v2, 0x0

    .line 395
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    check-cast v0, Ltr0/b;

    .line 400
    .line 401
    new-instance v1, Lu50/l;

    .line 402
    .line 403
    invoke-direct {v1, v0}, Lu50/l;-><init>(Ltr0/b;)V

    .line 404
    .line 405
    .line 406
    return-object v1

    .line 407
    :pswitch_7
    move-object/from16 v0, p1

    .line 408
    .line 409
    check-cast v0, Lk21/a;

    .line 410
    .line 411
    move-object/from16 v1, p2

    .line 412
    .line 413
    check-cast v1, Lg21/a;

    .line 414
    .line 415
    const-string v2, "$this$viewModel"

    .line 416
    .line 417
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 418
    .line 419
    .line 420
    const-string v2, "it"

    .line 421
    .line 422
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    const-class v1, Ltr0/b;

    .line 426
    .line 427
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 428
    .line 429
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 430
    .line 431
    .line 432
    move-result-object v1

    .line 433
    const/4 v2, 0x0

    .line 434
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    check-cast v0, Ltr0/b;

    .line 439
    .line 440
    new-instance v1, Lu50/m;

    .line 441
    .line 442
    invoke-direct {v1, v0}, Lu50/m;-><init>(Ltr0/b;)V

    .line 443
    .line 444
    .line 445
    return-object v1

    .line 446
    :pswitch_8
    move-object/from16 v0, p1

    .line 447
    .line 448
    check-cast v0, Lk21/a;

    .line 449
    .line 450
    move-object/from16 v1, p2

    .line 451
    .line 452
    check-cast v1, Lg21/a;

    .line 453
    .line 454
    const-string v2, "$this$viewModel"

    .line 455
    .line 456
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    const-string v2, "it"

    .line 460
    .line 461
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 462
    .line 463
    .line 464
    const-class v1, Ls50/u;

    .line 465
    .line 466
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 467
    .line 468
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 469
    .line 470
    .line 471
    move-result-object v1

    .line 472
    const/4 v2, 0x0

    .line 473
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    check-cast v0, Ls50/u;

    .line 478
    .line 479
    new-instance v1, Lu50/n;

    .line 480
    .line 481
    invoke-direct {v1, v0}, Lu50/n;-><init>(Ls50/u;)V

    .line 482
    .line 483
    .line 484
    return-object v1

    .line 485
    :pswitch_9
    move-object/from16 v0, p1

    .line 486
    .line 487
    check-cast v0, Lk21/a;

    .line 488
    .line 489
    move-object/from16 v1, p2

    .line 490
    .line 491
    check-cast v1, Lg21/a;

    .line 492
    .line 493
    const-string v2, "$this$viewModel"

    .line 494
    .line 495
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 496
    .line 497
    .line 498
    const-string v2, "it"

    .line 499
    .line 500
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 501
    .line 502
    .line 503
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 504
    .line 505
    const-class v2, Lrs0/g;

    .line 506
    .line 507
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 508
    .line 509
    .line 510
    move-result-object v2

    .line 511
    const/4 v3, 0x0

    .line 512
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v2

    .line 516
    const-class v4, Ls50/o;

    .line 517
    .line 518
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 519
    .line 520
    .line 521
    move-result-object v4

    .line 522
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 523
    .line 524
    .line 525
    move-result-object v4

    .line 526
    const-class v5, Ls50/q;

    .line 527
    .line 528
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 529
    .line 530
    .line 531
    move-result-object v5

    .line 532
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v5

    .line 536
    const-class v6, Ltr0/b;

    .line 537
    .line 538
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 539
    .line 540
    .line 541
    move-result-object v6

    .line 542
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v6

    .line 546
    const-class v7, Ls50/b0;

    .line 547
    .line 548
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 549
    .line 550
    .line 551
    move-result-object v7

    .line 552
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    move-result-object v7

    .line 556
    const-class v8, Ls50/b;

    .line 557
    .line 558
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 559
    .line 560
    .line 561
    move-result-object v8

    .line 562
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v8

    .line 566
    const-class v9, Lij0/a;

    .line 567
    .line 568
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 569
    .line 570
    .line 571
    move-result-object v1

    .line 572
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v0

    .line 576
    move-object/from16 v16, v0

    .line 577
    .line 578
    check-cast v16, Lij0/a;

    .line 579
    .line 580
    move-object v15, v8

    .line 581
    check-cast v15, Ls50/b;

    .line 582
    .line 583
    move-object v14, v7

    .line 584
    check-cast v14, Ls50/b0;

    .line 585
    .line 586
    move-object v13, v6

    .line 587
    check-cast v13, Ltr0/b;

    .line 588
    .line 589
    move-object v12, v5

    .line 590
    check-cast v12, Ls50/q;

    .line 591
    .line 592
    move-object v11, v4

    .line 593
    check-cast v11, Ls50/o;

    .line 594
    .line 595
    move-object v10, v2

    .line 596
    check-cast v10, Lrs0/g;

    .line 597
    .line 598
    new-instance v9, Lu50/r;

    .line 599
    .line 600
    invoke-direct/range {v9 .. v16}, Lu50/r;-><init>(Lrs0/g;Ls50/o;Ls50/q;Ltr0/b;Ls50/b0;Ls50/b;Lij0/a;)V

    .line 601
    .line 602
    .line 603
    return-object v9

    .line 604
    :pswitch_a
    move-object/from16 v0, p1

    .line 605
    .line 606
    check-cast v0, Lk21/a;

    .line 607
    .line 608
    move-object/from16 v1, p2

    .line 609
    .line 610
    check-cast v1, Lg21/a;

    .line 611
    .line 612
    const-string v2, "$this$viewModel"

    .line 613
    .line 614
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    const-string v2, "it"

    .line 618
    .line 619
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 620
    .line 621
    .line 622
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 623
    .line 624
    const-class v2, Lkf0/v;

    .line 625
    .line 626
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 627
    .line 628
    .line 629
    move-result-object v2

    .line 630
    const/4 v3, 0x0

    .line 631
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 632
    .line 633
    .line 634
    move-result-object v2

    .line 635
    const-class v4, Ltr0/b;

    .line 636
    .line 637
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 638
    .line 639
    .line 640
    move-result-object v4

    .line 641
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 642
    .line 643
    .line 644
    move-result-object v4

    .line 645
    const-class v5, Ls50/s;

    .line 646
    .line 647
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 648
    .line 649
    .line 650
    move-result-object v5

    .line 651
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v5

    .line 655
    const-class v6, Ls50/w;

    .line 656
    .line 657
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 658
    .line 659
    .line 660
    move-result-object v6

    .line 661
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 662
    .line 663
    .line 664
    move-result-object v6

    .line 665
    const-class v7, Ls50/a0;

    .line 666
    .line 667
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 668
    .line 669
    .line 670
    move-result-object v7

    .line 671
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object v7

    .line 675
    const-class v8, Ls50/b0;

    .line 676
    .line 677
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 678
    .line 679
    .line 680
    move-result-object v8

    .line 681
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 682
    .line 683
    .line 684
    move-result-object v8

    .line 685
    const-class v9, Ls50/e;

    .line 686
    .line 687
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 688
    .line 689
    .line 690
    move-result-object v9

    .line 691
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 692
    .line 693
    .line 694
    move-result-object v9

    .line 695
    const-class v10, Lrs0/b;

    .line 696
    .line 697
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 698
    .line 699
    .line 700
    move-result-object v10

    .line 701
    invoke-virtual {v0, v10, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 702
    .line 703
    .line 704
    move-result-object v10

    .line 705
    const-class v11, Ls50/h0;

    .line 706
    .line 707
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 708
    .line 709
    .line 710
    move-result-object v11

    .line 711
    invoke-virtual {v0, v11, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v11

    .line 715
    const-class v12, Lij0/a;

    .line 716
    .line 717
    invoke-virtual {v1, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 722
    .line 723
    .line 724
    move-result-object v0

    .line 725
    move-object/from16 v22, v0

    .line 726
    .line 727
    check-cast v22, Lij0/a;

    .line 728
    .line 729
    move-object/from16 v21, v11

    .line 730
    .line 731
    check-cast v21, Ls50/h0;

    .line 732
    .line 733
    move-object/from16 v20, v10

    .line 734
    .line 735
    check-cast v20, Lrs0/b;

    .line 736
    .line 737
    move-object/from16 v19, v9

    .line 738
    .line 739
    check-cast v19, Ls50/e;

    .line 740
    .line 741
    move-object/from16 v18, v8

    .line 742
    .line 743
    check-cast v18, Ls50/b0;

    .line 744
    .line 745
    move-object/from16 v17, v7

    .line 746
    .line 747
    check-cast v17, Ls50/a0;

    .line 748
    .line 749
    move-object/from16 v16, v6

    .line 750
    .line 751
    check-cast v16, Ls50/w;

    .line 752
    .line 753
    move-object v15, v5

    .line 754
    check-cast v15, Ls50/s;

    .line 755
    .line 756
    move-object v14, v4

    .line 757
    check-cast v14, Ltr0/b;

    .line 758
    .line 759
    move-object v13, v2

    .line 760
    check-cast v13, Lkf0/v;

    .line 761
    .line 762
    new-instance v12, Lu50/k;

    .line 763
    .line 764
    invoke-direct/range {v12 .. v22}, Lu50/k;-><init>(Lkf0/v;Ltr0/b;Ls50/s;Ls50/w;Ls50/a0;Ls50/b0;Ls50/e;Lrs0/b;Ls50/h0;Lij0/a;)V

    .line 765
    .line 766
    .line 767
    return-object v12

    .line 768
    :pswitch_b
    move-object/from16 v0, p1

    .line 769
    .line 770
    check-cast v0, Lk21/a;

    .line 771
    .line 772
    move-object/from16 v1, p2

    .line 773
    .line 774
    check-cast v1, Lg21/a;

    .line 775
    .line 776
    const-string v2, "$this$viewModel"

    .line 777
    .line 778
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 779
    .line 780
    .line 781
    const-string v2, "it"

    .line 782
    .line 783
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 784
    .line 785
    .line 786
    const-class v1, Ls50/u;

    .line 787
    .line 788
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 789
    .line 790
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 791
    .line 792
    .line 793
    move-result-object v1

    .line 794
    const/4 v2, 0x0

    .line 795
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    move-result-object v0

    .line 799
    check-cast v0, Ls50/u;

    .line 800
    .line 801
    new-instance v1, Lu50/z;

    .line 802
    .line 803
    invoke-direct {v1, v0}, Lu50/z;-><init>(Ls50/u;)V

    .line 804
    .line 805
    .line 806
    return-object v1

    .line 807
    :pswitch_c
    move-object/from16 v0, p1

    .line 808
    .line 809
    check-cast v0, Lk21/a;

    .line 810
    .line 811
    move-object/from16 v1, p2

    .line 812
    .line 813
    check-cast v1, Lg21/a;

    .line 814
    .line 815
    const-string v2, "$this$viewModel"

    .line 816
    .line 817
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 818
    .line 819
    .line 820
    const-string v2, "it"

    .line 821
    .line 822
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 823
    .line 824
    .line 825
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 826
    .line 827
    const-class v2, Ls50/r;

    .line 828
    .line 829
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 830
    .line 831
    .line 832
    move-result-object v2

    .line 833
    const/4 v3, 0x0

    .line 834
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 835
    .line 836
    .line 837
    move-result-object v2

    .line 838
    const-class v4, Ls50/g0;

    .line 839
    .line 840
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 841
    .line 842
    .line 843
    move-result-object v4

    .line 844
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v4

    .line 848
    const-class v5, Ls50/h;

    .line 849
    .line 850
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 851
    .line 852
    .line 853
    move-result-object v5

    .line 854
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 855
    .line 856
    .line 857
    move-result-object v5

    .line 858
    const-class v6, Ls50/u;

    .line 859
    .line 860
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 861
    .line 862
    .line 863
    move-result-object v1

    .line 864
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 865
    .line 866
    .line 867
    move-result-object v0

    .line 868
    check-cast v0, Ls50/u;

    .line 869
    .line 870
    check-cast v5, Ls50/h;

    .line 871
    .line 872
    check-cast v4, Ls50/g0;

    .line 873
    .line 874
    check-cast v2, Ls50/r;

    .line 875
    .line 876
    new-instance v1, Lu50/c;

    .line 877
    .line 878
    invoke-direct {v1, v2, v4, v5, v0}, Lu50/c;-><init>(Ls50/r;Ls50/g0;Ls50/h;Ls50/u;)V

    .line 879
    .line 880
    .line 881
    return-object v1

    .line 882
    :pswitch_d
    move-object/from16 v0, p1

    .line 883
    .line 884
    check-cast v0, Lk21/a;

    .line 885
    .line 886
    move-object/from16 v1, p2

    .line 887
    .line 888
    check-cast v1, Lg21/a;

    .line 889
    .line 890
    const-string v2, "$this$viewModel"

    .line 891
    .line 892
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 893
    .line 894
    .line 895
    const-string v2, "it"

    .line 896
    .line 897
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 901
    .line 902
    const-class v2, Lrs0/b;

    .line 903
    .line 904
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 905
    .line 906
    .line 907
    move-result-object v2

    .line 908
    const/4 v3, 0x0

    .line 909
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    move-result-object v2

    .line 913
    const-class v4, Ls50/c;

    .line 914
    .line 915
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 916
    .line 917
    .line 918
    move-result-object v4

    .line 919
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object v4

    .line 923
    const-class v5, Ls50/y;

    .line 924
    .line 925
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 926
    .line 927
    .line 928
    move-result-object v5

    .line 929
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 930
    .line 931
    .line 932
    move-result-object v5

    .line 933
    const-class v6, Ltr0/b;

    .line 934
    .line 935
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 936
    .line 937
    .line 938
    move-result-object v6

    .line 939
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v6

    .line 943
    const-class v7, Lij0/a;

    .line 944
    .line 945
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 946
    .line 947
    .line 948
    move-result-object v1

    .line 949
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 950
    .line 951
    .line 952
    move-result-object v0

    .line 953
    move-object v12, v0

    .line 954
    check-cast v12, Lij0/a;

    .line 955
    .line 956
    move-object v11, v6

    .line 957
    check-cast v11, Ltr0/b;

    .line 958
    .line 959
    move-object v10, v5

    .line 960
    check-cast v10, Ls50/y;

    .line 961
    .line 962
    move-object v9, v4

    .line 963
    check-cast v9, Ls50/c;

    .line 964
    .line 965
    move-object v8, v2

    .line 966
    check-cast v8, Lrs0/b;

    .line 967
    .line 968
    new-instance v7, Lu50/w;

    .line 969
    .line 970
    invoke-direct/range {v7 .. v12}, Lu50/w;-><init>(Lrs0/b;Ls50/c;Ls50/y;Ltr0/b;Lij0/a;)V

    .line 971
    .line 972
    .line 973
    return-object v7

    .line 974
    :pswitch_e
    move-object/from16 v0, p1

    .line 975
    .line 976
    check-cast v0, Lk21/a;

    .line 977
    .line 978
    move-object/from16 v1, p2

    .line 979
    .line 980
    check-cast v1, Lg21/a;

    .line 981
    .line 982
    const-string v2, "$this$viewModel"

    .line 983
    .line 984
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 985
    .line 986
    .line 987
    const-string v2, "it"

    .line 988
    .line 989
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 990
    .line 991
    .line 992
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 993
    .line 994
    const-class v2, Ls50/u;

    .line 995
    .line 996
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 997
    .line 998
    .line 999
    move-result-object v2

    .line 1000
    const/4 v3, 0x0

    .line 1001
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v2

    .line 1005
    const-class v4, Ltr0/b;

    .line 1006
    .line 1007
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v1

    .line 1011
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v0

    .line 1015
    check-cast v0, Ltr0/b;

    .line 1016
    .line 1017
    check-cast v2, Ls50/u;

    .line 1018
    .line 1019
    new-instance v1, Lu50/s;

    .line 1020
    .line 1021
    invoke-direct {v1, v2, v0}, Lu50/s;-><init>(Ls50/u;Ltr0/b;)V

    .line 1022
    .line 1023
    .line 1024
    return-object v1

    .line 1025
    :pswitch_f
    move-object/from16 v0, p1

    .line 1026
    .line 1027
    check-cast v0, Lk21/a;

    .line 1028
    .line 1029
    move-object/from16 v1, p2

    .line 1030
    .line 1031
    check-cast v1, Lg21/a;

    .line 1032
    .line 1033
    const-string v2, "$this$viewModel"

    .line 1034
    .line 1035
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1036
    .line 1037
    .line 1038
    const-string v2, "it"

    .line 1039
    .line 1040
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1041
    .line 1042
    .line 1043
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1044
    .line 1045
    const-class v2, Ls50/u;

    .line 1046
    .line 1047
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v2

    .line 1051
    const/4 v3, 0x0

    .line 1052
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v2

    .line 1056
    const-class v4, Ltr0/b;

    .line 1057
    .line 1058
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v1

    .line 1062
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    check-cast v0, Ltr0/b;

    .line 1067
    .line 1068
    check-cast v2, Ls50/u;

    .line 1069
    .line 1070
    new-instance v1, Lu50/a0;

    .line 1071
    .line 1072
    invoke-direct {v1, v2, v0}, Lu50/a0;-><init>(Ls50/u;Ltr0/b;)V

    .line 1073
    .line 1074
    .line 1075
    return-object v1

    .line 1076
    :pswitch_10
    move-object/from16 v0, p1

    .line 1077
    .line 1078
    check-cast v0, Lk21/a;

    .line 1079
    .line 1080
    move-object/from16 v1, p2

    .line 1081
    .line 1082
    check-cast v1, Lg21/a;

    .line 1083
    .line 1084
    const-string v2, "$this$single"

    .line 1085
    .line 1086
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1087
    .line 1088
    .line 1089
    const-string v2, "it"

    .line 1090
    .line 1091
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1092
    .line 1093
    .line 1094
    new-instance v1, Ljy/h;

    .line 1095
    .line 1096
    const/16 v2, 0xb

    .line 1097
    .line 1098
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 1099
    .line 1100
    .line 1101
    return-object v1

    .line 1102
    :pswitch_11
    move-object/from16 v0, p1

    .line 1103
    .line 1104
    check-cast v0, Lk21/a;

    .line 1105
    .line 1106
    move-object/from16 v1, p2

    .line 1107
    .line 1108
    check-cast v1, Lg21/a;

    .line 1109
    .line 1110
    const-string v2, "$this$single"

    .line 1111
    .line 1112
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1113
    .line 1114
    .line 1115
    const-string v2, "it"

    .line 1116
    .line 1117
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1118
    .line 1119
    .line 1120
    const-class v1, Lwe0/a;

    .line 1121
    .line 1122
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1123
    .line 1124
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v1

    .line 1128
    const/4 v2, 0x0

    .line 1129
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v0

    .line 1133
    check-cast v0, Lwe0/a;

    .line 1134
    .line 1135
    new-instance v1, Lp50/e;

    .line 1136
    .line 1137
    invoke-direct {v1, v0}, Lp50/e;-><init>(Lwe0/a;)V

    .line 1138
    .line 1139
    .line 1140
    return-object v1

    .line 1141
    :pswitch_12
    move-object/from16 v0, p1

    .line 1142
    .line 1143
    check-cast v0, Lk21/a;

    .line 1144
    .line 1145
    move-object/from16 v1, p2

    .line 1146
    .line 1147
    check-cast v1, Lg21/a;

    .line 1148
    .line 1149
    const-string v2, "$this$single"

    .line 1150
    .line 1151
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1152
    .line 1153
    .line 1154
    const-string v0, "it"

    .line 1155
    .line 1156
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1157
    .line 1158
    .line 1159
    new-instance v0, Lq50/a;

    .line 1160
    .line 1161
    invoke-direct {v0}, Lq50/a;-><init>()V

    .line 1162
    .line 1163
    .line 1164
    return-object v0

    .line 1165
    :pswitch_13
    move-object/from16 v0, p1

    .line 1166
    .line 1167
    check-cast v0, Lk21/a;

    .line 1168
    .line 1169
    move-object/from16 v1, p2

    .line 1170
    .line 1171
    check-cast v1, Lg21/a;

    .line 1172
    .line 1173
    const-string v2, "$this$single"

    .line 1174
    .line 1175
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1176
    .line 1177
    .line 1178
    const-string v2, "it"

    .line 1179
    .line 1180
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1181
    .line 1182
    .line 1183
    const-class v1, Ls50/m;

    .line 1184
    .line 1185
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1186
    .line 1187
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1188
    .line 1189
    .line 1190
    move-result-object v1

    .line 1191
    const/4 v2, 0x0

    .line 1192
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v0

    .line 1196
    check-cast v0, Ls50/m;

    .line 1197
    .line 1198
    new-instance v1, Ls50/b;

    .line 1199
    .line 1200
    invoke-direct {v1, v0}, Ls50/b;-><init>(Ls50/m;)V

    .line 1201
    .line 1202
    .line 1203
    return-object v1

    .line 1204
    :pswitch_14
    move-object/from16 v0, p1

    .line 1205
    .line 1206
    check-cast v0, Lk21/a;

    .line 1207
    .line 1208
    move-object/from16 v1, p2

    .line 1209
    .line 1210
    check-cast v1, Lg21/a;

    .line 1211
    .line 1212
    const-string v2, "$this$single"

    .line 1213
    .line 1214
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1215
    .line 1216
    .line 1217
    const-string v2, "it"

    .line 1218
    .line 1219
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1220
    .line 1221
    .line 1222
    const-class v1, Ls50/m;

    .line 1223
    .line 1224
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1225
    .line 1226
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v1

    .line 1230
    const/4 v2, 0x0

    .line 1231
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v0

    .line 1235
    check-cast v0, Ls50/m;

    .line 1236
    .line 1237
    new-instance v1, Ls50/q;

    .line 1238
    .line 1239
    invoke-direct {v1, v0}, Ls50/q;-><init>(Ls50/m;)V

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
    const-string v2, "$this$single"

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
    const-class v1, Lam0/c;

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
    check-cast v0, Lam0/c;

    .line 1275
    .line 1276
    new-instance v1, Lam0/f;

    .line 1277
    .line 1278
    invoke-direct {v1, v0}, Lam0/f;-><init>(Lam0/c;)V

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
    const-string v2, "$this$single"

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
    const-class v1, Ls50/m;

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
    check-cast v0, Ls50/m;

    .line 1314
    .line 1315
    new-instance v1, Ls50/o;

    .line 1316
    .line 1317
    invoke-direct {v1, v0}, Ls50/o;-><init>(Ls50/m;)V

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
    const-string v2, "$this$single"

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
    const-class v1, Lp50/d;

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
    check-cast v0, Lp50/d;

    .line 1353
    .line 1354
    new-instance v1, Ls50/e;

    .line 1355
    .line 1356
    invoke-direct {v1, v0}, Ls50/e;-><init>(Lp50/d;)V

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
    const-class v1, Ls50/l;

    .line 1379
    .line 1380
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1381
    .line 1382
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1383
    .line 1384
    .line 1385
    move-result-object v1

    .line 1386
    const/4 v2, 0x0

    .line 1387
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1388
    .line 1389
    .line 1390
    move-result-object v0

    .line 1391
    check-cast v0, Ls50/l;

    .line 1392
    .line 1393
    new-instance v1, Ls50/c0;

    .line 1394
    .line 1395
    invoke-direct {v1, v0}, Ls50/c0;-><init>(Ls50/l;)V

    .line 1396
    .line 1397
    .line 1398
    return-object v1

    .line 1399
    :pswitch_19
    move-object/from16 v0, p1

    .line 1400
    .line 1401
    check-cast v0, Lk21/a;

    .line 1402
    .line 1403
    move-object/from16 v1, p2

    .line 1404
    .line 1405
    check-cast v1, Lg21/a;

    .line 1406
    .line 1407
    const-string v2, "$this$factory"

    .line 1408
    .line 1409
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1410
    .line 1411
    .line 1412
    const-string v2, "it"

    .line 1413
    .line 1414
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1415
    .line 1416
    .line 1417
    const-class v1, Ls50/l;

    .line 1418
    .line 1419
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1420
    .line 1421
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1422
    .line 1423
    .line 1424
    move-result-object v1

    .line 1425
    const/4 v2, 0x0

    .line 1426
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v0

    .line 1430
    check-cast v0, Ls50/l;

    .line 1431
    .line 1432
    new-instance v1, Ls50/d0;

    .line 1433
    .line 1434
    invoke-direct {v1, v0}, Ls50/d0;-><init>(Ls50/l;)V

    .line 1435
    .line 1436
    .line 1437
    return-object v1

    .line 1438
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1439
    .line 1440
    check-cast v0, Lk21/a;

    .line 1441
    .line 1442
    move-object/from16 v1, p2

    .line 1443
    .line 1444
    check-cast v1, Lg21/a;

    .line 1445
    .line 1446
    const-string v2, "$this$factory"

    .line 1447
    .line 1448
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1449
    .line 1450
    .line 1451
    const-string v2, "it"

    .line 1452
    .line 1453
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1454
    .line 1455
    .line 1456
    const-class v1, Ls50/l;

    .line 1457
    .line 1458
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1459
    .line 1460
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1461
    .line 1462
    .line 1463
    move-result-object v1

    .line 1464
    const/4 v2, 0x0

    .line 1465
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1466
    .line 1467
    .line 1468
    move-result-object v0

    .line 1469
    check-cast v0, Ls50/l;

    .line 1470
    .line 1471
    new-instance v1, Ls50/x;

    .line 1472
    .line 1473
    invoke-direct {v1, v0}, Ls50/x;-><init>(Ls50/l;)V

    .line 1474
    .line 1475
    .line 1476
    return-object v1

    .line 1477
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1478
    .line 1479
    check-cast v0, Lk21/a;

    .line 1480
    .line 1481
    move-object/from16 v1, p2

    .line 1482
    .line 1483
    check-cast v1, Lg21/a;

    .line 1484
    .line 1485
    const-string v2, "$this$factory"

    .line 1486
    .line 1487
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1488
    .line 1489
    .line 1490
    const-string v2, "it"

    .line 1491
    .line 1492
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1493
    .line 1494
    .line 1495
    const-class v1, Ls50/l;

    .line 1496
    .line 1497
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1498
    .line 1499
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v1

    .line 1503
    const/4 v2, 0x0

    .line 1504
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1505
    .line 1506
    .line 1507
    move-result-object v0

    .line 1508
    check-cast v0, Ls50/l;

    .line 1509
    .line 1510
    new-instance v1, Ls50/s;

    .line 1511
    .line 1512
    invoke-direct {v1, v0}, Ls50/s;-><init>(Ls50/l;)V

    .line 1513
    .line 1514
    .line 1515
    return-object v1

    .line 1516
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1517
    .line 1518
    check-cast v0, Lk21/a;

    .line 1519
    .line 1520
    move-object/from16 v1, p2

    .line 1521
    .line 1522
    check-cast v1, Lg21/a;

    .line 1523
    .line 1524
    const-string v2, "$this$factory"

    .line 1525
    .line 1526
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1527
    .line 1528
    .line 1529
    const-string v2, "it"

    .line 1530
    .line 1531
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1532
    .line 1533
    .line 1534
    const-class v1, Ls50/l;

    .line 1535
    .line 1536
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1537
    .line 1538
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1539
    .line 1540
    .line 1541
    move-result-object v1

    .line 1542
    const/4 v2, 0x0

    .line 1543
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1544
    .line 1545
    .line 1546
    move-result-object v0

    .line 1547
    check-cast v0, Ls50/l;

    .line 1548
    .line 1549
    new-instance v1, Ls50/t;

    .line 1550
    .line 1551
    invoke-direct {v1, v0}, Ls50/t;-><init>(Ls50/l;)V

    .line 1552
    .line 1553
    .line 1554
    return-object v1

    .line 1555
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
