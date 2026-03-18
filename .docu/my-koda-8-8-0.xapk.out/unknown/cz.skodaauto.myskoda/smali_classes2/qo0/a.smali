.class public final Lqo0/a;
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
    iput p1, p0, Lqo0/a;->d:I

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
    iget v0, v0, Lqo0/a;->d:I

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
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 27
    .line 28
    const-class v2, Lbn0/g;

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    const-class v4, Lrt0/j;

    .line 40
    .line 41
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    const-class v5, Ljr0/c;

    .line 50
    .line 51
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Ljr0/c;

    .line 60
    .line 61
    check-cast v4, Lrt0/j;

    .line 62
    .line 63
    check-cast v2, Lbn0/g;

    .line 64
    .line 65
    new-instance v1, Lrt0/o;

    .line 66
    .line 67
    invoke-direct {v1, v2, v4, v0}, Lrt0/o;-><init>(Lbn0/g;Lrt0/j;Ljr0/c;)V

    .line 68
    .line 69
    .line 70
    return-object v1

    .line 71
    :pswitch_0
    move-object/from16 v0, p1

    .line 72
    .line 73
    check-cast v0, Lk21/a;

    .line 74
    .line 75
    move-object/from16 v1, p2

    .line 76
    .line 77
    check-cast v1, Lg21/a;

    .line 78
    .line 79
    const-string v2, "$this$factory"

    .line 80
    .line 81
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const-string v2, "it"

    .line 85
    .line 86
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-class v1, Lrt0/k;

    .line 90
    .line 91
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 92
    .line 93
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    const/4 v2, 0x0

    .line 98
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    check-cast v0, Lrt0/k;

    .line 103
    .line 104
    new-instance v1, Lrt0/t;

    .line 105
    .line 106
    invoke-direct {v1, v0}, Lrt0/t;-><init>(Lrt0/k;)V

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
    const-string v2, "$this$single"

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
    const-class v1, Lve0/u;

    .line 129
    .line 130
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 131
    .line 132
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    const/4 v2, 0x0

    .line 137
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    check-cast v0, Lve0/u;

    .line 142
    .line 143
    new-instance v1, Lps0/f;

    .line 144
    .line 145
    invoke-direct {v1, v0}, Lps0/f;-><init>(Lve0/u;)V

    .line 146
    .line 147
    .line 148
    return-object v1

    .line 149
    :pswitch_2
    move-object/from16 v0, p1

    .line 150
    .line 151
    check-cast v0, Lk21/a;

    .line 152
    .line 153
    move-object/from16 v1, p2

    .line 154
    .line 155
    check-cast v1, Lg21/a;

    .line 156
    .line 157
    const-string v2, "$this$factory"

    .line 158
    .line 159
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    const-string v2, "it"

    .line 163
    .line 164
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    const-class v1, Lrs0/c;

    .line 168
    .line 169
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 170
    .line 171
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    const/4 v2, 0x0

    .line 176
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    check-cast v0, Lrs0/c;

    .line 181
    .line 182
    new-instance v0, Lrs0/e;

    .line 183
    .line 184
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 185
    .line 186
    .line 187
    return-object v0

    .line 188
    :pswitch_3
    move-object/from16 v0, p1

    .line 189
    .line 190
    check-cast v0, Lk21/a;

    .line 191
    .line 192
    move-object/from16 v1, p2

    .line 193
    .line 194
    check-cast v1, Lg21/a;

    .line 195
    .line 196
    const-string v2, "$this$factory"

    .line 197
    .line 198
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    const-string v0, "it"

    .line 202
    .line 203
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    new-instance v0, Lrs0/c;

    .line 207
    .line 208
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 209
    .line 210
    .line 211
    return-object v0

    .line 212
    :pswitch_4
    move-object/from16 v0, p1

    .line 213
    .line 214
    check-cast v0, Lk21/a;

    .line 215
    .line 216
    move-object/from16 v1, p2

    .line 217
    .line 218
    check-cast v1, Lg21/a;

    .line 219
    .line 220
    const-string v2, "$this$factory"

    .line 221
    .line 222
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    const-string v2, "it"

    .line 226
    .line 227
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    const-class v1, Lrs0/f;

    .line 231
    .line 232
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 233
    .line 234
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    const/4 v2, 0x0

    .line 239
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    check-cast v0, Lrs0/f;

    .line 244
    .line 245
    new-instance v1, Lrs0/b;

    .line 246
    .line 247
    invoke-direct {v1, v0}, Lrs0/b;-><init>(Lrs0/f;)V

    .line 248
    .line 249
    .line 250
    return-object v1

    .line 251
    :pswitch_5
    move-object/from16 v0, p1

    .line 252
    .line 253
    check-cast v0, Lk21/a;

    .line 254
    .line 255
    move-object/from16 v1, p2

    .line 256
    .line 257
    check-cast v1, Lg21/a;

    .line 258
    .line 259
    const-string v2, "$this$factory"

    .line 260
    .line 261
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    const-string v2, "it"

    .line 265
    .line 266
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    const-class v1, Lrs0/f;

    .line 270
    .line 271
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 272
    .line 273
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    const/4 v2, 0x0

    .line 278
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    check-cast v0, Lrs0/f;

    .line 283
    .line 284
    new-instance v1, Lrs0/g;

    .line 285
    .line 286
    invoke-direct {v1, v0}, Lrs0/g;-><init>(Lrs0/f;)V

    .line 287
    .line 288
    .line 289
    return-object v1

    .line 290
    :pswitch_6
    move-object/from16 v0, p1

    .line 291
    .line 292
    check-cast v0, Lk21/a;

    .line 293
    .line 294
    move-object/from16 v1, p2

    .line 295
    .line 296
    check-cast v1, Lg21/a;

    .line 297
    .line 298
    const-string v2, "$this$single"

    .line 299
    .line 300
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    const-string v0, "it"

    .line 304
    .line 305
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    new-instance v0, Lpq0/b;

    .line 309
    .line 310
    invoke-direct {v0}, Lpq0/b;-><init>()V

    .line 311
    .line 312
    .line 313
    return-object v0

    .line 314
    :pswitch_7
    move-object/from16 v0, p1

    .line 315
    .line 316
    check-cast v0, Lk21/a;

    .line 317
    .line 318
    move-object/from16 v1, p2

    .line 319
    .line 320
    check-cast v1, Lg21/a;

    .line 321
    .line 322
    const-string v2, "$this$factory"

    .line 323
    .line 324
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    const-string v2, "it"

    .line 328
    .line 329
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 333
    .line 334
    const-class v2, Lrq0/f;

    .line 335
    .line 336
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 337
    .line 338
    .line 339
    move-result-object v2

    .line 340
    const/4 v3, 0x0

    .line 341
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v2

    .line 345
    const-class v4, Ljn0/c;

    .line 346
    .line 347
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 348
    .line 349
    .line 350
    move-result-object v1

    .line 351
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    check-cast v0, Ljn0/c;

    .line 356
    .line 357
    check-cast v2, Lrq0/f;

    .line 358
    .line 359
    new-instance v1, Lrq0/d;

    .line 360
    .line 361
    invoke-direct {v1, v2, v0}, Lrq0/d;-><init>(Lrq0/f;Ljn0/c;)V

    .line 362
    .line 363
    .line 364
    return-object v1

    .line 365
    :pswitch_8
    move-object/from16 v0, p1

    .line 366
    .line 367
    check-cast v0, Lk21/a;

    .line 368
    .line 369
    move-object/from16 v1, p2

    .line 370
    .line 371
    check-cast v1, Lg21/a;

    .line 372
    .line 373
    const-string v2, "$this$factory"

    .line 374
    .line 375
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    const-string v2, "it"

    .line 379
    .line 380
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    const-class v1, Lpq0/b;

    .line 384
    .line 385
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 386
    .line 387
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 388
    .line 389
    .line 390
    move-result-object v1

    .line 391
    const/4 v2, 0x0

    .line 392
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    check-cast v0, Lpq0/b;

    .line 397
    .line 398
    new-instance v1, Lrq0/a;

    .line 399
    .line 400
    invoke-direct {v1, v0}, Lrq0/a;-><init>(Lpq0/b;)V

    .line 401
    .line 402
    .line 403
    return-object v1

    .line 404
    :pswitch_9
    move-object/from16 v0, p1

    .line 405
    .line 406
    check-cast v0, Lk21/a;

    .line 407
    .line 408
    move-object/from16 v1, p2

    .line 409
    .line 410
    check-cast v1, Lg21/a;

    .line 411
    .line 412
    const-string v2, "$this$factory"

    .line 413
    .line 414
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    const-string v2, "it"

    .line 418
    .line 419
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    const-class v1, Lpq0/b;

    .line 423
    .line 424
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 425
    .line 426
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 427
    .line 428
    .line 429
    move-result-object v1

    .line 430
    const/4 v2, 0x0

    .line 431
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    check-cast v0, Lpq0/b;

    .line 436
    .line 437
    new-instance v1, Lrq0/f;

    .line 438
    .line 439
    invoke-direct {v1, v0}, Lrq0/f;-><init>(Lpq0/b;)V

    .line 440
    .line 441
    .line 442
    return-object v1

    .line 443
    :pswitch_a
    move-object/from16 v0, p1

    .line 444
    .line 445
    check-cast v0, Lk21/a;

    .line 446
    .line 447
    move-object/from16 v1, p2

    .line 448
    .line 449
    check-cast v1, Lg21/a;

    .line 450
    .line 451
    const-string v2, "$this$viewModel"

    .line 452
    .line 453
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 454
    .line 455
    .line 456
    const-string v2, "it"

    .line 457
    .line 458
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 462
    .line 463
    const-class v2, Lro0/m;

    .line 464
    .line 465
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 466
    .line 467
    .line 468
    move-result-object v2

    .line 469
    const/4 v3, 0x0

    .line 470
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v2

    .line 474
    const-class v4, Lgb0/f;

    .line 475
    .line 476
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 477
    .line 478
    .line 479
    move-result-object v4

    .line 480
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v4

    .line 484
    const-class v5, Lkf0/o;

    .line 485
    .line 486
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 487
    .line 488
    .line 489
    move-result-object v5

    .line 490
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v5

    .line 494
    const-class v6, Lro0/p;

    .line 495
    .line 496
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 497
    .line 498
    .line 499
    move-result-object v6

    .line 500
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v6

    .line 504
    const-class v7, Lro0/f;

    .line 505
    .line 506
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 507
    .line 508
    .line 509
    move-result-object v7

    .line 510
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 511
    .line 512
    .line 513
    move-result-object v7

    .line 514
    const-class v8, Ltr0/b;

    .line 515
    .line 516
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 517
    .line 518
    .line 519
    move-result-object v8

    .line 520
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 521
    .line 522
    .line 523
    move-result-object v8

    .line 524
    const-class v9, Lij0/a;

    .line 525
    .line 526
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 527
    .line 528
    .line 529
    move-result-object v1

    .line 530
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v0

    .line 534
    move-object/from16 v16, v0

    .line 535
    .line 536
    check-cast v16, Lij0/a;

    .line 537
    .line 538
    move-object v15, v8

    .line 539
    check-cast v15, Ltr0/b;

    .line 540
    .line 541
    move-object v14, v7

    .line 542
    check-cast v14, Lro0/f;

    .line 543
    .line 544
    move-object v13, v6

    .line 545
    check-cast v13, Lro0/p;

    .line 546
    .line 547
    move-object v12, v5

    .line 548
    check-cast v12, Lkf0/o;

    .line 549
    .line 550
    move-object v11, v4

    .line 551
    check-cast v11, Lgb0/f;

    .line 552
    .line 553
    move-object v10, v2

    .line 554
    check-cast v10, Lro0/m;

    .line 555
    .line 556
    new-instance v9, Luo0/q;

    .line 557
    .line 558
    invoke-direct/range {v9 .. v16}, Luo0/q;-><init>(Lro0/m;Lgb0/f;Lkf0/o;Lro0/p;Lro0/f;Ltr0/b;Lij0/a;)V

    .line 559
    .line 560
    .line 561
    return-object v9

    .line 562
    :pswitch_b
    move-object/from16 v0, p1

    .line 563
    .line 564
    check-cast v0, Lk21/a;

    .line 565
    .line 566
    move-object/from16 v1, p2

    .line 567
    .line 568
    check-cast v1, Lg21/a;

    .line 569
    .line 570
    const-string v2, "$this$viewModel"

    .line 571
    .line 572
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    const-string v2, "it"

    .line 576
    .line 577
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    const-class v1, Lro0/o;

    .line 581
    .line 582
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 583
    .line 584
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 585
    .line 586
    .line 587
    move-result-object v1

    .line 588
    const/4 v2, 0x0

    .line 589
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    check-cast v0, Lro0/o;

    .line 594
    .line 595
    new-instance v1, Luo0/b;

    .line 596
    .line 597
    invoke-direct {v1, v0}, Luo0/b;-><init>(Lro0/o;)V

    .line 598
    .line 599
    .line 600
    return-object v1

    .line 601
    :pswitch_c
    move-object/from16 v0, p1

    .line 602
    .line 603
    check-cast v0, Lk21/a;

    .line 604
    .line 605
    move-object/from16 v1, p2

    .line 606
    .line 607
    check-cast v1, Lg21/a;

    .line 608
    .line 609
    const-string v2, "$this$single"

    .line 610
    .line 611
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    const-string v0, "it"

    .line 615
    .line 616
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    new-instance v0, Lpo0/i;

    .line 620
    .line 621
    invoke-direct {v0}, Lpo0/i;-><init>()V

    .line 622
    .line 623
    .line 624
    return-object v0

    .line 625
    :pswitch_d
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
    const-string v0, "it"

    .line 639
    .line 640
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    new-instance v0, Lpo0/j;

    .line 644
    .line 645
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 646
    .line 647
    .line 648
    return-object v0

    .line 649
    :pswitch_e
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
    const-string v2, "$this$single"

    .line 658
    .line 659
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 660
    .line 661
    .line 662
    const-string v0, "it"

    .line 663
    .line 664
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 665
    .line 666
    .line 667
    new-instance v0, Lpo0/e;

    .line 668
    .line 669
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 670
    .line 671
    .line 672
    return-object v0

    .line 673
    :pswitch_f
    move-object/from16 v0, p1

    .line 674
    .line 675
    check-cast v0, Lk21/a;

    .line 676
    .line 677
    move-object/from16 v1, p2

    .line 678
    .line 679
    check-cast v1, Lg21/a;

    .line 680
    .line 681
    const-string v2, "$this$factory"

    .line 682
    .line 683
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 684
    .line 685
    .line 686
    const-string v2, "it"

    .line 687
    .line 688
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 689
    .line 690
    .line 691
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 692
    .line 693
    const-class v2, Lro0/t;

    .line 694
    .line 695
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 696
    .line 697
    .line 698
    move-result-object v2

    .line 699
    const/4 v3, 0x0

    .line 700
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    move-result-object v2

    .line 704
    const-class v4, Lro0/x;

    .line 705
    .line 706
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 707
    .line 708
    .line 709
    move-result-object v1

    .line 710
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 711
    .line 712
    .line 713
    move-result-object v0

    .line 714
    check-cast v0, Lro0/x;

    .line 715
    .line 716
    check-cast v2, Lro0/t;

    .line 717
    .line 718
    new-instance v1, Lro0/o;

    .line 719
    .line 720
    invoke-direct {v1, v2, v0}, Lro0/o;-><init>(Lro0/t;Lro0/x;)V

    .line 721
    .line 722
    .line 723
    return-object v1

    .line 724
    :pswitch_10
    move-object/from16 v0, p1

    .line 725
    .line 726
    check-cast v0, Lk21/a;

    .line 727
    .line 728
    move-object/from16 v1, p2

    .line 729
    .line 730
    check-cast v1, Lg21/a;

    .line 731
    .line 732
    const-string v2, "$this$factory"

    .line 733
    .line 734
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 735
    .line 736
    .line 737
    const-string v2, "it"

    .line 738
    .line 739
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    const-class v1, Lro0/w;

    .line 743
    .line 744
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 745
    .line 746
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 747
    .line 748
    .line 749
    move-result-object v1

    .line 750
    const/4 v2, 0x0

    .line 751
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 752
    .line 753
    .line 754
    move-result-object v0

    .line 755
    check-cast v0, Lro0/w;

    .line 756
    .line 757
    new-instance v1, Lro0/m;

    .line 758
    .line 759
    invoke-direct {v1, v0}, Lro0/m;-><init>(Lro0/w;)V

    .line 760
    .line 761
    .line 762
    return-object v1

    .line 763
    :pswitch_11
    move-object/from16 v0, p1

    .line 764
    .line 765
    check-cast v0, Lk21/a;

    .line 766
    .line 767
    move-object/from16 v1, p2

    .line 768
    .line 769
    check-cast v1, Lg21/a;

    .line 770
    .line 771
    const-string v2, "$this$factory"

    .line 772
    .line 773
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 774
    .line 775
    .line 776
    const-string v2, "it"

    .line 777
    .line 778
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 779
    .line 780
    .line 781
    const-class v1, Lro0/w;

    .line 782
    .line 783
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 784
    .line 785
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 786
    .line 787
    .line 788
    move-result-object v1

    .line 789
    const/4 v2, 0x0

    .line 790
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 791
    .line 792
    .line 793
    move-result-object v0

    .line 794
    check-cast v0, Lro0/w;

    .line 795
    .line 796
    new-instance v1, Lro0/x;

    .line 797
    .line 798
    invoke-direct {v1, v0}, Lro0/x;-><init>(Lro0/w;)V

    .line 799
    .line 800
    .line 801
    return-object v1

    .line 802
    :pswitch_12
    move-object/from16 v0, p1

    .line 803
    .line 804
    check-cast v0, Lk21/a;

    .line 805
    .line 806
    move-object/from16 v1, p2

    .line 807
    .line 808
    check-cast v1, Lg21/a;

    .line 809
    .line 810
    const-string v2, "$this$factory"

    .line 811
    .line 812
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 813
    .line 814
    .line 815
    const-string v2, "it"

    .line 816
    .line 817
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 818
    .line 819
    .line 820
    const-class v1, Lam0/c;

    .line 821
    .line 822
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 823
    .line 824
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 825
    .line 826
    .line 827
    move-result-object v1

    .line 828
    const/4 v2, 0x0

    .line 829
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    move-result-object v0

    .line 833
    check-cast v0, Lam0/c;

    .line 834
    .line 835
    new-instance v1, Lro0/c;

    .line 836
    .line 837
    invoke-direct {v1, v0}, Lro0/c;-><init>(Lam0/c;)V

    .line 838
    .line 839
    .line 840
    return-object v1

    .line 841
    :pswitch_13
    move-object/from16 v0, p1

    .line 842
    .line 843
    check-cast v0, Lk21/a;

    .line 844
    .line 845
    move-object/from16 v1, p2

    .line 846
    .line 847
    check-cast v1, Lg21/a;

    .line 848
    .line 849
    const-string v2, "$this$factory"

    .line 850
    .line 851
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 852
    .line 853
    .line 854
    const-string v2, "it"

    .line 855
    .line 856
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 857
    .line 858
    .line 859
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 860
    .line 861
    const-class v2, Lro0/u;

    .line 862
    .line 863
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 864
    .line 865
    .line 866
    move-result-object v2

    .line 867
    const/4 v3, 0x0

    .line 868
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    move-result-object v2

    .line 872
    const-class v4, Lro0/c;

    .line 873
    .line 874
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 875
    .line 876
    .line 877
    move-result-object v4

    .line 878
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 879
    .line 880
    .line 881
    move-result-object v4

    .line 882
    const-class v5, Lvo0/a;

    .line 883
    .line 884
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 885
    .line 886
    .line 887
    move-result-object v5

    .line 888
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v5

    .line 892
    const-class v6, Lkc0/z;

    .line 893
    .line 894
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 895
    .line 896
    .line 897
    move-result-object v6

    .line 898
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 899
    .line 900
    .line 901
    move-result-object v6

    .line 902
    const-class v7, Lfj0/g;

    .line 903
    .line 904
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 905
    .line 906
    .line 907
    move-result-object v1

    .line 908
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 909
    .line 910
    .line 911
    move-result-object v0

    .line 912
    move-object v12, v0

    .line 913
    check-cast v12, Lfj0/g;

    .line 914
    .line 915
    move-object v11, v6

    .line 916
    check-cast v11, Lkc0/z;

    .line 917
    .line 918
    move-object v10, v5

    .line 919
    check-cast v10, Lvo0/a;

    .line 920
    .line 921
    move-object v9, v4

    .line 922
    check-cast v9, Lro0/c;

    .line 923
    .line 924
    move-object v8, v2

    .line 925
    check-cast v8, Lro0/u;

    .line 926
    .line 927
    new-instance v7, Lvo0/f;

    .line 928
    .line 929
    invoke-direct/range {v7 .. v12}, Lvo0/f;-><init>(Lro0/u;Lro0/c;Lvo0/a;Lkc0/z;Lfj0/g;)V

    .line 930
    .line 931
    .line 932
    return-object v7

    .line 933
    :pswitch_14
    move-object/from16 v0, p1

    .line 934
    .line 935
    check-cast v0, Lk21/a;

    .line 936
    .line 937
    move-object/from16 v1, p2

    .line 938
    .line 939
    check-cast v1, Lg21/a;

    .line 940
    .line 941
    const-string v2, "$this$factory"

    .line 942
    .line 943
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 944
    .line 945
    .line 946
    const-string v2, "it"

    .line 947
    .line 948
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 949
    .line 950
    .line 951
    const-class v1, Lro0/u;

    .line 952
    .line 953
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 954
    .line 955
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 956
    .line 957
    .line 958
    move-result-object v1

    .line 959
    const/4 v2, 0x0

    .line 960
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 961
    .line 962
    .line 963
    move-result-object v0

    .line 964
    check-cast v0, Lro0/u;

    .line 965
    .line 966
    new-instance v1, Lpo0/d;

    .line 967
    .line 968
    invoke-direct {v1, v0}, Lpo0/d;-><init>(Lro0/u;)V

    .line 969
    .line 970
    .line 971
    return-object v1

    .line 972
    :pswitch_15
    move-object/from16 v0, p1

    .line 973
    .line 974
    check-cast v0, Lk21/a;

    .line 975
    .line 976
    move-object/from16 v1, p2

    .line 977
    .line 978
    check-cast v1, Lg21/a;

    .line 979
    .line 980
    const-string v2, "$this$factory"

    .line 981
    .line 982
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 983
    .line 984
    .line 985
    const-string v2, "it"

    .line 986
    .line 987
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 988
    .line 989
    .line 990
    const-class v1, Lro0/u;

    .line 991
    .line 992
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 993
    .line 994
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 995
    .line 996
    .line 997
    move-result-object v1

    .line 998
    const/4 v2, 0x0

    .line 999
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v0

    .line 1003
    check-cast v0, Lro0/u;

    .line 1004
    .line 1005
    new-instance v1, Lpo0/c;

    .line 1006
    .line 1007
    invoke-direct {v1, v0}, Lpo0/c;-><init>(Lro0/u;)V

    .line 1008
    .line 1009
    .line 1010
    return-object v1

    .line 1011
    :pswitch_16
    move-object/from16 v0, p1

    .line 1012
    .line 1013
    check-cast v0, Lk21/a;

    .line 1014
    .line 1015
    move-object/from16 v1, p2

    .line 1016
    .line 1017
    check-cast v1, Lg21/a;

    .line 1018
    .line 1019
    const-string v2, "$this$factory"

    .line 1020
    .line 1021
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1022
    .line 1023
    .line 1024
    const-string v2, "it"

    .line 1025
    .line 1026
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1027
    .line 1028
    .line 1029
    const-class v1, Lro0/u;

    .line 1030
    .line 1031
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1032
    .line 1033
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v1

    .line 1037
    const/4 v2, 0x0

    .line 1038
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v0

    .line 1042
    check-cast v0, Lro0/u;

    .line 1043
    .line 1044
    new-instance v1, Lpo0/b;

    .line 1045
    .line 1046
    invoke-direct {v1, v0}, Lpo0/b;-><init>(Lro0/u;)V

    .line 1047
    .line 1048
    .line 1049
    return-object v1

    .line 1050
    :pswitch_17
    move-object/from16 v0, p1

    .line 1051
    .line 1052
    check-cast v0, Lk21/a;

    .line 1053
    .line 1054
    move-object/from16 v1, p2

    .line 1055
    .line 1056
    check-cast v1, Lg21/a;

    .line 1057
    .line 1058
    const-string v2, "$this$factory"

    .line 1059
    .line 1060
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1061
    .line 1062
    .line 1063
    const-string v2, "it"

    .line 1064
    .line 1065
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1066
    .line 1067
    .line 1068
    const-class v1, Lro0/u;

    .line 1069
    .line 1070
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1071
    .line 1072
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v1

    .line 1076
    const/4 v2, 0x0

    .line 1077
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1078
    .line 1079
    .line 1080
    move-result-object v0

    .line 1081
    check-cast v0, Lro0/u;

    .line 1082
    .line 1083
    new-instance v1, Lpo0/h;

    .line 1084
    .line 1085
    invoke-direct {v1, v0}, Lpo0/h;-><init>(Lro0/u;)V

    .line 1086
    .line 1087
    .line 1088
    return-object v1

    .line 1089
    :pswitch_18
    move-object/from16 v0, p1

    .line 1090
    .line 1091
    check-cast v0, Lk21/a;

    .line 1092
    .line 1093
    move-object/from16 v1, p2

    .line 1094
    .line 1095
    check-cast v1, Lg21/a;

    .line 1096
    .line 1097
    const-string v2, "$this$factory"

    .line 1098
    .line 1099
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1100
    .line 1101
    .line 1102
    const-string v2, "it"

    .line 1103
    .line 1104
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1105
    .line 1106
    .line 1107
    const-class v1, Lic0/c;

    .line 1108
    .line 1109
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1110
    .line 1111
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v1

    .line 1115
    const/4 v2, 0x0

    .line 1116
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v0

    .line 1120
    check-cast v0, Lic0/c;

    .line 1121
    .line 1122
    new-instance v1, Lvo0/a;

    .line 1123
    .line 1124
    invoke-direct {v1, v0}, Lvo0/a;-><init>(Lic0/c;)V

    .line 1125
    .line 1126
    .line 1127
    return-object v1

    .line 1128
    :pswitch_19
    move-object/from16 v0, p1

    .line 1129
    .line 1130
    check-cast v0, Lk21/a;

    .line 1131
    .line 1132
    move-object/from16 v1, p2

    .line 1133
    .line 1134
    check-cast v1, Lg21/a;

    .line 1135
    .line 1136
    const-string v2, "$this$factory"

    .line 1137
    .line 1138
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1139
    .line 1140
    .line 1141
    const-string v2, "it"

    .line 1142
    .line 1143
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1144
    .line 1145
    .line 1146
    const-class v1, Lro0/v;

    .line 1147
    .line 1148
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1149
    .line 1150
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v1

    .line 1154
    const/4 v2, 0x0

    .line 1155
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v0

    .line 1159
    check-cast v0, Lro0/v;

    .line 1160
    .line 1161
    new-instance v1, Lro0/e;

    .line 1162
    .line 1163
    invoke-direct {v1, v0}, Lro0/e;-><init>(Lro0/v;)V

    .line 1164
    .line 1165
    .line 1166
    return-object v1

    .line 1167
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1168
    .line 1169
    check-cast v0, Lk21/a;

    .line 1170
    .line 1171
    move-object/from16 v1, p2

    .line 1172
    .line 1173
    check-cast v1, Lg21/a;

    .line 1174
    .line 1175
    const-string v2, "$this$factory"

    .line 1176
    .line 1177
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1178
    .line 1179
    .line 1180
    const-string v2, "it"

    .line 1181
    .line 1182
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1183
    .line 1184
    .line 1185
    const-class v1, Lro0/q;

    .line 1186
    .line 1187
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1188
    .line 1189
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v1

    .line 1193
    const/4 v2, 0x0

    .line 1194
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1195
    .line 1196
    .line 1197
    move-result-object v0

    .line 1198
    check-cast v0, Lro0/q;

    .line 1199
    .line 1200
    new-instance v1, Lro0/a;

    .line 1201
    .line 1202
    invoke-direct {v1, v0}, Lro0/a;-><init>(Lro0/q;)V

    .line 1203
    .line 1204
    .line 1205
    return-object v1

    .line 1206
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1207
    .line 1208
    check-cast v0, Lk21/a;

    .line 1209
    .line 1210
    move-object/from16 v1, p2

    .line 1211
    .line 1212
    check-cast v1, Lg21/a;

    .line 1213
    .line 1214
    const-string v2, "$this$factory"

    .line 1215
    .line 1216
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1217
    .line 1218
    .line 1219
    const-string v2, "it"

    .line 1220
    .line 1221
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1222
    .line 1223
    .line 1224
    const-class v1, Lro0/g;

    .line 1225
    .line 1226
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1227
    .line 1228
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1229
    .line 1230
    .line 1231
    move-result-object v1

    .line 1232
    const/4 v2, 0x0

    .line 1233
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v0

    .line 1237
    check-cast v0, Lro0/g;

    .line 1238
    .line 1239
    new-instance v1, Lro0/y;

    .line 1240
    .line 1241
    invoke-direct {v1, v0}, Lro0/y;-><init>(Lro0/g;)V

    .line 1242
    .line 1243
    .line 1244
    return-object v1

    .line 1245
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1246
    .line 1247
    check-cast v0, Lk21/a;

    .line 1248
    .line 1249
    move-object/from16 v1, p2

    .line 1250
    .line 1251
    check-cast v1, Lg21/a;

    .line 1252
    .line 1253
    const-string v2, "$this$factory"

    .line 1254
    .line 1255
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1256
    .line 1257
    .line 1258
    const-string v2, "it"

    .line 1259
    .line 1260
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1261
    .line 1262
    .line 1263
    const-class v1, Lro0/g;

    .line 1264
    .line 1265
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1266
    .line 1267
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v1

    .line 1271
    const/4 v2, 0x0

    .line 1272
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1273
    .line 1274
    .line 1275
    move-result-object v0

    .line 1276
    check-cast v0, Lro0/g;

    .line 1277
    .line 1278
    new-instance v1, Lro0/f;

    .line 1279
    .line 1280
    invoke-direct {v1, v0}, Lro0/f;-><init>(Lro0/g;)V

    .line 1281
    .line 1282
    .line 1283
    return-object v1

    .line 1284
    nop

    .line 1285
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
