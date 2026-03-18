.class public final synthetic Lvj0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Leo0/b;


# direct methods
.method public synthetic constructor <init>(Leo0/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvj0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvj0/a;->e:Leo0/b;

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
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvj0/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk21/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Lg21/a;

    .line 15
    .line 16
    const-string v3, "$this$scopedFactory"

    .line 17
    .line 18
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v3, "it"

    .line 22
    .line 23
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lwj0/i0;

    .line 27
    .line 28
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 29
    .line 30
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-class v3, Lwj0/a;

    .line 37
    .line 38
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 39
    .line 40
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    const/4 v4, 0x0

    .line 45
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Lwj0/a;

    .line 50
    .line 51
    invoke-direct {v2, v0}, Lwj0/i0;-><init>(Lwj0/a;)V

    .line 52
    .line 53
    .line 54
    return-object v2

    .line 55
    :pswitch_0
    move-object/from16 v1, p1

    .line 56
    .line 57
    check-cast v1, Lk21/a;

    .line 58
    .line 59
    move-object/from16 v2, p2

    .line 60
    .line 61
    check-cast v2, Lg21/a;

    .line 62
    .line 63
    const-string v3, "$this$scopedFactory"

    .line 64
    .line 65
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v3, "it"

    .line 69
    .line 70
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    new-instance v2, Lwj0/c0;

    .line 74
    .line 75
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 76
    .line 77
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    const-class v3, Luj0/i;

    .line 84
    .line 85
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 86
    .line 87
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    const/4 v4, 0x0

    .line 92
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    check-cast v0, Luj0/i;

    .line 97
    .line 98
    invoke-direct {v2, v0}, Lwj0/c0;-><init>(Luj0/i;)V

    .line 99
    .line 100
    .line 101
    return-object v2

    .line 102
    :pswitch_1
    move-object/from16 v1, p1

    .line 103
    .line 104
    check-cast v1, Lk21/a;

    .line 105
    .line 106
    move-object/from16 v2, p2

    .line 107
    .line 108
    check-cast v2, Lg21/a;

    .line 109
    .line 110
    const-string v3, "$this$scopedFactory"

    .line 111
    .line 112
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string v3, "it"

    .line 116
    .line 117
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    new-instance v2, Lwj0/b0;

    .line 121
    .line 122
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 123
    .line 124
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 125
    .line 126
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    const-class v3, Luj0/h;

    .line 131
    .line 132
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 133
    .line 134
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    const/4 v4, 0x0

    .line 139
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    check-cast v0, Luj0/h;

    .line 144
    .line 145
    invoke-direct {v2, v0}, Lwj0/b0;-><init>(Luj0/h;)V

    .line 146
    .line 147
    .line 148
    return-object v2

    .line 149
    :pswitch_2
    move-object/from16 v1, p1

    .line 150
    .line 151
    check-cast v1, Lk21/a;

    .line 152
    .line 153
    move-object/from16 v2, p2

    .line 154
    .line 155
    check-cast v2, Lg21/a;

    .line 156
    .line 157
    const-string v3, "$this$scopedFactory"

    .line 158
    .line 159
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    const-string v3, "it"

    .line 163
    .line 164
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    new-instance v2, Lwj0/a0;

    .line 168
    .line 169
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 170
    .line 171
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 172
    .line 173
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    const-class v3, Luj0/g;

    .line 178
    .line 179
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 180
    .line 181
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    const/4 v4, 0x0

    .line 186
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    check-cast v0, Luj0/g;

    .line 191
    .line 192
    invoke-direct {v2, v0}, Lwj0/a0;-><init>(Luj0/g;)V

    .line 193
    .line 194
    .line 195
    return-object v2

    .line 196
    :pswitch_3
    move-object/from16 v1, p1

    .line 197
    .line 198
    check-cast v1, Lk21/a;

    .line 199
    .line 200
    move-object/from16 v2, p2

    .line 201
    .line 202
    check-cast v2, Lg21/a;

    .line 203
    .line 204
    const-string v3, "$this$scopedFactory"

    .line 205
    .line 206
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    const-string v3, "it"

    .line 210
    .line 211
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    new-instance v2, Lwj0/z;

    .line 215
    .line 216
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 217
    .line 218
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 219
    .line 220
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    const-class v3, Luj0/e;

    .line 225
    .line 226
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 227
    .line 228
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    const/4 v4, 0x0

    .line 233
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    check-cast v0, Luj0/e;

    .line 238
    .line 239
    invoke-direct {v2, v0}, Lwj0/z;-><init>(Luj0/e;)V

    .line 240
    .line 241
    .line 242
    return-object v2

    .line 243
    :pswitch_4
    move-object/from16 v1, p1

    .line 244
    .line 245
    check-cast v1, Lk21/a;

    .line 246
    .line 247
    move-object/from16 v2, p2

    .line 248
    .line 249
    check-cast v2, Lg21/a;

    .line 250
    .line 251
    const-string v3, "$this$scopedFactory"

    .line 252
    .line 253
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    const-string v3, "it"

    .line 257
    .line 258
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    new-instance v2, Lwj0/w;

    .line 262
    .line 263
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 264
    .line 265
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 266
    .line 267
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    const-class v3, Luj0/d;

    .line 272
    .line 273
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 274
    .line 275
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    const/4 v4, 0x0

    .line 280
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    check-cast v0, Luj0/d;

    .line 285
    .line 286
    invoke-direct {v2, v0}, Lwj0/w;-><init>(Luj0/d;)V

    .line 287
    .line 288
    .line 289
    return-object v2

    .line 290
    :pswitch_5
    move-object/from16 v1, p1

    .line 291
    .line 292
    check-cast v1, Lk21/a;

    .line 293
    .line 294
    move-object/from16 v2, p2

    .line 295
    .line 296
    check-cast v2, Lg21/a;

    .line 297
    .line 298
    const-string v3, "$this$scopedFactory"

    .line 299
    .line 300
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    const-string v3, "it"

    .line 304
    .line 305
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    new-instance v2, Lwj0/f;

    .line 309
    .line 310
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 311
    .line 312
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 313
    .line 314
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    const-class v3, Lwj0/u;

    .line 319
    .line 320
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 321
    .line 322
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    const/4 v4, 0x0

    .line 327
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    check-cast v0, Lwj0/u;

    .line 332
    .line 333
    invoke-direct {v2, v0}, Lwj0/f;-><init>(Lwj0/u;)V

    .line 334
    .line 335
    .line 336
    return-object v2

    .line 337
    :pswitch_6
    move-object/from16 v1, p1

    .line 338
    .line 339
    check-cast v1, Lk21/a;

    .line 340
    .line 341
    move-object/from16 v2, p2

    .line 342
    .line 343
    check-cast v2, Lg21/a;

    .line 344
    .line 345
    const-string v3, "$this$scopedFactory"

    .line 346
    .line 347
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    const-string v3, "it"

    .line 351
    .line 352
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 353
    .line 354
    .line 355
    new-instance v2, Lwj0/f0;

    .line 356
    .line 357
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 358
    .line 359
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 360
    .line 361
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 366
    .line 367
    const-class v5, Lwj0/u;

    .line 368
    .line 369
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 370
    .line 371
    .line 372
    move-result-object v5

    .line 373
    const/4 v6, 0x0

    .line 374
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    check-cast v3, Lwj0/u;

    .line 379
    .line 380
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 381
    .line 382
    .line 383
    move-result-object v0

    .line 384
    const-class v5, Luj0/g;

    .line 385
    .line 386
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 387
    .line 388
    .line 389
    move-result-object v4

    .line 390
    invoke-virtual {v1, v4, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v0

    .line 394
    check-cast v0, Luj0/g;

    .line 395
    .line 396
    invoke-direct {v2, v3, v0}, Lwj0/f0;-><init>(Lwj0/u;Luj0/g;)V

    .line 397
    .line 398
    .line 399
    return-object v2

    .line 400
    :pswitch_7
    move-object/from16 v1, p1

    .line 401
    .line 402
    check-cast v1, Lk21/a;

    .line 403
    .line 404
    move-object/from16 v2, p2

    .line 405
    .line 406
    check-cast v2, Lg21/a;

    .line 407
    .line 408
    const-string v3, "$this$scopedFactory"

    .line 409
    .line 410
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    const-string v3, "it"

    .line 414
    .line 415
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 416
    .line 417
    .line 418
    new-instance v2, Lwj0/p;

    .line 419
    .line 420
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 421
    .line 422
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 423
    .line 424
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    const-class v3, Luj0/i;

    .line 429
    .line 430
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 431
    .line 432
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 433
    .line 434
    .line 435
    move-result-object v3

    .line 436
    const/4 v4, 0x0

    .line 437
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    check-cast v0, Luj0/i;

    .line 442
    .line 443
    invoke-direct {v2, v0}, Lwj0/p;-><init>(Luj0/i;)V

    .line 444
    .line 445
    .line 446
    return-object v2

    .line 447
    :pswitch_8
    move-object/from16 v1, p1

    .line 448
    .line 449
    check-cast v1, Lk21/a;

    .line 450
    .line 451
    move-object/from16 v2, p2

    .line 452
    .line 453
    check-cast v2, Lg21/a;

    .line 454
    .line 455
    const-string v3, "$this$scopedFactory"

    .line 456
    .line 457
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    const-string v3, "it"

    .line 461
    .line 462
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 463
    .line 464
    .line 465
    new-instance v2, Lwj0/o;

    .line 466
    .line 467
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 468
    .line 469
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 470
    .line 471
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 472
    .line 473
    .line 474
    move-result-object v0

    .line 475
    const-class v3, Luj0/h;

    .line 476
    .line 477
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 478
    .line 479
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 480
    .line 481
    .line 482
    move-result-object v3

    .line 483
    const/4 v4, 0x0

    .line 484
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    check-cast v0, Luj0/h;

    .line 489
    .line 490
    invoke-direct {v2, v0}, Lwj0/o;-><init>(Luj0/h;)V

    .line 491
    .line 492
    .line 493
    return-object v2

    .line 494
    :pswitch_9
    move-object/from16 v1, p1

    .line 495
    .line 496
    check-cast v1, Lk21/a;

    .line 497
    .line 498
    move-object/from16 v2, p2

    .line 499
    .line 500
    check-cast v2, Lg21/a;

    .line 501
    .line 502
    const-string v3, "$this$scopedFactory"

    .line 503
    .line 504
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    const-string v3, "it"

    .line 508
    .line 509
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 510
    .line 511
    .line 512
    new-instance v2, Lwj0/n;

    .line 513
    .line 514
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 515
    .line 516
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 517
    .line 518
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 519
    .line 520
    .line 521
    move-result-object v0

    .line 522
    const-class v3, Luj0/g;

    .line 523
    .line 524
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 525
    .line 526
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 527
    .line 528
    .line 529
    move-result-object v3

    .line 530
    const/4 v4, 0x0

    .line 531
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    move-result-object v0

    .line 535
    check-cast v0, Luj0/g;

    .line 536
    .line 537
    invoke-direct {v2, v0}, Lwj0/n;-><init>(Luj0/g;)V

    .line 538
    .line 539
    .line 540
    return-object v2

    .line 541
    :pswitch_a
    move-object/from16 v1, p1

    .line 542
    .line 543
    check-cast v1, Lk21/a;

    .line 544
    .line 545
    move-object/from16 v2, p2

    .line 546
    .line 547
    check-cast v2, Lg21/a;

    .line 548
    .line 549
    const-string v3, "$this$scopedFactory"

    .line 550
    .line 551
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    const-string v3, "it"

    .line 555
    .line 556
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 557
    .line 558
    .line 559
    new-instance v2, Lwj0/l;

    .line 560
    .line 561
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 562
    .line 563
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 564
    .line 565
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 566
    .line 567
    .line 568
    move-result-object v0

    .line 569
    const-class v3, Luj0/e;

    .line 570
    .line 571
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 572
    .line 573
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 574
    .line 575
    .line 576
    move-result-object v3

    .line 577
    const/4 v4, 0x0

    .line 578
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    check-cast v0, Luj0/e;

    .line 583
    .line 584
    invoke-direct {v2, v0}, Lwj0/l;-><init>(Luj0/e;)V

    .line 585
    .line 586
    .line 587
    return-object v2

    .line 588
    :pswitch_b
    move-object/from16 v1, p1

    .line 589
    .line 590
    check-cast v1, Lk21/a;

    .line 591
    .line 592
    move-object/from16 v2, p2

    .line 593
    .line 594
    check-cast v2, Lg21/a;

    .line 595
    .line 596
    const-string v3, "$this$scopedFactory"

    .line 597
    .line 598
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 599
    .line 600
    .line 601
    const-string v3, "it"

    .line 602
    .line 603
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    new-instance v2, Lwj0/i;

    .line 607
    .line 608
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 609
    .line 610
    const-class v4, Ltn0/d;

    .line 611
    .line 612
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 613
    .line 614
    .line 615
    move-result-object v4

    .line 616
    const/4 v5, 0x0

    .line 617
    invoke-virtual {v1, v4, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v4

    .line 621
    check-cast v4, Ltn0/d;

    .line 622
    .line 623
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 624
    .line 625
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 626
    .line 627
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 628
    .line 629
    .line 630
    move-result-object v0

    .line 631
    const-class v6, Luj0/d;

    .line 632
    .line 633
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 634
    .line 635
    .line 636
    move-result-object v3

    .line 637
    invoke-virtual {v1, v3, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 638
    .line 639
    .line 640
    move-result-object v0

    .line 641
    check-cast v0, Luj0/d;

    .line 642
    .line 643
    invoke-direct {v2, v4, v0}, Lwj0/i;-><init>(Ltn0/d;Luj0/d;)V

    .line 644
    .line 645
    .line 646
    return-object v2

    .line 647
    :pswitch_c
    move-object/from16 v1, p1

    .line 648
    .line 649
    check-cast v1, Lk21/a;

    .line 650
    .line 651
    move-object/from16 v2, p2

    .line 652
    .line 653
    check-cast v2, Lg21/a;

    .line 654
    .line 655
    const-string v3, "$this$scopedFactory"

    .line 656
    .line 657
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 658
    .line 659
    .line 660
    const-string v3, "it"

    .line 661
    .line 662
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 663
    .line 664
    .line 665
    new-instance v2, Lwj0/r;

    .line 666
    .line 667
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 668
    .line 669
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 670
    .line 671
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 672
    .line 673
    .line 674
    move-result-object v0

    .line 675
    const-class v3, Lwj0/u;

    .line 676
    .line 677
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 678
    .line 679
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 680
    .line 681
    .line 682
    move-result-object v3

    .line 683
    const/4 v4, 0x0

    .line 684
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 685
    .line 686
    .line 687
    move-result-object v0

    .line 688
    check-cast v0, Lwj0/u;

    .line 689
    .line 690
    invoke-direct {v2, v0}, Lwj0/r;-><init>(Lwj0/u;)V

    .line 691
    .line 692
    .line 693
    return-object v2

    .line 694
    :pswitch_d
    move-object/from16 v1, p1

    .line 695
    .line 696
    check-cast v1, Lk21/a;

    .line 697
    .line 698
    move-object/from16 v2, p2

    .line 699
    .line 700
    check-cast v2, Lg21/a;

    .line 701
    .line 702
    const-string v3, "$this$scopedFactory"

    .line 703
    .line 704
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 705
    .line 706
    .line 707
    const-string v3, "it"

    .line 708
    .line 709
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 710
    .line 711
    .line 712
    new-instance v2, Lwj0/d;

    .line 713
    .line 714
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 715
    .line 716
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 717
    .line 718
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 719
    .line 720
    .line 721
    move-result-object v0

    .line 722
    const-class v3, Luj0/i;

    .line 723
    .line 724
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 725
    .line 726
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 727
    .line 728
    .line 729
    move-result-object v3

    .line 730
    const/4 v4, 0x0

    .line 731
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v0

    .line 735
    check-cast v0, Luj0/i;

    .line 736
    .line 737
    invoke-direct {v2, v0}, Lwj0/d;-><init>(Luj0/i;)V

    .line 738
    .line 739
    .line 740
    return-object v2

    .line 741
    :pswitch_e
    move-object/from16 v1, p1

    .line 742
    .line 743
    check-cast v1, Lk21/a;

    .line 744
    .line 745
    move-object/from16 v2, p2

    .line 746
    .line 747
    check-cast v2, Lg21/a;

    .line 748
    .line 749
    const-string v3, "$this$scopedFactory"

    .line 750
    .line 751
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 752
    .line 753
    .line 754
    const-string v3, "it"

    .line 755
    .line 756
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    new-instance v2, Lwj0/c;

    .line 760
    .line 761
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 762
    .line 763
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 764
    .line 765
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 766
    .line 767
    .line 768
    move-result-object v0

    .line 769
    const-class v3, Luj0/g;

    .line 770
    .line 771
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 772
    .line 773
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 774
    .line 775
    .line 776
    move-result-object v3

    .line 777
    const/4 v4, 0x0

    .line 778
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 779
    .line 780
    .line 781
    move-result-object v0

    .line 782
    check-cast v0, Luj0/g;

    .line 783
    .line 784
    invoke-direct {v2, v0}, Lwj0/c;-><init>(Luj0/g;)V

    .line 785
    .line 786
    .line 787
    return-object v2

    .line 788
    :pswitch_f
    move-object/from16 v1, p1

    .line 789
    .line 790
    check-cast v1, Lk21/a;

    .line 791
    .line 792
    move-object/from16 v2, p2

    .line 793
    .line 794
    check-cast v2, Lg21/a;

    .line 795
    .line 796
    const-string v3, "$this$scopedFactory"

    .line 797
    .line 798
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    const-string v3, "it"

    .line 802
    .line 803
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 804
    .line 805
    .line 806
    new-instance v2, Lwj0/t;

    .line 807
    .line 808
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 809
    .line 810
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 811
    .line 812
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 813
    .line 814
    .line 815
    move-result-object v0

    .line 816
    const-class v3, Lwj0/a;

    .line 817
    .line 818
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 819
    .line 820
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 821
    .line 822
    .line 823
    move-result-object v3

    .line 824
    const/4 v4, 0x0

    .line 825
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 826
    .line 827
    .line 828
    move-result-object v0

    .line 829
    check-cast v0, Lwj0/a;

    .line 830
    .line 831
    invoke-direct {v2, v0}, Lwj0/t;-><init>(Lwj0/a;)V

    .line 832
    .line 833
    .line 834
    return-object v2

    .line 835
    :pswitch_10
    move-object/from16 v1, p1

    .line 836
    .line 837
    check-cast v1, Lk21/a;

    .line 838
    .line 839
    move-object/from16 v2, p2

    .line 840
    .line 841
    check-cast v2, Lg21/a;

    .line 842
    .line 843
    const-string v3, "$this$scopedFactory"

    .line 844
    .line 845
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 846
    .line 847
    .line 848
    const-string v3, "it"

    .line 849
    .line 850
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 851
    .line 852
    .line 853
    new-instance v2, Lwj0/x;

    .line 854
    .line 855
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 856
    .line 857
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 858
    .line 859
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 860
    .line 861
    .line 862
    move-result-object v0

    .line 863
    const-class v3, Lwj0/a;

    .line 864
    .line 865
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 866
    .line 867
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 868
    .line 869
    .line 870
    move-result-object v3

    .line 871
    const/4 v4, 0x0

    .line 872
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 873
    .line 874
    .line 875
    move-result-object v0

    .line 876
    check-cast v0, Lwj0/a;

    .line 877
    .line 878
    invoke-direct {v2, v0}, Lwj0/x;-><init>(Lwj0/a;)V

    .line 879
    .line 880
    .line 881
    return-object v2

    .line 882
    :pswitch_11
    move-object/from16 v1, p1

    .line 883
    .line 884
    check-cast v1, Lk21/a;

    .line 885
    .line 886
    move-object/from16 v2, p2

    .line 887
    .line 888
    check-cast v2, Lg21/a;

    .line 889
    .line 890
    const-string v3, "$this$scopedFactory"

    .line 891
    .line 892
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 893
    .line 894
    .line 895
    const-string v3, "it"

    .line 896
    .line 897
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    new-instance v2, Lwj0/b;

    .line 901
    .line 902
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 903
    .line 904
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 905
    .line 906
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 907
    .line 908
    .line 909
    move-result-object v3

    .line 910
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 911
    .line 912
    const-class v5, Lwj0/c;

    .line 913
    .line 914
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 915
    .line 916
    .line 917
    move-result-object v5

    .line 918
    const/4 v6, 0x0

    .line 919
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object v3

    .line 923
    check-cast v3, Lwj0/c;

    .line 924
    .line 925
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 926
    .line 927
    .line 928
    move-result-object v0

    .line 929
    const-class v5, Lwj0/d;

    .line 930
    .line 931
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 932
    .line 933
    .line 934
    move-result-object v5

    .line 935
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    check-cast v0, Lwj0/d;

    .line 940
    .line 941
    const-class v5, Lwj0/e;

    .line 942
    .line 943
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 944
    .line 945
    .line 946
    move-result-object v4

    .line 947
    invoke-virtual {v1, v4, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 948
    .line 949
    .line 950
    move-result-object v1

    .line 951
    check-cast v1, Lwj0/e;

    .line 952
    .line 953
    invoke-direct {v2, v3, v0, v1}, Lwj0/b;-><init>(Lwj0/c;Lwj0/d;Lwj0/e;)V

    .line 954
    .line 955
    .line 956
    return-object v2

    .line 957
    :pswitch_12
    move-object/from16 v1, p1

    .line 958
    .line 959
    check-cast v1, Lk21/a;

    .line 960
    .line 961
    move-object/from16 v2, p2

    .line 962
    .line 963
    check-cast v2, Lg21/a;

    .line 964
    .line 965
    const-string v3, "$this$scopedFactory"

    .line 966
    .line 967
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 968
    .line 969
    .line 970
    const-string v3, "it"

    .line 971
    .line 972
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 973
    .line 974
    .line 975
    new-instance v2, Lwj0/j0;

    .line 976
    .line 977
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 978
    .line 979
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 980
    .line 981
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 982
    .line 983
    .line 984
    move-result-object v0

    .line 985
    const-class v3, Lwj0/a;

    .line 986
    .line 987
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 988
    .line 989
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 990
    .line 991
    .line 992
    move-result-object v3

    .line 993
    const/4 v4, 0x0

    .line 994
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    check-cast v0, Lwj0/a;

    .line 999
    .line 1000
    invoke-direct {v2, v0}, Lwj0/j0;-><init>(Lwj0/a;)V

    .line 1001
    .line 1002
    .line 1003
    return-object v2

    .line 1004
    :pswitch_13
    move-object/from16 v1, p1

    .line 1005
    .line 1006
    check-cast v1, Lk21/a;

    .line 1007
    .line 1008
    move-object/from16 v2, p2

    .line 1009
    .line 1010
    check-cast v2, Lg21/a;

    .line 1011
    .line 1012
    const-string v3, "$this$scopedViewModel"

    .line 1013
    .line 1014
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1015
    .line 1016
    .line 1017
    const-string v3, "it"

    .line 1018
    .line 1019
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1020
    .line 1021
    .line 1022
    new-instance v4, Lyj0/f;

    .line 1023
    .line 1024
    iget-object v0, v0, Lvj0/a;->e:Leo0/b;

    .line 1025
    .line 1026
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1027
    .line 1028
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v2

    .line 1032
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1033
    .line 1034
    const-class v5, Lwj0/i;

    .line 1035
    .line 1036
    invoke-virtual {v3, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v5

    .line 1040
    const/4 v6, 0x0

    .line 1041
    invoke-virtual {v1, v5, v2, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1042
    .line 1043
    .line 1044
    move-result-object v2

    .line 1045
    move-object v5, v2

    .line 1046
    check-cast v5, Lwj0/i;

    .line 1047
    .line 1048
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v2

    .line 1052
    const-class v7, Lwj0/n;

    .line 1053
    .line 1054
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v7

    .line 1058
    invoke-virtual {v1, v7, v2, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v2

    .line 1062
    check-cast v2, Lwj0/n;

    .line 1063
    .line 1064
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v7

    .line 1068
    const-class v8, Lwj0/o;

    .line 1069
    .line 1070
    invoke-virtual {v3, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v8

    .line 1074
    invoke-virtual {v1, v8, v7, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v7

    .line 1078
    check-cast v7, Lwj0/o;

    .line 1079
    .line 1080
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v8

    .line 1084
    const-class v9, Lwj0/p;

    .line 1085
    .line 1086
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v9

    .line 1090
    invoke-virtual {v1, v9, v8, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v8

    .line 1094
    check-cast v8, Lwj0/p;

    .line 1095
    .line 1096
    const-class v9, Lwj0/s;

    .line 1097
    .line 1098
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v9

    .line 1102
    invoke-virtual {v1, v9, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v9

    .line 1106
    check-cast v9, Lwj0/s;

    .line 1107
    .line 1108
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v10

    .line 1112
    const-class v11, Lwj0/t;

    .line 1113
    .line 1114
    invoke-virtual {v3, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v11

    .line 1118
    invoke-virtual {v1, v11, v10, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v10

    .line 1122
    check-cast v10, Lwj0/t;

    .line 1123
    .line 1124
    const-class v11, Lwj0/q;

    .line 1125
    .line 1126
    invoke-virtual {v3, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v11

    .line 1130
    invoke-virtual {v1, v11, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v11

    .line 1134
    check-cast v11, Lwj0/q;

    .line 1135
    .line 1136
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v12

    .line 1140
    const-class v13, Lwj0/f0;

    .line 1141
    .line 1142
    invoke-virtual {v3, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1143
    .line 1144
    .line 1145
    move-result-object v13

    .line 1146
    invoke-virtual {v1, v13, v12, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v12

    .line 1150
    check-cast v12, Lwj0/f0;

    .line 1151
    .line 1152
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v13

    .line 1156
    const-class v14, Lwj0/f;

    .line 1157
    .line 1158
    invoke-virtual {v3, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v14

    .line 1162
    invoke-virtual {v1, v14, v13, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v13

    .line 1166
    check-cast v13, Lwj0/f;

    .line 1167
    .line 1168
    const-class v14, Lwj0/g;

    .line 1169
    .line 1170
    invoke-virtual {v3, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v14

    .line 1174
    invoke-virtual {v1, v14, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v14

    .line 1178
    check-cast v14, Lwj0/g;

    .line 1179
    .line 1180
    const-class v15, Lwj0/y;

    .line 1181
    .line 1182
    invoke-virtual {v3, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v15

    .line 1186
    invoke-virtual {v1, v15, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v15

    .line 1190
    check-cast v15, Lwj0/y;

    .line 1191
    .line 1192
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v6

    .line 1196
    move-object/from16 v16, v0

    .line 1197
    .line 1198
    const-class v0, Lwj0/z;

    .line 1199
    .line 1200
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v0

    .line 1204
    move-object/from16 p1, v2

    .line 1205
    .line 1206
    const/4 v2, 0x0

    .line 1207
    invoke-virtual {v1, v0, v6, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v0

    .line 1211
    check-cast v0, Lwj0/z;

    .line 1212
    .line 1213
    invoke-static/range {v16 .. v16}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1214
    .line 1215
    .line 1216
    move-result-object v6

    .line 1217
    move-object/from16 p0, v0

    .line 1218
    .line 1219
    const-class v0, Lwj0/i0;

    .line 1220
    .line 1221
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v0

    .line 1225
    invoke-virtual {v1, v0, v6, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v0

    .line 1229
    move-object/from16 v17, v0

    .line 1230
    .line 1231
    check-cast v17, Lwj0/i0;

    .line 1232
    .line 1233
    invoke-static/range {v16 .. v16}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v0

    .line 1237
    const-class v6, Lwj0/j0;

    .line 1238
    .line 1239
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v6

    .line 1243
    invoke-virtual {v1, v6, v0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v0

    .line 1247
    move-object/from16 v18, v0

    .line 1248
    .line 1249
    check-cast v18, Lwj0/j0;

    .line 1250
    .line 1251
    const-class v0, Lck0/d;

    .line 1252
    .line 1253
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1254
    .line 1255
    .line 1256
    move-result-object v0

    .line 1257
    invoke-virtual {v1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1258
    .line 1259
    .line 1260
    move-result-object v0

    .line 1261
    move-object/from16 v19, v0

    .line 1262
    .line 1263
    check-cast v19, Lck0/d;

    .line 1264
    .line 1265
    invoke-static/range {v16 .. v16}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1266
    .line 1267
    .line 1268
    move-result-object v0

    .line 1269
    const-class v6, Lwj0/a0;

    .line 1270
    .line 1271
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v6

    .line 1275
    invoke-virtual {v1, v6, v0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1276
    .line 1277
    .line 1278
    move-result-object v0

    .line 1279
    move-object/from16 v20, v0

    .line 1280
    .line 1281
    check-cast v20, Lwj0/a0;

    .line 1282
    .line 1283
    invoke-static/range {v16 .. v16}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1284
    .line 1285
    .line 1286
    move-result-object v0

    .line 1287
    const-class v6, Lwj0/c0;

    .line 1288
    .line 1289
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1290
    .line 1291
    .line 1292
    move-result-object v3

    .line 1293
    invoke-virtual {v1, v3, v0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1294
    .line 1295
    .line 1296
    move-result-object v0

    .line 1297
    move-object/from16 v21, v0

    .line 1298
    .line 1299
    check-cast v21, Lwj0/c0;

    .line 1300
    .line 1301
    move-object/from16 v16, p0

    .line 1302
    .line 1303
    move-object/from16 v6, p1

    .line 1304
    .line 1305
    invoke-direct/range {v4 .. v21}, Lyj0/f;-><init>(Lwj0/i;Lwj0/n;Lwj0/o;Lwj0/p;Lwj0/s;Lwj0/t;Lwj0/q;Lwj0/f0;Lwj0/f;Lwj0/g;Lwj0/y;Lwj0/z;Lwj0/i0;Lwj0/j0;Lck0/d;Lwj0/a0;Lwj0/c0;)V

    .line 1306
    .line 1307
    .line 1308
    return-object v4

    .line 1309
    :pswitch_data_0
    .packed-switch 0x0
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
