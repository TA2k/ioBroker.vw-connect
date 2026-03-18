.class public final synthetic Ltk0/a;
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
    iput p2, p0, Ltk0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltk0/a;->e:Leo0/b;

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
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltk0/a;->d:I

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
    new-instance v2, Luk0/e0;

    .line 27
    .line 28
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 29
    .line 30
    const-class v4, Lpp0/n0;

    .line 31
    .line 32
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    const/4 v5, 0x0

    .line 37
    invoke-virtual {v1, v4, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Lpp0/n0;

    .line 42
    .line 43
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 44
    .line 45
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    const-class v7, Luk0/h;

    .line 52
    .line 53
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    invoke-virtual {v1, v7, v6, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    check-cast v6, Luk0/h;

    .line 62
    .line 63
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const-class v7, Luk0/r;

    .line 68
    .line 69
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-virtual {v1, v7, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    check-cast v0, Luk0/r;

    .line 78
    .line 79
    const-class v7, Luk0/t;

    .line 80
    .line 81
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Luk0/t;

    .line 90
    .line 91
    invoke-direct {v2, v4, v6, v0, v1}, Luk0/e0;-><init>(Lpp0/n0;Luk0/h;Luk0/r;Luk0/t;)V

    .line 92
    .line 93
    .line 94
    return-object v2

    .line 95
    :pswitch_0
    move-object/from16 v1, p1

    .line 96
    .line 97
    check-cast v1, Lk21/a;

    .line 98
    .line 99
    move-object/from16 v2, p2

    .line 100
    .line 101
    check-cast v2, Lg21/a;

    .line 102
    .line 103
    const-string v3, "$this$scopedFactory"

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v3, "it"

    .line 109
    .line 110
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 114
    .line 115
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 116
    .line 117
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 122
    .line 123
    const-class v4, Luk0/v;

    .line 124
    .line 125
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    const/4 v5, 0x0

    .line 130
    invoke-virtual {v1, v4, v2, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    check-cast v2, Luk0/v;

    .line 135
    .line 136
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    const-class v4, Luk0/r;

    .line 141
    .line 142
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    invoke-virtual {v1, v3, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    check-cast v0, Luk0/r;

    .line 151
    .line 152
    new-instance v1, Luk0/r0;

    .line 153
    .line 154
    invoke-direct {v1, v0, v2}, Luk0/r0;-><init>(Luk0/r;Luk0/v;)V

    .line 155
    .line 156
    .line 157
    return-object v1

    .line 158
    :pswitch_1
    move-object/from16 v1, p1

    .line 159
    .line 160
    check-cast v1, Lk21/a;

    .line 161
    .line 162
    move-object/from16 v2, p2

    .line 163
    .line 164
    check-cast v2, Lg21/a;

    .line 165
    .line 166
    const-string v3, "$this$scopedFactory"

    .line 167
    .line 168
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    const-string v3, "it"

    .line 172
    .line 173
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 177
    .line 178
    const-class v3, Lsk0/f;

    .line 179
    .line 180
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    const/4 v4, 0x0

    .line 185
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    move-object v6, v3

    .line 190
    check-cast v6, Lsk0/f;

    .line 191
    .line 192
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 193
    .line 194
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 195
    .line 196
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    const-class v3, Luk0/v;

    .line 201
    .line 202
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    move-object v8, v0

    .line 211
    check-cast v8, Luk0/v;

    .line 212
    .line 213
    const-class v0, Lkf0/o;

    .line 214
    .line 215
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    move-object v9, v0

    .line 224
    check-cast v9, Lkf0/o;

    .line 225
    .line 226
    const-class v0, Lml0/e;

    .line 227
    .line 228
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    move-object v11, v0

    .line 237
    check-cast v11, Lml0/e;

    .line 238
    .line 239
    const-class v0, Lro0/e;

    .line 240
    .line 241
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    move-object v10, v0

    .line 250
    check-cast v10, Lro0/e;

    .line 251
    .line 252
    const-class v0, Lnn0/t;

    .line 253
    .line 254
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    move-object v12, v0

    .line 263
    check-cast v12, Lnn0/t;

    .line 264
    .line 265
    const-class v0, Lal0/v;

    .line 266
    .line 267
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    move-object v13, v0

    .line 276
    check-cast v13, Lal0/v;

    .line 277
    .line 278
    const-class v0, Lpp0/l0;

    .line 279
    .line 280
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    move-object v7, v0

    .line 289
    check-cast v7, Lpp0/l0;

    .line 290
    .line 291
    new-instance v5, Luk0/r;

    .line 292
    .line 293
    invoke-direct/range {v5 .. v13}, Luk0/r;-><init>(Lsk0/f;Lpp0/l0;Luk0/v;Lkf0/o;Lro0/e;Lml0/e;Lnn0/t;Lal0/v;)V

    .line 294
    .line 295
    .line 296
    return-object v5

    .line 297
    :pswitch_2
    move-object/from16 v1, p1

    .line 298
    .line 299
    check-cast v1, Lk21/a;

    .line 300
    .line 301
    move-object/from16 v2, p2

    .line 302
    .line 303
    check-cast v2, Lg21/a;

    .line 304
    .line 305
    const-string v3, "$this$scopedFactory"

    .line 306
    .line 307
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    const-string v3, "it"

    .line 311
    .line 312
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    new-instance v2, Luk0/h;

    .line 316
    .line 317
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 318
    .line 319
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 320
    .line 321
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    const-class v3, Luk0/v;

    .line 326
    .line 327
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 328
    .line 329
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 330
    .line 331
    .line 332
    move-result-object v3

    .line 333
    const/4 v4, 0x0

    .line 334
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    check-cast v0, Luk0/v;

    .line 339
    .line 340
    invoke-direct {v2, v0}, Luk0/h;-><init>(Luk0/v;)V

    .line 341
    .line 342
    .line 343
    return-object v2

    .line 344
    :pswitch_3
    move-object/from16 v1, p1

    .line 345
    .line 346
    check-cast v1, Lk21/a;

    .line 347
    .line 348
    move-object/from16 v2, p2

    .line 349
    .line 350
    check-cast v2, Lg21/a;

    .line 351
    .line 352
    const-string v3, "$this$scopedFactory"

    .line 353
    .line 354
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    const-string v3, "it"

    .line 358
    .line 359
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    new-instance v2, Luk0/b0;

    .line 363
    .line 364
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 365
    .line 366
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 367
    .line 368
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    const-class v3, Luk0/v;

    .line 373
    .line 374
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 375
    .line 376
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 377
    .line 378
    .line 379
    move-result-object v3

    .line 380
    const/4 v4, 0x0

    .line 381
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v0

    .line 385
    check-cast v0, Luk0/v;

    .line 386
    .line 387
    invoke-direct {v2, v0}, Luk0/b0;-><init>(Luk0/v;)V

    .line 388
    .line 389
    .line 390
    return-object v2

    .line 391
    :pswitch_4
    move-object/from16 v1, p1

    .line 392
    .line 393
    check-cast v1, Lk21/a;

    .line 394
    .line 395
    move-object/from16 v2, p2

    .line 396
    .line 397
    check-cast v2, Lg21/a;

    .line 398
    .line 399
    const-string v3, "$this$scopedViewModel"

    .line 400
    .line 401
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    const-string v3, "it"

    .line 405
    .line 406
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    new-instance v2, Lwk0/b;

    .line 410
    .line 411
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 412
    .line 413
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 414
    .line 415
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 416
    .line 417
    .line 418
    move-result-object v3

    .line 419
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 420
    .line 421
    const-class v5, Luk0/c0;

    .line 422
    .line 423
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 424
    .line 425
    .line 426
    move-result-object v5

    .line 427
    const/4 v6, 0x0

    .line 428
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v3

    .line 432
    check-cast v3, Luk0/c0;

    .line 433
    .line 434
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    const-class v5, Luk0/b0;

    .line 439
    .line 440
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 441
    .line 442
    .line 443
    move-result-object v5

    .line 444
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v0

    .line 448
    check-cast v0, Luk0/b0;

    .line 449
    .line 450
    const-class v1, Lvk0/a;

    .line 451
    .line 452
    invoke-virtual {v4, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 453
    .line 454
    .line 455
    move-result-object v1

    .line 456
    invoke-direct {v2, v3, v0, v1}, Lwk0/z1;-><init>(Luk0/c0;Luk0/b0;Lhy0/d;)V

    .line 457
    .line 458
    .line 459
    return-object v2

    .line 460
    :pswitch_5
    move-object/from16 v1, p1

    .line 461
    .line 462
    check-cast v1, Lk21/a;

    .line 463
    .line 464
    move-object/from16 v2, p2

    .line 465
    .line 466
    check-cast v2, Lg21/a;

    .line 467
    .line 468
    const-string v3, "$this$scopedViewModel"

    .line 469
    .line 470
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 471
    .line 472
    .line 473
    const-string v3, "it"

    .line 474
    .line 475
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 476
    .line 477
    .line 478
    new-instance v2, Lwk0/f0;

    .line 479
    .line 480
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 481
    .line 482
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 483
    .line 484
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 485
    .line 486
    .line 487
    move-result-object v3

    .line 488
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 489
    .line 490
    const-class v5, Luk0/c0;

    .line 491
    .line 492
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 493
    .line 494
    .line 495
    move-result-object v5

    .line 496
    const/4 v6, 0x0

    .line 497
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object v3

    .line 501
    check-cast v3, Luk0/c0;

    .line 502
    .line 503
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    const-class v5, Luk0/b0;

    .line 508
    .line 509
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 510
    .line 511
    .line 512
    move-result-object v5

    .line 513
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    check-cast v0, Luk0/b0;

    .line 518
    .line 519
    const-class v1, Lvk0/v;

    .line 520
    .line 521
    invoke-virtual {v4, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 522
    .line 523
    .line 524
    move-result-object v1

    .line 525
    invoke-direct {v2, v3, v0, v1}, Lwk0/z1;-><init>(Luk0/c0;Luk0/b0;Lhy0/d;)V

    .line 526
    .line 527
    .line 528
    return-object v2

    .line 529
    :pswitch_6
    move-object/from16 v1, p1

    .line 530
    .line 531
    check-cast v1, Lk21/a;

    .line 532
    .line 533
    move-object/from16 v2, p2

    .line 534
    .line 535
    check-cast v2, Lg21/a;

    .line 536
    .line 537
    const-string v3, "$this$scopedViewModel"

    .line 538
    .line 539
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    const-string v3, "it"

    .line 543
    .line 544
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 545
    .line 546
    .line 547
    new-instance v2, Lwk0/x0;

    .line 548
    .line 549
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 550
    .line 551
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 552
    .line 553
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 554
    .line 555
    .line 556
    move-result-object v3

    .line 557
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 558
    .line 559
    const-class v5, Luk0/c0;

    .line 560
    .line 561
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 562
    .line 563
    .line 564
    move-result-object v5

    .line 565
    const/4 v6, 0x0

    .line 566
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v3

    .line 570
    check-cast v3, Luk0/c0;

    .line 571
    .line 572
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 573
    .line 574
    .line 575
    move-result-object v0

    .line 576
    const-class v5, Luk0/b0;

    .line 577
    .line 578
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 579
    .line 580
    .line 581
    move-result-object v5

    .line 582
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object v0

    .line 586
    check-cast v0, Luk0/b0;

    .line 587
    .line 588
    const-class v5, Lij0/a;

    .line 589
    .line 590
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 591
    .line 592
    .line 593
    move-result-object v4

    .line 594
    invoke-virtual {v1, v4, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 595
    .line 596
    .line 597
    move-result-object v1

    .line 598
    check-cast v1, Lij0/a;

    .line 599
    .line 600
    invoke-direct {v2, v3, v0, v1}, Lwk0/x0;-><init>(Luk0/c0;Luk0/b0;Lij0/a;)V

    .line 601
    .line 602
    .line 603
    return-object v2

    .line 604
    :pswitch_7
    move-object/from16 v1, p1

    .line 605
    .line 606
    check-cast v1, Lk21/a;

    .line 607
    .line 608
    move-object/from16 v2, p2

    .line 609
    .line 610
    check-cast v2, Lg21/a;

    .line 611
    .line 612
    const-string v3, "$this$scopedViewModel"

    .line 613
    .line 614
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    const-string v3, "it"

    .line 618
    .line 619
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 620
    .line 621
    .line 622
    new-instance v2, Lwk0/y;

    .line 623
    .line 624
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 625
    .line 626
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 627
    .line 628
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 629
    .line 630
    .line 631
    move-result-object v3

    .line 632
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 633
    .line 634
    const-class v5, Luk0/c0;

    .line 635
    .line 636
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 637
    .line 638
    .line 639
    move-result-object v5

    .line 640
    const/4 v6, 0x0

    .line 641
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 642
    .line 643
    .line 644
    move-result-object v3

    .line 645
    check-cast v3, Luk0/c0;

    .line 646
    .line 647
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 648
    .line 649
    .line 650
    move-result-object v0

    .line 651
    const-class v5, Luk0/b0;

    .line 652
    .line 653
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 654
    .line 655
    .line 656
    move-result-object v5

    .line 657
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 658
    .line 659
    .line 660
    move-result-object v0

    .line 661
    check-cast v0, Luk0/b0;

    .line 662
    .line 663
    const-class v1, Lvk0/r;

    .line 664
    .line 665
    invoke-virtual {v4, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 666
    .line 667
    .line 668
    move-result-object v1

    .line 669
    invoke-direct {v2, v3, v0, v1}, Lwk0/z1;-><init>(Luk0/c0;Luk0/b0;Lhy0/d;)V

    .line 670
    .line 671
    .line 672
    return-object v2

    .line 673
    :pswitch_8
    move-object/from16 v1, p1

    .line 674
    .line 675
    check-cast v1, Lk21/a;

    .line 676
    .line 677
    move-object/from16 v2, p2

    .line 678
    .line 679
    check-cast v2, Lg21/a;

    .line 680
    .line 681
    const-string v3, "$this$scopedFactory"

    .line 682
    .line 683
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 684
    .line 685
    .line 686
    const-string v3, "it"

    .line 687
    .line 688
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 689
    .line 690
    .line 691
    new-instance v4, Luk0/a0;

    .line 692
    .line 693
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 694
    .line 695
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 696
    .line 697
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 698
    .line 699
    .line 700
    move-result-object v2

    .line 701
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 702
    .line 703
    const-class v5, Lal0/s0;

    .line 704
    .line 705
    invoke-virtual {v3, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 706
    .line 707
    .line 708
    move-result-object v5

    .line 709
    const/4 v6, 0x0

    .line 710
    invoke-virtual {v1, v5, v2, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 711
    .line 712
    .line 713
    move-result-object v2

    .line 714
    move-object v5, v2

    .line 715
    check-cast v5, Lal0/s0;

    .line 716
    .line 717
    const-class v2, Lal0/p0;

    .line 718
    .line 719
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 720
    .line 721
    .line 722
    move-result-object v2

    .line 723
    invoke-virtual {v1, v2, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v2

    .line 727
    check-cast v2, Lal0/p0;

    .line 728
    .line 729
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 730
    .line 731
    .line 732
    move-result-object v7

    .line 733
    const-class v8, Lwj0/r;

    .line 734
    .line 735
    invoke-virtual {v3, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 736
    .line 737
    .line 738
    move-result-object v8

    .line 739
    invoke-virtual {v1, v8, v7, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 740
    .line 741
    .line 742
    move-result-object v7

    .line 743
    check-cast v7, Lwj0/r;

    .line 744
    .line 745
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 746
    .line 747
    .line 748
    move-result-object v8

    .line 749
    const-class v9, Luk0/h;

    .line 750
    .line 751
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 752
    .line 753
    .line 754
    move-result-object v9

    .line 755
    invoke-virtual {v1, v9, v8, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    move-result-object v8

    .line 759
    check-cast v8, Luk0/h;

    .line 760
    .line 761
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 762
    .line 763
    .line 764
    move-result-object v0

    .line 765
    const-class v9, Luk0/r;

    .line 766
    .line 767
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 768
    .line 769
    .line 770
    move-result-object v3

    .line 771
    invoke-virtual {v1, v3, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 772
    .line 773
    .line 774
    move-result-object v0

    .line 775
    move-object v9, v0

    .line 776
    check-cast v9, Luk0/r;

    .line 777
    .line 778
    move-object v6, v2

    .line 779
    invoke-direct/range {v4 .. v9}, Luk0/a0;-><init>(Lal0/s0;Lal0/p0;Lwj0/r;Luk0/h;Luk0/r;)V

    .line 780
    .line 781
    .line 782
    return-object v4

    .line 783
    :pswitch_9
    move-object/from16 v1, p1

    .line 784
    .line 785
    check-cast v1, Lk21/a;

    .line 786
    .line 787
    move-object/from16 v2, p2

    .line 788
    .line 789
    check-cast v2, Lg21/a;

    .line 790
    .line 791
    const-string v3, "$this$scopedViewModel"

    .line 792
    .line 793
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    const-string v3, "it"

    .line 797
    .line 798
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    new-instance v4, Lwk0/t2;

    .line 802
    .line 803
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 804
    .line 805
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 806
    .line 807
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 808
    .line 809
    .line 810
    move-result-object v2

    .line 811
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 812
    .line 813
    const-class v5, Luk0/c0;

    .line 814
    .line 815
    invoke-virtual {v3, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 816
    .line 817
    .line 818
    move-result-object v5

    .line 819
    const/4 v6, 0x0

    .line 820
    invoke-virtual {v1, v5, v2, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 821
    .line 822
    .line 823
    move-result-object v2

    .line 824
    move-object v5, v2

    .line 825
    check-cast v5, Luk0/c0;

    .line 826
    .line 827
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 828
    .line 829
    .line 830
    move-result-object v2

    .line 831
    const-class v7, Luk0/b0;

    .line 832
    .line 833
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 834
    .line 835
    .line 836
    move-result-object v7

    .line 837
    invoke-virtual {v1, v7, v2, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 838
    .line 839
    .line 840
    move-result-object v2

    .line 841
    check-cast v2, Luk0/b0;

    .line 842
    .line 843
    const-class v7, Lij0/a;

    .line 844
    .line 845
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 846
    .line 847
    .line 848
    move-result-object v7

    .line 849
    invoke-virtual {v1, v7, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 850
    .line 851
    .line 852
    move-result-object v7

    .line 853
    check-cast v7, Lij0/a;

    .line 854
    .line 855
    const-class v8, Lbq0/p;

    .line 856
    .line 857
    invoke-virtual {v3, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 858
    .line 859
    .line 860
    move-result-object v8

    .line 861
    invoke-virtual {v1, v8, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    move-result-object v8

    .line 865
    check-cast v8, Lbq0/p;

    .line 866
    .line 867
    const-class v9, Lbq0/n;

    .line 868
    .line 869
    invoke-virtual {v3, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 870
    .line 871
    .line 872
    move-result-object v9

    .line 873
    invoke-virtual {v1, v9, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 874
    .line 875
    .line 876
    move-result-object v9

    .line 877
    check-cast v9, Lbq0/n;

    .line 878
    .line 879
    const-class v10, Lbq0/q;

    .line 880
    .line 881
    invoke-virtual {v3, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 882
    .line 883
    .line 884
    move-result-object v10

    .line 885
    invoke-virtual {v1, v10, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 886
    .line 887
    .line 888
    move-result-object v10

    .line 889
    check-cast v10, Lbq0/q;

    .line 890
    .line 891
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 892
    .line 893
    .line 894
    move-result-object v0

    .line 895
    const-class v11, Luk0/r0;

    .line 896
    .line 897
    invoke-virtual {v3, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 898
    .line 899
    .line 900
    move-result-object v11

    .line 901
    invoke-virtual {v1, v11, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 902
    .line 903
    .line 904
    move-result-object v0

    .line 905
    move-object v11, v0

    .line 906
    check-cast v11, Luk0/r0;

    .line 907
    .line 908
    const-class v0, Lbq0/c;

    .line 909
    .line 910
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 911
    .line 912
    .line 913
    move-result-object v0

    .line 914
    invoke-virtual {v1, v0, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 915
    .line 916
    .line 917
    move-result-object v0

    .line 918
    move-object v12, v0

    .line 919
    check-cast v12, Lbq0/c;

    .line 920
    .line 921
    const-class v0, Lqf0/g;

    .line 922
    .line 923
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 924
    .line 925
    .line 926
    move-result-object v0

    .line 927
    invoke-virtual {v1, v0, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v0

    .line 931
    move-object v13, v0

    .line 932
    check-cast v13, Lqf0/g;

    .line 933
    .line 934
    const-class v0, Lkf0/k;

    .line 935
    .line 936
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 937
    .line 938
    .line 939
    move-result-object v0

    .line 940
    invoke-virtual {v1, v0, v6, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 941
    .line 942
    .line 943
    move-result-object v0

    .line 944
    move-object v14, v0

    .line 945
    check-cast v14, Lkf0/k;

    .line 946
    .line 947
    move-object v6, v2

    .line 948
    invoke-direct/range {v4 .. v14}, Lwk0/t2;-><init>(Luk0/c0;Luk0/b0;Lij0/a;Lbq0/p;Lbq0/n;Lbq0/q;Luk0/r0;Lbq0/c;Lqf0/g;Lkf0/k;)V

    .line 949
    .line 950
    .line 951
    return-object v4

    .line 952
    :pswitch_a
    move-object/from16 v1, p1

    .line 953
    .line 954
    check-cast v1, Lk21/a;

    .line 955
    .line 956
    move-object/from16 v2, p2

    .line 957
    .line 958
    check-cast v2, Lg21/a;

    .line 959
    .line 960
    const-string v3, "$this$scopedViewModel"

    .line 961
    .line 962
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 963
    .line 964
    .line 965
    const-string v3, "it"

    .line 966
    .line 967
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 968
    .line 969
    .line 970
    new-instance v2, Lwk0/n2;

    .line 971
    .line 972
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 973
    .line 974
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 975
    .line 976
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 977
    .line 978
    .line 979
    move-result-object v3

    .line 980
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 981
    .line 982
    const-class v5, Luk0/c0;

    .line 983
    .line 984
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 985
    .line 986
    .line 987
    move-result-object v5

    .line 988
    const/4 v6, 0x0

    .line 989
    invoke-virtual {v1, v5, v3, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 990
    .line 991
    .line 992
    move-result-object v3

    .line 993
    check-cast v3, Luk0/c0;

    .line 994
    .line 995
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 996
    .line 997
    .line 998
    move-result-object v0

    .line 999
    const-class v5, Luk0/b0;

    .line 1000
    .line 1001
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v5

    .line 1005
    invoke-virtual {v1, v5, v0, v6}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v0

    .line 1009
    check-cast v0, Luk0/b0;

    .line 1010
    .line 1011
    const-class v1, Lvk0/s0;

    .line 1012
    .line 1013
    invoke-virtual {v4, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v1

    .line 1017
    invoke-direct {v2, v3, v0, v1}, Lwk0/z1;-><init>(Luk0/c0;Luk0/b0;Lhy0/d;)V

    .line 1018
    .line 1019
    .line 1020
    return-object v2

    .line 1021
    :pswitch_b
    move-object/from16 v1, p1

    .line 1022
    .line 1023
    check-cast v1, Lk21/a;

    .line 1024
    .line 1025
    move-object/from16 v2, p2

    .line 1026
    .line 1027
    check-cast v2, Lg21/a;

    .line 1028
    .line 1029
    const-string v3, "$this$scopedViewModel"

    .line 1030
    .line 1031
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1032
    .line 1033
    .line 1034
    const-string v3, "it"

    .line 1035
    .line 1036
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1037
    .line 1038
    .line 1039
    new-instance v4, Lwk0/l2;

    .line 1040
    .line 1041
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1042
    .line 1043
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1044
    .line 1045
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v0

    .line 1049
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1050
    .line 1051
    const-class v3, Luk0/b0;

    .line 1052
    .line 1053
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v3

    .line 1057
    const/4 v5, 0x0

    .line 1058
    invoke-virtual {v1, v3, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v0

    .line 1062
    check-cast v0, Luk0/b0;

    .line 1063
    .line 1064
    const-class v3, Lro0/e;

    .line 1065
    .line 1066
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v3

    .line 1070
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v3

    .line 1074
    move-object v6, v3

    .line 1075
    check-cast v6, Lro0/e;

    .line 1076
    .line 1077
    const-class v3, Luk0/f0;

    .line 1078
    .line 1079
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1080
    .line 1081
    .line 1082
    move-result-object v3

    .line 1083
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v3

    .line 1087
    move-object v7, v3

    .line 1088
    check-cast v7, Luk0/f0;

    .line 1089
    .line 1090
    const-class v3, Luk0/x;

    .line 1091
    .line 1092
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v3

    .line 1096
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v3

    .line 1100
    move-object v8, v3

    .line 1101
    check-cast v8, Luk0/x;

    .line 1102
    .line 1103
    const-class v3, Luk0/f;

    .line 1104
    .line 1105
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v3

    .line 1109
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v3

    .line 1113
    move-object v9, v3

    .line 1114
    check-cast v9, Luk0/f;

    .line 1115
    .line 1116
    const-class v3, Luk0/l0;

    .line 1117
    .line 1118
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v3

    .line 1122
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v3

    .line 1126
    move-object v10, v3

    .line 1127
    check-cast v10, Luk0/l0;

    .line 1128
    .line 1129
    const-class v3, Lro0/a;

    .line 1130
    .line 1131
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1132
    .line 1133
    .line 1134
    move-result-object v3

    .line 1135
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1136
    .line 1137
    .line 1138
    move-result-object v3

    .line 1139
    move-object v11, v3

    .line 1140
    check-cast v11, Lro0/a;

    .line 1141
    .line 1142
    const-class v3, Ljn0/c;

    .line 1143
    .line 1144
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v3

    .line 1148
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v3

    .line 1152
    move-object v12, v3

    .line 1153
    check-cast v12, Ljn0/c;

    .line 1154
    .line 1155
    const-class v3, Lsf0/a;

    .line 1156
    .line 1157
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v2

    .line 1161
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v1

    .line 1165
    move-object v13, v1

    .line 1166
    check-cast v13, Lsf0/a;

    .line 1167
    .line 1168
    move-object v5, v0

    .line 1169
    invoke-direct/range {v4 .. v13}, Lwk0/l2;-><init>(Luk0/b0;Lro0/e;Luk0/f0;Luk0/x;Luk0/f;Luk0/l0;Lro0/a;Ljn0/c;Lsf0/a;)V

    .line 1170
    .line 1171
    .line 1172
    return-object v4

    .line 1173
    :pswitch_c
    move-object/from16 v1, p1

    .line 1174
    .line 1175
    check-cast v1, Lk21/a;

    .line 1176
    .line 1177
    move-object/from16 v2, p2

    .line 1178
    .line 1179
    check-cast v2, Lg21/a;

    .line 1180
    .line 1181
    const-string v3, "$this$scopedViewModel"

    .line 1182
    .line 1183
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1184
    .line 1185
    .line 1186
    const-string v3, "it"

    .line 1187
    .line 1188
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1189
    .line 1190
    .line 1191
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1192
    .line 1193
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1194
    .line 1195
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1196
    .line 1197
    .line 1198
    move-result-object v0

    .line 1199
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1200
    .line 1201
    const-class v3, Luk0/b0;

    .line 1202
    .line 1203
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v3

    .line 1207
    const/4 v4, 0x0

    .line 1208
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v0

    .line 1212
    move-object v6, v0

    .line 1213
    check-cast v6, Luk0/b0;

    .line 1214
    .line 1215
    const-class v0, Lpp0/z;

    .line 1216
    .line 1217
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1218
    .line 1219
    .line 1220
    move-result-object v0

    .line 1221
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v0

    .line 1225
    move-object v7, v0

    .line 1226
    check-cast v7, Lpp0/z;

    .line 1227
    .line 1228
    const-class v0, Lnn0/d0;

    .line 1229
    .line 1230
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v0

    .line 1234
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v0

    .line 1238
    move-object v10, v0

    .line 1239
    check-cast v10, Lnn0/d0;

    .line 1240
    .line 1241
    const-class v0, Luk0/i0;

    .line 1242
    .line 1243
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v0

    .line 1247
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v0

    .line 1251
    move-object v8, v0

    .line 1252
    check-cast v8, Luk0/i0;

    .line 1253
    .line 1254
    const-class v0, Lkf0/k;

    .line 1255
    .line 1256
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v0

    .line 1260
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v0

    .line 1264
    move-object v9, v0

    .line 1265
    check-cast v9, Lkf0/k;

    .line 1266
    .line 1267
    new-instance v5, Lwk0/b1;

    .line 1268
    .line 1269
    invoke-direct/range {v5 .. v10}, Lwk0/b1;-><init>(Luk0/b0;Lpp0/z;Luk0/i0;Lkf0/k;Lnn0/d0;)V

    .line 1270
    .line 1271
    .line 1272
    return-object v5

    .line 1273
    :pswitch_d
    move-object/from16 v1, p1

    .line 1274
    .line 1275
    check-cast v1, Lk21/a;

    .line 1276
    .line 1277
    move-object/from16 v2, p2

    .line 1278
    .line 1279
    check-cast v2, Lg21/a;

    .line 1280
    .line 1281
    const-string v3, "$this$scopedViewModel"

    .line 1282
    .line 1283
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1284
    .line 1285
    .line 1286
    const-string v3, "it"

    .line 1287
    .line 1288
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1289
    .line 1290
    .line 1291
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1292
    .line 1293
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1294
    .line 1295
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v0

    .line 1299
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1300
    .line 1301
    const-class v3, Luk0/b0;

    .line 1302
    .line 1303
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1304
    .line 1305
    .line 1306
    move-result-object v3

    .line 1307
    const/4 v4, 0x0

    .line 1308
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v0

    .line 1312
    check-cast v0, Luk0/b0;

    .line 1313
    .line 1314
    const-class v3, Lkf0/k;

    .line 1315
    .line 1316
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v3

    .line 1320
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v3

    .line 1324
    check-cast v3, Lkf0/k;

    .line 1325
    .line 1326
    const-class v5, Lnn0/v;

    .line 1327
    .line 1328
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1329
    .line 1330
    .line 1331
    move-result-object v2

    .line 1332
    invoke-virtual {v1, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v1

    .line 1336
    check-cast v1, Lnn0/v;

    .line 1337
    .line 1338
    new-instance v2, Lwk0/e1;

    .line 1339
    .line 1340
    invoke-direct {v2, v0, v1, v3}, Lwk0/e1;-><init>(Luk0/b0;Lnn0/v;Lkf0/k;)V

    .line 1341
    .line 1342
    .line 1343
    return-object v2

    .line 1344
    :pswitch_e
    move-object/from16 v1, p1

    .line 1345
    .line 1346
    check-cast v1, Lk21/a;

    .line 1347
    .line 1348
    move-object/from16 v2, p2

    .line 1349
    .line 1350
    check-cast v2, Lg21/a;

    .line 1351
    .line 1352
    const-string v3, "$this$scopedViewModel"

    .line 1353
    .line 1354
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1355
    .line 1356
    .line 1357
    const-string v3, "it"

    .line 1358
    .line 1359
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1360
    .line 1361
    .line 1362
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1363
    .line 1364
    const-class v3, Luk0/h0;

    .line 1365
    .line 1366
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1367
    .line 1368
    .line 1369
    move-result-object v3

    .line 1370
    const/4 v4, 0x0

    .line 1371
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1372
    .line 1373
    .line 1374
    move-result-object v3

    .line 1375
    move-object v6, v3

    .line 1376
    check-cast v6, Luk0/h0;

    .line 1377
    .line 1378
    const-class v3, Luk0/k0;

    .line 1379
    .line 1380
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v3

    .line 1384
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v3

    .line 1388
    move-object v7, v3

    .line 1389
    check-cast v7, Luk0/k0;

    .line 1390
    .line 1391
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1392
    .line 1393
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1394
    .line 1395
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v3

    .line 1399
    const-class v5, Luk0/b0;

    .line 1400
    .line 1401
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1402
    .line 1403
    .line 1404
    move-result-object v5

    .line 1405
    invoke-virtual {v1, v5, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v3

    .line 1409
    move-object v8, v3

    .line 1410
    check-cast v8, Luk0/b0;

    .line 1411
    .line 1412
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1413
    .line 1414
    .line 1415
    move-result-object v3

    .line 1416
    const-class v5, Luk0/r0;

    .line 1417
    .line 1418
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v5

    .line 1422
    invoke-virtual {v1, v5, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v3

    .line 1426
    move-object v10, v3

    .line 1427
    check-cast v10, Luk0/r0;

    .line 1428
    .line 1429
    const-class v3, Lij0/a;

    .line 1430
    .line 1431
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1432
    .line 1433
    .line 1434
    move-result-object v3

    .line 1435
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v3

    .line 1439
    move-object v11, v3

    .line 1440
    check-cast v11, Lij0/a;

    .line 1441
    .line 1442
    const-class v3, Llk0/f;

    .line 1443
    .line 1444
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v3

    .line 1448
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1449
    .line 1450
    .line 1451
    move-result-object v3

    .line 1452
    move-object v12, v3

    .line 1453
    check-cast v12, Llk0/f;

    .line 1454
    .line 1455
    const-class v3, Lgl0/f;

    .line 1456
    .line 1457
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v3

    .line 1461
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v3

    .line 1465
    move-object v14, v3

    .line 1466
    check-cast v14, Lgl0/f;

    .line 1467
    .line 1468
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1469
    .line 1470
    .line 1471
    move-result-object v3

    .line 1472
    const-class v5, Luk0/d;

    .line 1473
    .line 1474
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v5

    .line 1478
    invoke-virtual {v1, v5, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1479
    .line 1480
    .line 1481
    move-result-object v3

    .line 1482
    move-object v15, v3

    .line 1483
    check-cast v15, Luk0/d;

    .line 1484
    .line 1485
    const-class v3, Luk0/u;

    .line 1486
    .line 1487
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v3

    .line 1491
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v3

    .line 1495
    move-object/from16 v16, v3

    .line 1496
    .line 1497
    check-cast v16, Luk0/u;

    .line 1498
    .line 1499
    const-class v3, Lpp0/z;

    .line 1500
    .line 1501
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1502
    .line 1503
    .line 1504
    move-result-object v3

    .line 1505
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v3

    .line 1509
    move-object v13, v3

    .line 1510
    check-cast v13, Lpp0/z;

    .line 1511
    .line 1512
    const-class v3, Lrq0/f;

    .line 1513
    .line 1514
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1515
    .line 1516
    .line 1517
    move-result-object v3

    .line 1518
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1519
    .line 1520
    .line 1521
    move-result-object v3

    .line 1522
    move-object/from16 v18, v3

    .line 1523
    .line 1524
    check-cast v18, Lrq0/f;

    .line 1525
    .line 1526
    const-class v3, Ljn0/c;

    .line 1527
    .line 1528
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1529
    .line 1530
    .line 1531
    move-result-object v3

    .line 1532
    invoke-virtual {v1, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1533
    .line 1534
    .line 1535
    move-result-object v3

    .line 1536
    move-object/from16 v19, v3

    .line 1537
    .line 1538
    check-cast v19, Ljn0/c;

    .line 1539
    .line 1540
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1541
    .line 1542
    .line 1543
    move-result-object v0

    .line 1544
    const-class v3, Luk0/c0;

    .line 1545
    .line 1546
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1547
    .line 1548
    .line 1549
    move-result-object v3

    .line 1550
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1551
    .line 1552
    .line 1553
    move-result-object v0

    .line 1554
    move-object/from16 v20, v0

    .line 1555
    .line 1556
    check-cast v20, Luk0/c0;

    .line 1557
    .line 1558
    const-class v0, Lkf0/k;

    .line 1559
    .line 1560
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1561
    .line 1562
    .line 1563
    move-result-object v0

    .line 1564
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1565
    .line 1566
    .line 1567
    move-result-object v0

    .line 1568
    move-object v9, v0

    .line 1569
    check-cast v9, Lkf0/k;

    .line 1570
    .line 1571
    const-class v0, Luk0/t0;

    .line 1572
    .line 1573
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1574
    .line 1575
    .line 1576
    move-result-object v0

    .line 1577
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1578
    .line 1579
    .line 1580
    move-result-object v0

    .line 1581
    move-object/from16 v17, v0

    .line 1582
    .line 1583
    check-cast v17, Luk0/t0;

    .line 1584
    .line 1585
    const-class v0, Luk0/n0;

    .line 1586
    .line 1587
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v0

    .line 1591
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1592
    .line 1593
    .line 1594
    move-result-object v0

    .line 1595
    move-object/from16 v21, v0

    .line 1596
    .line 1597
    check-cast v21, Luk0/n0;

    .line 1598
    .line 1599
    const-class v0, Lpp0/l0;

    .line 1600
    .line 1601
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v0

    .line 1605
    invoke-virtual {v1, v0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1606
    .line 1607
    .line 1608
    move-result-object v0

    .line 1609
    move-object/from16 v22, v0

    .line 1610
    .line 1611
    check-cast v22, Lpp0/l0;

    .line 1612
    .line 1613
    new-instance v5, Lwk0/s1;

    .line 1614
    .line 1615
    invoke-direct/range {v5 .. v22}, Lwk0/s1;-><init>(Luk0/h0;Luk0/k0;Luk0/b0;Lkf0/k;Luk0/r0;Lij0/a;Llk0/f;Lpp0/z;Lgl0/f;Luk0/d;Luk0/u;Luk0/t0;Lrq0/f;Ljn0/c;Luk0/c0;Luk0/n0;Lpp0/l0;)V

    .line 1616
    .line 1617
    .line 1618
    return-object v5

    .line 1619
    :pswitch_f
    move-object/from16 v1, p1

    .line 1620
    .line 1621
    check-cast v1, Lk21/a;

    .line 1622
    .line 1623
    move-object/from16 v2, p2

    .line 1624
    .line 1625
    check-cast v2, Lg21/a;

    .line 1626
    .line 1627
    const-string v3, "$this$scopedFactory"

    .line 1628
    .line 1629
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1630
    .line 1631
    .line 1632
    const-string v3, "it"

    .line 1633
    .line 1634
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1635
    .line 1636
    .line 1637
    new-instance v2, Luk0/c0;

    .line 1638
    .line 1639
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1640
    .line 1641
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1642
    .line 1643
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1644
    .line 1645
    .line 1646
    move-result-object v0

    .line 1647
    const-class v3, Luk0/v;

    .line 1648
    .line 1649
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1650
    .line 1651
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1652
    .line 1653
    .line 1654
    move-result-object v3

    .line 1655
    const/4 v4, 0x0

    .line 1656
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1657
    .line 1658
    .line 1659
    move-result-object v0

    .line 1660
    check-cast v0, Luk0/v;

    .line 1661
    .line 1662
    invoke-direct {v2, v0}, Luk0/c0;-><init>(Luk0/v;)V

    .line 1663
    .line 1664
    .line 1665
    return-object v2

    .line 1666
    :pswitch_10
    move-object/from16 v1, p1

    .line 1667
    .line 1668
    check-cast v1, Lk21/a;

    .line 1669
    .line 1670
    move-object/from16 v2, p2

    .line 1671
    .line 1672
    check-cast v2, Lg21/a;

    .line 1673
    .line 1674
    const-string v3, "$this$scopedFactory"

    .line 1675
    .line 1676
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1677
    .line 1678
    .line 1679
    const-string v3, "it"

    .line 1680
    .line 1681
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1682
    .line 1683
    .line 1684
    new-instance v2, Luk0/d;

    .line 1685
    .line 1686
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1687
    .line 1688
    const-class v4, Llk0/a;

    .line 1689
    .line 1690
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1691
    .line 1692
    .line 1693
    move-result-object v4

    .line 1694
    const/4 v5, 0x0

    .line 1695
    invoke-virtual {v1, v4, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1696
    .line 1697
    .line 1698
    move-result-object v4

    .line 1699
    check-cast v4, Llk0/a;

    .line 1700
    .line 1701
    const-class v6, Llk0/f;

    .line 1702
    .line 1703
    invoke-virtual {v3, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1704
    .line 1705
    .line 1706
    move-result-object v6

    .line 1707
    invoke-virtual {v1, v6, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1708
    .line 1709
    .line 1710
    move-result-object v6

    .line 1711
    check-cast v6, Llk0/f;

    .line 1712
    .line 1713
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1714
    .line 1715
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1716
    .line 1717
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v0

    .line 1721
    const-class v7, Luk0/b0;

    .line 1722
    .line 1723
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1724
    .line 1725
    .line 1726
    move-result-object v7

    .line 1727
    invoke-virtual {v1, v7, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1728
    .line 1729
    .line 1730
    move-result-object v0

    .line 1731
    check-cast v0, Luk0/b0;

    .line 1732
    .line 1733
    const-class v7, Llk0/k;

    .line 1734
    .line 1735
    invoke-virtual {v3, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1736
    .line 1737
    .line 1738
    move-result-object v3

    .line 1739
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1740
    .line 1741
    .line 1742
    move-result-object v1

    .line 1743
    check-cast v1, Llk0/k;

    .line 1744
    .line 1745
    invoke-direct {v2, v4, v6, v0, v1}, Luk0/d;-><init>(Llk0/a;Llk0/f;Luk0/b0;Llk0/k;)V

    .line 1746
    .line 1747
    .line 1748
    return-object v2

    .line 1749
    :pswitch_11
    move-object/from16 v1, p1

    .line 1750
    .line 1751
    check-cast v1, Lk21/a;

    .line 1752
    .line 1753
    move-object/from16 v2, p2

    .line 1754
    .line 1755
    check-cast v2, Lg21/a;

    .line 1756
    .line 1757
    const-string v3, "$this$scopedViewModel"

    .line 1758
    .line 1759
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1760
    .line 1761
    .line 1762
    const-string v3, "it"

    .line 1763
    .line 1764
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1765
    .line 1766
    .line 1767
    new-instance v4, Lwk0/p0;

    .line 1768
    .line 1769
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1770
    .line 1771
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1772
    .line 1773
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v0

    .line 1777
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1778
    .line 1779
    const-class v3, Luk0/b0;

    .line 1780
    .line 1781
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1782
    .line 1783
    .line 1784
    move-result-object v3

    .line 1785
    const/4 v5, 0x0

    .line 1786
    invoke-virtual {v1, v3, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1787
    .line 1788
    .line 1789
    move-result-object v0

    .line 1790
    check-cast v0, Luk0/b0;

    .line 1791
    .line 1792
    const-class v3, Luk0/g0;

    .line 1793
    .line 1794
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1795
    .line 1796
    .line 1797
    move-result-object v3

    .line 1798
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1799
    .line 1800
    .line 1801
    move-result-object v3

    .line 1802
    move-object v6, v3

    .line 1803
    check-cast v6, Luk0/g0;

    .line 1804
    .line 1805
    const-class v3, Lck0/d;

    .line 1806
    .line 1807
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v3

    .line 1811
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1812
    .line 1813
    .line 1814
    move-result-object v3

    .line 1815
    move-object v7, v3

    .line 1816
    check-cast v7, Lck0/d;

    .line 1817
    .line 1818
    const-class v3, Luk0/p0;

    .line 1819
    .line 1820
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1821
    .line 1822
    .line 1823
    move-result-object v3

    .line 1824
    invoke-virtual {v1, v3, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1825
    .line 1826
    .line 1827
    move-result-object v3

    .line 1828
    move-object v8, v3

    .line 1829
    check-cast v8, Luk0/p0;

    .line 1830
    .line 1831
    const-class v3, Lrq0/d;

    .line 1832
    .line 1833
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1834
    .line 1835
    .line 1836
    move-result-object v2

    .line 1837
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1838
    .line 1839
    .line 1840
    move-result-object v1

    .line 1841
    move-object v9, v1

    .line 1842
    check-cast v9, Lrq0/d;

    .line 1843
    .line 1844
    move-object v5, v0

    .line 1845
    invoke-direct/range {v4 .. v9}, Lwk0/p0;-><init>(Luk0/b0;Luk0/g0;Lck0/d;Luk0/p0;Lrq0/d;)V

    .line 1846
    .line 1847
    .line 1848
    return-object v4

    .line 1849
    :pswitch_12
    move-object/from16 v1, p1

    .line 1850
    .line 1851
    check-cast v1, Lk21/a;

    .line 1852
    .line 1853
    move-object/from16 v2, p2

    .line 1854
    .line 1855
    check-cast v2, Lg21/a;

    .line 1856
    .line 1857
    const-string v3, "$this$scopedFactory"

    .line 1858
    .line 1859
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1860
    .line 1861
    .line 1862
    const-string v3, "it"

    .line 1863
    .line 1864
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1865
    .line 1866
    .line 1867
    new-instance v2, Luk0/j;

    .line 1868
    .line 1869
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1870
    .line 1871
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1872
    .line 1873
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v0

    .line 1877
    const-class v3, Luk0/r;

    .line 1878
    .line 1879
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1880
    .line 1881
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1882
    .line 1883
    .line 1884
    move-result-object v3

    .line 1885
    const/4 v4, 0x0

    .line 1886
    invoke-virtual {v1, v3, v0, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1887
    .line 1888
    .line 1889
    move-result-object v0

    .line 1890
    check-cast v0, Luk0/r;

    .line 1891
    .line 1892
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 1893
    .line 1894
    .line 1895
    return-object v2

    .line 1896
    :pswitch_13
    move-object/from16 v1, p1

    .line 1897
    .line 1898
    check-cast v1, Lk21/a;

    .line 1899
    .line 1900
    move-object/from16 v2, p2

    .line 1901
    .line 1902
    check-cast v2, Lg21/a;

    .line 1903
    .line 1904
    const-string v3, "$this$scopedViewModel"

    .line 1905
    .line 1906
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1907
    .line 1908
    .line 1909
    const-string v3, "it"

    .line 1910
    .line 1911
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1912
    .line 1913
    .line 1914
    iget-object v0, v0, Ltk0/a;->e:Leo0/b;

    .line 1915
    .line 1916
    iget-object v0, v0, Leo0/b;->b:Ljava/lang/String;

    .line 1917
    .line 1918
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1919
    .line 1920
    .line 1921
    move-result-object v2

    .line 1922
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1923
    .line 1924
    const-class v4, Luk0/b0;

    .line 1925
    .line 1926
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1927
    .line 1928
    .line 1929
    move-result-object v4

    .line 1930
    const/4 v5, 0x0

    .line 1931
    invoke-virtual {v1, v4, v2, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1932
    .line 1933
    .line 1934
    move-result-object v2

    .line 1935
    move-object v7, v2

    .line 1936
    check-cast v7, Luk0/b0;

    .line 1937
    .line 1938
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 1939
    .line 1940
    .line 1941
    move-result-object v2

    .line 1942
    const-class v4, Luk0/r0;

    .line 1943
    .line 1944
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1945
    .line 1946
    .line 1947
    move-result-object v4

    .line 1948
    invoke-virtual {v1, v4, v2, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1949
    .line 1950
    .line 1951
    move-result-object v2

    .line 1952
    move-object v9, v2

    .line 1953
    check-cast v9, Luk0/r0;

    .line 1954
    .line 1955
    const-class v2, Lro0/e;

    .line 1956
    .line 1957
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1958
    .line 1959
    .line 1960
    move-result-object v2

    .line 1961
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1962
    .line 1963
    .line 1964
    move-result-object v2

    .line 1965
    move-object v10, v2

    .line 1966
    check-cast v10, Lro0/e;

    .line 1967
    .line 1968
    const-class v2, Luk0/m0;

    .line 1969
    .line 1970
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1971
    .line 1972
    .line 1973
    move-result-object v2

    .line 1974
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1975
    .line 1976
    .line 1977
    move-result-object v2

    .line 1978
    move-object v11, v2

    .line 1979
    check-cast v11, Luk0/m0;

    .line 1980
    .line 1981
    const-class v2, Luk0/l0;

    .line 1982
    .line 1983
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1984
    .line 1985
    .line 1986
    move-result-object v2

    .line 1987
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1988
    .line 1989
    .line 1990
    move-result-object v2

    .line 1991
    move-object v12, v2

    .line 1992
    check-cast v12, Luk0/l0;

    .line 1993
    .line 1994
    const-class v2, Lij0/a;

    .line 1995
    .line 1996
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1997
    .line 1998
    .line 1999
    move-result-object v2

    .line 2000
    invoke-virtual {v1, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 2001
    .line 2002
    .line 2003
    move-result-object v2

    .line 2004
    move-object v13, v2

    .line 2005
    check-cast v13, Lij0/a;

    .line 2006
    .line 2007
    invoke-static {v0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 2008
    .line 2009
    .line 2010
    move-result-object v0

    .line 2011
    const-class v2, Luk0/c0;

    .line 2012
    .line 2013
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2014
    .line 2015
    .line 2016
    move-result-object v2

    .line 2017
    invoke-virtual {v1, v2, v0, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 2018
    .line 2019
    .line 2020
    move-result-object v0

    .line 2021
    move-object v8, v0

    .line 2022
    check-cast v8, Luk0/c0;

    .line 2023
    .line 2024
    new-instance v6, Lwk0/q;

    .line 2025
    .line 2026
    invoke-direct/range {v6 .. v13}, Lwk0/q;-><init>(Luk0/b0;Luk0/c0;Luk0/r0;Lro0/e;Luk0/m0;Luk0/l0;Lij0/a;)V

    .line 2027
    .line 2028
    .line 2029
    return-object v6

    .line 2030
    nop

    .line 2031
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
