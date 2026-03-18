.class public final Lkm0/a;
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
    iput p1, p0, Lkm0/a;->d:I

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
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lkm0/a;->d:I

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
    const-string v0, "it"

    .line 22
    .line 23
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Llz/n;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_0
    move-object/from16 v0, p1

    .line 33
    .line 34
    check-cast v0, Lk21/a;

    .line 35
    .line 36
    move-object/from16 v1, p2

    .line 37
    .line 38
    check-cast v1, Lg21/a;

    .line 39
    .line 40
    const-string v2, "$this$factory"

    .line 41
    .line 42
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    const-string v2, "it"

    .line 46
    .line 47
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 51
    .line 52
    const-class v2, Lbn0/g;

    .line 53
    .line 54
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    const-class v4, Llz/e;

    .line 64
    .line 65
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    const-class v5, Ljr0/c;

    .line 74
    .line 75
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    check-cast v0, Ljr0/c;

    .line 84
    .line 85
    check-cast v4, Llz/e;

    .line 86
    .line 87
    check-cast v2, Lbn0/g;

    .line 88
    .line 89
    new-instance v1, Llz/i;

    .line 90
    .line 91
    invoke-direct {v1, v2, v4, v0}, Llz/i;-><init>(Lbn0/g;Llz/e;Ljr0/c;)V

    .line 92
    .line 93
    .line 94
    return-object v1

    .line 95
    :pswitch_1
    move-object/from16 v0, p1

    .line 96
    .line 97
    check-cast v0, Lk21/a;

    .line 98
    .line 99
    move-object/from16 v1, p2

    .line 100
    .line 101
    check-cast v1, Lg21/a;

    .line 102
    .line 103
    const-string v2, "$this$factory"

    .line 104
    .line 105
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const-string v2, "it"

    .line 109
    .line 110
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 114
    .line 115
    const-class v2, Lkf0/m;

    .line 116
    .line 117
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    const/4 v3, 0x0

    .line 122
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    const-class v4, Lsf0/a;

    .line 127
    .line 128
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    const-class v5, Ljn0/c;

    .line 137
    .line 138
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 139
    .line 140
    .line 141
    move-result-object v5

    .line 142
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v5

    .line 146
    const-class v6, Lwq0/e0;

    .line 147
    .line 148
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    const-class v7, Lkf0/j0;

    .line 157
    .line 158
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    const-class v8, Ljz/m;

    .line 167
    .line 168
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 169
    .line 170
    .line 171
    move-result-object v8

    .line 172
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    const-class v9, Lko0/f;

    .line 177
    .line 178
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v9

    .line 186
    const-class v10, Llz/n;

    .line 187
    .line 188
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    move-object/from16 v18, v0

    .line 197
    .line 198
    check-cast v18, Llz/n;

    .line 199
    .line 200
    move-object/from16 v17, v9

    .line 201
    .line 202
    check-cast v17, Lko0/f;

    .line 203
    .line 204
    move-object/from16 v16, v8

    .line 205
    .line 206
    check-cast v16, Ljz/m;

    .line 207
    .line 208
    move-object v15, v7

    .line 209
    check-cast v15, Lkf0/j0;

    .line 210
    .line 211
    move-object v14, v6

    .line 212
    check-cast v14, Lwq0/e0;

    .line 213
    .line 214
    move-object v13, v5

    .line 215
    check-cast v13, Ljn0/c;

    .line 216
    .line 217
    move-object v12, v4

    .line 218
    check-cast v12, Lsf0/a;

    .line 219
    .line 220
    move-object v11, v2

    .line 221
    check-cast v11, Lkf0/m;

    .line 222
    .line 223
    new-instance v10, Llz/v;

    .line 224
    .line 225
    invoke-direct/range {v10 .. v18}, Llz/v;-><init>(Lkf0/m;Lsf0/a;Ljn0/c;Lwq0/e0;Lkf0/j0;Ljz/m;Lko0/f;Llz/n;)V

    .line 226
    .line 227
    .line 228
    return-object v10

    .line 229
    :pswitch_2
    move-object/from16 v0, p1

    .line 230
    .line 231
    check-cast v0, Lk21/a;

    .line 232
    .line 233
    move-object/from16 v1, p2

    .line 234
    .line 235
    check-cast v1, Lg21/a;

    .line 236
    .line 237
    const-string v2, "$this$factory"

    .line 238
    .line 239
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    const-string v2, "it"

    .line 243
    .line 244
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 248
    .line 249
    const-class v2, Lkf0/m;

    .line 250
    .line 251
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    const/4 v3, 0x0

    .line 256
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v2

    .line 260
    const-class v4, Lsf0/a;

    .line 261
    .line 262
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 263
    .line 264
    .line 265
    move-result-object v4

    .line 266
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    const-class v5, Ljn0/c;

    .line 271
    .line 272
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    const-class v6, Lkf0/j0;

    .line 281
    .line 282
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 283
    .line 284
    .line 285
    move-result-object v6

    .line 286
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v6

    .line 290
    const-class v7, Ljz/m;

    .line 291
    .line 292
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 293
    .line 294
    .line 295
    move-result-object v7

    .line 296
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v7

    .line 300
    const-class v8, Ljr0/f;

    .line 301
    .line 302
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    move-object v14, v0

    .line 311
    check-cast v14, Ljr0/f;

    .line 312
    .line 313
    move-object v13, v7

    .line 314
    check-cast v13, Ljz/m;

    .line 315
    .line 316
    move-object v12, v6

    .line 317
    check-cast v12, Lkf0/j0;

    .line 318
    .line 319
    move-object v11, v5

    .line 320
    check-cast v11, Ljn0/c;

    .line 321
    .line 322
    move-object v10, v4

    .line 323
    check-cast v10, Lsf0/a;

    .line 324
    .line 325
    move-object v9, v2

    .line 326
    check-cast v9, Lkf0/m;

    .line 327
    .line 328
    new-instance v8, Llz/s;

    .line 329
    .line 330
    invoke-direct/range {v8 .. v14}, Llz/s;-><init>(Lkf0/m;Lsf0/a;Ljn0/c;Lkf0/j0;Ljz/m;Ljr0/f;)V

    .line 331
    .line 332
    .line 333
    return-object v8

    .line 334
    :pswitch_3
    move-object/from16 v0, p1

    .line 335
    .line 336
    check-cast v0, Lk21/a;

    .line 337
    .line 338
    move-object/from16 v1, p2

    .line 339
    .line 340
    check-cast v1, Lg21/a;

    .line 341
    .line 342
    const-string v2, "$this$factory"

    .line 343
    .line 344
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    const-string v2, "it"

    .line 348
    .line 349
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 353
    .line 354
    const-class v2, Lkf0/m;

    .line 355
    .line 356
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 357
    .line 358
    .line 359
    move-result-object v2

    .line 360
    const/4 v3, 0x0

    .line 361
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v2

    .line 365
    const-class v4, Lsf0/a;

    .line 366
    .line 367
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 368
    .line 369
    .line 370
    move-result-object v4

    .line 371
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v4

    .line 375
    const-class v5, Ljn0/c;

    .line 376
    .line 377
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 378
    .line 379
    .line 380
    move-result-object v5

    .line 381
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v5

    .line 385
    const-class v6, Lwq0/e0;

    .line 386
    .line 387
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 388
    .line 389
    .line 390
    move-result-object v6

    .line 391
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v6

    .line 395
    const-class v7, Lkf0/j0;

    .line 396
    .line 397
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 398
    .line 399
    .line 400
    move-result-object v7

    .line 401
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v7

    .line 405
    const-class v8, Ljz/m;

    .line 406
    .line 407
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 408
    .line 409
    .line 410
    move-result-object v8

    .line 411
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v8

    .line 415
    const-class v9, Lko0/f;

    .line 416
    .line 417
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 418
    .line 419
    .line 420
    move-result-object v9

    .line 421
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v9

    .line 425
    const-class v10, Ljr0/f;

    .line 426
    .line 427
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    move-object/from16 v18, v0

    .line 436
    .line 437
    check-cast v18, Ljr0/f;

    .line 438
    .line 439
    move-object/from16 v17, v9

    .line 440
    .line 441
    check-cast v17, Lko0/f;

    .line 442
    .line 443
    move-object/from16 v16, v8

    .line 444
    .line 445
    check-cast v16, Ljz/m;

    .line 446
    .line 447
    move-object v15, v7

    .line 448
    check-cast v15, Lkf0/j0;

    .line 449
    .line 450
    move-object v14, v6

    .line 451
    check-cast v14, Lwq0/e0;

    .line 452
    .line 453
    move-object v13, v5

    .line 454
    check-cast v13, Ljn0/c;

    .line 455
    .line 456
    move-object v12, v4

    .line 457
    check-cast v12, Lsf0/a;

    .line 458
    .line 459
    move-object v11, v2

    .line 460
    check-cast v11, Lkf0/m;

    .line 461
    .line 462
    new-instance v10, Llz/q;

    .line 463
    .line 464
    invoke-direct/range {v10 .. v18}, Llz/q;-><init>(Lkf0/m;Lsf0/a;Ljn0/c;Lwq0/e0;Lkf0/j0;Ljz/m;Lko0/f;Ljr0/f;)V

    .line 465
    .line 466
    .line 467
    return-object v10

    .line 468
    :pswitch_4
    move-object/from16 v0, p1

    .line 469
    .line 470
    check-cast v0, Lk21/a;

    .line 471
    .line 472
    move-object/from16 v1, p2

    .line 473
    .line 474
    check-cast v1, Lg21/a;

    .line 475
    .line 476
    const-string v2, "$this$factory"

    .line 477
    .line 478
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    const-string v2, "it"

    .line 482
    .line 483
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    const-class v1, Llz/a;

    .line 487
    .line 488
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 489
    .line 490
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    const/4 v2, 0x0

    .line 495
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    check-cast v0, Llz/a;

    .line 500
    .line 501
    new-instance v1, Llz/l;

    .line 502
    .line 503
    invoke-direct {v1, v0}, Llz/l;-><init>(Llz/a;)V

    .line 504
    .line 505
    .line 506
    return-object v1

    .line 507
    :pswitch_5
    move-object/from16 v0, p1

    .line 508
    .line 509
    check-cast v0, Lk21/a;

    .line 510
    .line 511
    move-object/from16 v1, p2

    .line 512
    .line 513
    check-cast v1, Lg21/a;

    .line 514
    .line 515
    const-string v2, "$this$factory"

    .line 516
    .line 517
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    const-string v2, "it"

    .line 521
    .line 522
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 523
    .line 524
    .line 525
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 526
    .line 527
    const-class v2, Ljz/m;

    .line 528
    .line 529
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 530
    .line 531
    .line 532
    move-result-object v2

    .line 533
    const/4 v3, 0x0

    .line 534
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 535
    .line 536
    .line 537
    move-result-object v2

    .line 538
    const-class v4, Ljz/s;

    .line 539
    .line 540
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 541
    .line 542
    .line 543
    move-result-object v4

    .line 544
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    move-result-object v4

    .line 548
    const-class v5, Lkf0/z;

    .line 549
    .line 550
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 551
    .line 552
    .line 553
    move-result-object v5

    .line 554
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    move-result-object v5

    .line 558
    const-class v6, Llz/n;

    .line 559
    .line 560
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 561
    .line 562
    .line 563
    move-result-object v1

    .line 564
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    check-cast v0, Llz/n;

    .line 569
    .line 570
    check-cast v5, Lkf0/z;

    .line 571
    .line 572
    check-cast v4, Ljz/s;

    .line 573
    .line 574
    check-cast v2, Ljz/m;

    .line 575
    .line 576
    new-instance v1, Llz/e;

    .line 577
    .line 578
    invoke-direct {v1, v2, v4, v5, v0}, Llz/e;-><init>(Ljz/m;Ljz/s;Lkf0/z;Llz/n;)V

    .line 579
    .line 580
    .line 581
    return-object v1

    .line 582
    :pswitch_6
    move-object/from16 v0, p1

    .line 583
    .line 584
    check-cast v0, Lk21/a;

    .line 585
    .line 586
    move-object/from16 v1, p2

    .line 587
    .line 588
    check-cast v1, Lg21/a;

    .line 589
    .line 590
    const-string v2, "$this$factory"

    .line 591
    .line 592
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    const-string v2, "it"

    .line 596
    .line 597
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 598
    .line 599
    .line 600
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 601
    .line 602
    const-class v2, Ljz/s;

    .line 603
    .line 604
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 605
    .line 606
    .line 607
    move-result-object v2

    .line 608
    const/4 v3, 0x0

    .line 609
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 610
    .line 611
    .line 612
    move-result-object v2

    .line 613
    const-class v4, Llz/e;

    .line 614
    .line 615
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 616
    .line 617
    .line 618
    move-result-object v4

    .line 619
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v4

    .line 623
    const-class v5, Lkf0/b0;

    .line 624
    .line 625
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 626
    .line 627
    .line 628
    move-result-object v1

    .line 629
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 630
    .line 631
    .line 632
    move-result-object v0

    .line 633
    check-cast v0, Lkf0/b0;

    .line 634
    .line 635
    check-cast v4, Llz/e;

    .line 636
    .line 637
    check-cast v2, Ljz/s;

    .line 638
    .line 639
    new-instance v1, Llz/k;

    .line 640
    .line 641
    invoke-direct {v1, v2, v4, v0}, Llz/k;-><init>(Ljz/s;Llz/e;Lkf0/b0;)V

    .line 642
    .line 643
    .line 644
    return-object v1

    .line 645
    :pswitch_7
    move-object/from16 v0, p1

    .line 646
    .line 647
    check-cast v0, Lk21/a;

    .line 648
    .line 649
    move-object/from16 v1, p2

    .line 650
    .line 651
    check-cast v1, Lg21/a;

    .line 652
    .line 653
    const-string v2, "$this$factory"

    .line 654
    .line 655
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 656
    .line 657
    .line 658
    const-string v2, "it"

    .line 659
    .line 660
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 661
    .line 662
    .line 663
    const-class v1, Llz/k;

    .line 664
    .line 665
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 666
    .line 667
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 668
    .line 669
    .line 670
    move-result-object v1

    .line 671
    const/4 v2, 0x0

    .line 672
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v0

    .line 676
    check-cast v0, Llz/k;

    .line 677
    .line 678
    new-instance v1, Llz/g;

    .line 679
    .line 680
    invoke-direct {v1, v0}, Llz/g;-><init>(Llz/k;)V

    .line 681
    .line 682
    .line 683
    return-object v1

    .line 684
    :pswitch_8
    move-object/from16 v0, p1

    .line 685
    .line 686
    check-cast v0, Lk21/a;

    .line 687
    .line 688
    move-object/from16 v1, p2

    .line 689
    .line 690
    check-cast v1, Lg21/a;

    .line 691
    .line 692
    const-string v2, "$this$factory"

    .line 693
    .line 694
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 695
    .line 696
    .line 697
    const-string v2, "it"

    .line 698
    .line 699
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 700
    .line 701
    .line 702
    const-class v1, Ljz/s;

    .line 703
    .line 704
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 705
    .line 706
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 707
    .line 708
    .line 709
    move-result-object v1

    .line 710
    const/4 v2, 0x0

    .line 711
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v0

    .line 715
    check-cast v0, Ljz/s;

    .line 716
    .line 717
    new-instance v1, Llz/j;

    .line 718
    .line 719
    invoke-direct {v1, v0}, Llz/j;-><init>(Ljz/s;)V

    .line 720
    .line 721
    .line 722
    return-object v1

    .line 723
    :pswitch_9
    move-object/from16 v0, p1

    .line 724
    .line 725
    check-cast v0, Lk21/a;

    .line 726
    .line 727
    move-object/from16 v1, p2

    .line 728
    .line 729
    check-cast v1, Lg21/a;

    .line 730
    .line 731
    const-string v2, "$this$viewModel"

    .line 732
    .line 733
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    const-string v2, "it"

    .line 737
    .line 738
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 742
    .line 743
    const-class v2, Llt0/c;

    .line 744
    .line 745
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 746
    .line 747
    .line 748
    move-result-object v2

    .line 749
    const/4 v3, 0x0

    .line 750
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    move-result-object v2

    .line 754
    const-class v4, Ltr0/b;

    .line 755
    .line 756
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 757
    .line 758
    .line 759
    move-result-object v4

    .line 760
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v4

    .line 764
    const-class v5, Lbd0/c;

    .line 765
    .line 766
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 767
    .line 768
    .line 769
    move-result-object v1

    .line 770
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    move-result-object v0

    .line 774
    check-cast v0, Lbd0/c;

    .line 775
    .line 776
    check-cast v4, Ltr0/b;

    .line 777
    .line 778
    check-cast v2, Llt0/c;

    .line 779
    .line 780
    new-instance v1, Lnt0/k;

    .line 781
    .line 782
    invoke-direct {v1, v2, v4, v0}, Lnt0/k;-><init>(Llt0/c;Ltr0/b;Lbd0/c;)V

    .line 783
    .line 784
    .line 785
    return-object v1

    .line 786
    :pswitch_a
    move-object/from16 v0, p1

    .line 787
    .line 788
    check-cast v0, Lk21/a;

    .line 789
    .line 790
    move-object/from16 v1, p2

    .line 791
    .line 792
    check-cast v1, Lg21/a;

    .line 793
    .line 794
    const-string v2, "$this$viewModel"

    .line 795
    .line 796
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 797
    .line 798
    .line 799
    const-string v2, "it"

    .line 800
    .line 801
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 802
    .line 803
    .line 804
    const-class v1, Llt0/g;

    .line 805
    .line 806
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 807
    .line 808
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 809
    .line 810
    .line 811
    move-result-object v1

    .line 812
    const/4 v2, 0x0

    .line 813
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 814
    .line 815
    .line 816
    move-result-object v0

    .line 817
    check-cast v0, Llt0/g;

    .line 818
    .line 819
    new-instance v1, Lnt0/b;

    .line 820
    .line 821
    invoke-direct {v1, v0}, Lnt0/b;-><init>(Llt0/g;)V

    .line 822
    .line 823
    .line 824
    return-object v1

    .line 825
    :pswitch_b
    move-object/from16 v0, p1

    .line 826
    .line 827
    check-cast v0, Lk21/a;

    .line 828
    .line 829
    move-object/from16 v1, p2

    .line 830
    .line 831
    check-cast v1, Lg21/a;

    .line 832
    .line 833
    const-string v2, "$this$viewModel"

    .line 834
    .line 835
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 836
    .line 837
    .line 838
    const-string v2, "it"

    .line 839
    .line 840
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 841
    .line 842
    .line 843
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 844
    .line 845
    const-class v2, Llt0/b;

    .line 846
    .line 847
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 848
    .line 849
    .line 850
    move-result-object v2

    .line 851
    const/4 v3, 0x0

    .line 852
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v2

    .line 856
    const-class v4, Llt0/a;

    .line 857
    .line 858
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 859
    .line 860
    .line 861
    move-result-object v4

    .line 862
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 863
    .line 864
    .line 865
    move-result-object v4

    .line 866
    const-class v5, Lkf0/m;

    .line 867
    .line 868
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 869
    .line 870
    .line 871
    move-result-object v5

    .line 872
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 873
    .line 874
    .line 875
    move-result-object v5

    .line 876
    const-class v6, Lgn0/f;

    .line 877
    .line 878
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 879
    .line 880
    .line 881
    move-result-object v6

    .line 882
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 883
    .line 884
    .line 885
    move-result-object v6

    .line 886
    const-class v7, Llt0/f;

    .line 887
    .line 888
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 889
    .line 890
    .line 891
    move-result-object v7

    .line 892
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 893
    .line 894
    .line 895
    move-result-object v7

    .line 896
    const-class v8, Ltj0/a;

    .line 897
    .line 898
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 899
    .line 900
    .line 901
    move-result-object v8

    .line 902
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 903
    .line 904
    .line 905
    move-result-object v8

    .line 906
    const-class v9, Llt0/h;

    .line 907
    .line 908
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 909
    .line 910
    .line 911
    move-result-object v9

    .line 912
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 913
    .line 914
    .line 915
    move-result-object v9

    .line 916
    const-class v10, Ltr0/b;

    .line 917
    .line 918
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 919
    .line 920
    .line 921
    move-result-object v10

    .line 922
    invoke-virtual {v0, v10, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 923
    .line 924
    .line 925
    move-result-object v10

    .line 926
    const-class v11, Lrs0/g;

    .line 927
    .line 928
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 929
    .line 930
    .line 931
    move-result-object v11

    .line 932
    invoke-virtual {v0, v11, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 933
    .line 934
    .line 935
    move-result-object v11

    .line 936
    const-class v12, Lqf0/g;

    .line 937
    .line 938
    invoke-virtual {v1, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 939
    .line 940
    .line 941
    move-result-object v12

    .line 942
    invoke-virtual {v0, v12, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 943
    .line 944
    .line 945
    move-result-object v12

    .line 946
    const-class v13, Lij0/a;

    .line 947
    .line 948
    invoke-virtual {v1, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 949
    .line 950
    .line 951
    move-result-object v1

    .line 952
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 953
    .line 954
    .line 955
    move-result-object v0

    .line 956
    move-object/from16 v24, v0

    .line 957
    .line 958
    check-cast v24, Lij0/a;

    .line 959
    .line 960
    move-object/from16 v23, v12

    .line 961
    .line 962
    check-cast v23, Lqf0/g;

    .line 963
    .line 964
    move-object/from16 v22, v11

    .line 965
    .line 966
    check-cast v22, Lrs0/g;

    .line 967
    .line 968
    move-object/from16 v21, v10

    .line 969
    .line 970
    check-cast v21, Ltr0/b;

    .line 971
    .line 972
    move-object/from16 v20, v9

    .line 973
    .line 974
    check-cast v20, Llt0/h;

    .line 975
    .line 976
    move-object/from16 v19, v8

    .line 977
    .line 978
    check-cast v19, Ltj0/a;

    .line 979
    .line 980
    move-object/from16 v18, v7

    .line 981
    .line 982
    check-cast v18, Llt0/f;

    .line 983
    .line 984
    move-object/from16 v17, v6

    .line 985
    .line 986
    check-cast v17, Lgn0/f;

    .line 987
    .line 988
    move-object/from16 v16, v5

    .line 989
    .line 990
    check-cast v16, Lkf0/m;

    .line 991
    .line 992
    move-object v15, v4

    .line 993
    check-cast v15, Llt0/a;

    .line 994
    .line 995
    move-object v14, v2

    .line 996
    check-cast v14, Llt0/b;

    .line 997
    .line 998
    new-instance v13, Lnt0/i;

    .line 999
    .line 1000
    invoke-direct/range {v13 .. v24}, Lnt0/i;-><init>(Llt0/b;Llt0/a;Lkf0/m;Lgn0/f;Llt0/f;Ltj0/a;Llt0/h;Ltr0/b;Lrs0/g;Lqf0/g;Lij0/a;)V

    .line 1001
    .line 1002
    .line 1003
    return-object v13

    .line 1004
    :pswitch_c
    move-object/from16 v0, p1

    .line 1005
    .line 1006
    check-cast v0, Lk21/a;

    .line 1007
    .line 1008
    move-object/from16 v1, p2

    .line 1009
    .line 1010
    check-cast v1, Lg21/a;

    .line 1011
    .line 1012
    const-string v2, "$this$single"

    .line 1013
    .line 1014
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1015
    .line 1016
    .line 1017
    const-string v2, "it"

    .line 1018
    .line 1019
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1020
    .line 1021
    .line 1022
    const-class v1, Lwe0/a;

    .line 1023
    .line 1024
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1025
    .line 1026
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v1

    .line 1030
    const/4 v2, 0x0

    .line 1031
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v0

    .line 1035
    check-cast v0, Lwe0/a;

    .line 1036
    .line 1037
    new-instance v1, Ljt0/a;

    .line 1038
    .line 1039
    invoke-direct {v1, v0}, Ljt0/a;-><init>(Lwe0/a;)V

    .line 1040
    .line 1041
    .line 1042
    return-object v1

    .line 1043
    :pswitch_d
    move-object/from16 v0, p1

    .line 1044
    .line 1045
    check-cast v0, Lk21/a;

    .line 1046
    .line 1047
    move-object/from16 v1, p2

    .line 1048
    .line 1049
    check-cast v1, Lg21/a;

    .line 1050
    .line 1051
    const-string v2, "$this$single"

    .line 1052
    .line 1053
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1054
    .line 1055
    .line 1056
    const-string v2, "it"

    .line 1057
    .line 1058
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1059
    .line 1060
    .line 1061
    const-class v1, Lwe0/a;

    .line 1062
    .line 1063
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1064
    .line 1065
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1066
    .line 1067
    .line 1068
    move-result-object v1

    .line 1069
    const/4 v2, 0x0

    .line 1070
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v0

    .line 1074
    check-cast v0, Lwe0/a;

    .line 1075
    .line 1076
    new-instance v1, Ljt0/c;

    .line 1077
    .line 1078
    invoke-direct {v1, v0}, Ljt0/c;-><init>(Lwe0/a;)V

    .line 1079
    .line 1080
    .line 1081
    return-object v1

    .line 1082
    :pswitch_e
    move-object/from16 v0, p1

    .line 1083
    .line 1084
    check-cast v0, Lk21/a;

    .line 1085
    .line 1086
    move-object/from16 v1, p2

    .line 1087
    .line 1088
    check-cast v1, Lg21/a;

    .line 1089
    .line 1090
    const-string v2, "$this$factory"

    .line 1091
    .line 1092
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1093
    .line 1094
    .line 1095
    const-string v2, "it"

    .line 1096
    .line 1097
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1098
    .line 1099
    .line 1100
    const-class v1, Ljt0/b;

    .line 1101
    .line 1102
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1103
    .line 1104
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v1

    .line 1108
    const/4 v2, 0x0

    .line 1109
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v0

    .line 1113
    check-cast v0, Ljt0/b;

    .line 1114
    .line 1115
    new-instance v1, Llt0/c;

    .line 1116
    .line 1117
    invoke-direct {v1, v0}, Llt0/c;-><init>(Ljt0/b;)V

    .line 1118
    .line 1119
    .line 1120
    return-object v1

    .line 1121
    :pswitch_f
    move-object/from16 v0, p1

    .line 1122
    .line 1123
    check-cast v0, Lk21/a;

    .line 1124
    .line 1125
    move-object/from16 v1, p2

    .line 1126
    .line 1127
    check-cast v1, Lg21/a;

    .line 1128
    .line 1129
    const-string v2, "$this$factory"

    .line 1130
    .line 1131
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    const-string v2, "it"

    .line 1135
    .line 1136
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1137
    .line 1138
    .line 1139
    const-class v1, Ljt0/b;

    .line 1140
    .line 1141
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1142
    .line 1143
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v1

    .line 1147
    const/4 v2, 0x0

    .line 1148
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v0

    .line 1152
    check-cast v0, Ljt0/b;

    .line 1153
    .line 1154
    new-instance v1, Llt0/h;

    .line 1155
    .line 1156
    invoke-direct {v1, v0}, Llt0/h;-><init>(Ljt0/b;)V

    .line 1157
    .line 1158
    .line 1159
    return-object v1

    .line 1160
    :pswitch_10
    move-object/from16 v0, p1

    .line 1161
    .line 1162
    check-cast v0, Lk21/a;

    .line 1163
    .line 1164
    move-object/from16 v1, p2

    .line 1165
    .line 1166
    check-cast v1, Lg21/a;

    .line 1167
    .line 1168
    const-string v2, "$this$factory"

    .line 1169
    .line 1170
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1171
    .line 1172
    .line 1173
    const-string v2, "it"

    .line 1174
    .line 1175
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1176
    .line 1177
    .line 1178
    const-class v1, Llt0/i;

    .line 1179
    .line 1180
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1181
    .line 1182
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v1

    .line 1186
    const/4 v2, 0x0

    .line 1187
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1188
    .line 1189
    .line 1190
    move-result-object v0

    .line 1191
    check-cast v0, Llt0/i;

    .line 1192
    .line 1193
    new-instance v1, Llt0/f;

    .line 1194
    .line 1195
    invoke-direct {v1, v0}, Llt0/f;-><init>(Llt0/i;)V

    .line 1196
    .line 1197
    .line 1198
    return-object v1

    .line 1199
    :pswitch_11
    move-object/from16 v0, p1

    .line 1200
    .line 1201
    check-cast v0, Lk21/a;

    .line 1202
    .line 1203
    move-object/from16 v1, p2

    .line 1204
    .line 1205
    check-cast v1, Lg21/a;

    .line 1206
    .line 1207
    const-string v2, "$this$factory"

    .line 1208
    .line 1209
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1210
    .line 1211
    .line 1212
    const-string v2, "it"

    .line 1213
    .line 1214
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1215
    .line 1216
    .line 1217
    const-class v1, Llt0/i;

    .line 1218
    .line 1219
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1220
    .line 1221
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v1

    .line 1225
    const/4 v2, 0x0

    .line 1226
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v0

    .line 1230
    check-cast v0, Llt0/i;

    .line 1231
    .line 1232
    new-instance v1, Llt0/g;

    .line 1233
    .line 1234
    invoke-direct {v1, v0}, Llt0/g;-><init>(Llt0/i;)V

    .line 1235
    .line 1236
    .line 1237
    return-object v1

    .line 1238
    :pswitch_12
    move-object/from16 v0, p1

    .line 1239
    .line 1240
    check-cast v0, Lk21/a;

    .line 1241
    .line 1242
    move-object/from16 v1, p2

    .line 1243
    .line 1244
    check-cast v1, Lg21/a;

    .line 1245
    .line 1246
    const-string v2, "$this$factory"

    .line 1247
    .line 1248
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1249
    .line 1250
    .line 1251
    const-string v2, "it"

    .line 1252
    .line 1253
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1254
    .line 1255
    .line 1256
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1257
    .line 1258
    const-class v2, Ljt0/d;

    .line 1259
    .line 1260
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v2

    .line 1264
    const/4 v3, 0x0

    .line 1265
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1266
    .line 1267
    .line 1268
    move-result-object v2

    .line 1269
    const-class v4, Llt0/d;

    .line 1270
    .line 1271
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v1

    .line 1275
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1276
    .line 1277
    .line 1278
    move-result-object v0

    .line 1279
    check-cast v0, Llt0/d;

    .line 1280
    .line 1281
    check-cast v2, Ljt0/d;

    .line 1282
    .line 1283
    new-instance v1, Llt0/a;

    .line 1284
    .line 1285
    invoke-direct {v1, v2, v0}, Llt0/a;-><init>(Ljt0/d;Llt0/d;)V

    .line 1286
    .line 1287
    .line 1288
    return-object v1

    .line 1289
    :pswitch_13
    move-object/from16 v0, p1

    .line 1290
    .line 1291
    check-cast v0, Lk21/a;

    .line 1292
    .line 1293
    move-object/from16 v1, p2

    .line 1294
    .line 1295
    check-cast v1, Lg21/a;

    .line 1296
    .line 1297
    const-string v2, "$this$factory"

    .line 1298
    .line 1299
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1300
    .line 1301
    .line 1302
    const-string v2, "it"

    .line 1303
    .line 1304
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1305
    .line 1306
    .line 1307
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1308
    .line 1309
    const-class v2, Ljt0/e;

    .line 1310
    .line 1311
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v2

    .line 1315
    const/4 v3, 0x0

    .line 1316
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v2

    .line 1320
    const-class v4, Llt0/e;

    .line 1321
    .line 1322
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v1

    .line 1326
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v0

    .line 1330
    check-cast v0, Llt0/e;

    .line 1331
    .line 1332
    check-cast v2, Ljt0/e;

    .line 1333
    .line 1334
    new-instance v1, Llt0/b;

    .line 1335
    .line 1336
    invoke-direct {v1, v2, v0}, Llt0/b;-><init>(Ljt0/e;Llt0/e;)V

    .line 1337
    .line 1338
    .line 1339
    return-object v1

    .line 1340
    :pswitch_14
    move-object/from16 v0, p1

    .line 1341
    .line 1342
    check-cast v0, Lk21/a;

    .line 1343
    .line 1344
    move-object/from16 v1, p2

    .line 1345
    .line 1346
    check-cast v1, Lg21/a;

    .line 1347
    .line 1348
    const-string v2, "$this$factory"

    .line 1349
    .line 1350
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1351
    .line 1352
    .line 1353
    const-string v2, "it"

    .line 1354
    .line 1355
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1356
    .line 1357
    .line 1358
    const-class v1, Llq0/e;

    .line 1359
    .line 1360
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1361
    .line 1362
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v1

    .line 1366
    const/4 v2, 0x0

    .line 1367
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1368
    .line 1369
    .line 1370
    move-result-object v0

    .line 1371
    check-cast v0, Llq0/e;

    .line 1372
    .line 1373
    new-instance v1, Llq0/d;

    .line 1374
    .line 1375
    invoke-direct {v1, v0}, Llq0/d;-><init>(Llq0/e;)V

    .line 1376
    .line 1377
    .line 1378
    return-object v1

    .line 1379
    :pswitch_15
    move-object/from16 v0, p1

    .line 1380
    .line 1381
    check-cast v0, Lk21/a;

    .line 1382
    .line 1383
    move-object/from16 v1, p2

    .line 1384
    .line 1385
    check-cast v1, Lg21/a;

    .line 1386
    .line 1387
    const-string v2, "$this$factory"

    .line 1388
    .line 1389
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1390
    .line 1391
    .line 1392
    const-string v2, "it"

    .line 1393
    .line 1394
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1395
    .line 1396
    .line 1397
    const-class v1, Llq0/e;

    .line 1398
    .line 1399
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1400
    .line 1401
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1402
    .line 1403
    .line 1404
    move-result-object v1

    .line 1405
    const/4 v2, 0x0

    .line 1406
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v0

    .line 1410
    check-cast v0, Llq0/e;

    .line 1411
    .line 1412
    new-instance v1, Llq0/b;

    .line 1413
    .line 1414
    invoke-direct {v1, v0}, Llq0/b;-><init>(Llq0/e;)V

    .line 1415
    .line 1416
    .line 1417
    return-object v1

    .line 1418
    :pswitch_16
    move-object/from16 v0, p1

    .line 1419
    .line 1420
    check-cast v0, Lk21/a;

    .line 1421
    .line 1422
    move-object/from16 v1, p2

    .line 1423
    .line 1424
    check-cast v1, Lg21/a;

    .line 1425
    .line 1426
    const-string v2, "$this$factory"

    .line 1427
    .line 1428
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1429
    .line 1430
    .line 1431
    const-string v2, "it"

    .line 1432
    .line 1433
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1434
    .line 1435
    .line 1436
    const-class v1, Ljq0/b;

    .line 1437
    .line 1438
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1439
    .line 1440
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v1

    .line 1444
    const/4 v2, 0x0

    .line 1445
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1446
    .line 1447
    .line 1448
    move-result-object v0

    .line 1449
    check-cast v0, Ljq0/b;

    .line 1450
    .line 1451
    new-instance v1, Ljq0/a;

    .line 1452
    .line 1453
    invoke-direct {v1, v0}, Ljq0/a;-><init>(Ljq0/b;)V

    .line 1454
    .line 1455
    .line 1456
    return-object v1

    .line 1457
    :pswitch_17
    move-object/from16 v0, p1

    .line 1458
    .line 1459
    check-cast v0, Lk21/a;

    .line 1460
    .line 1461
    move-object/from16 v1, p2

    .line 1462
    .line 1463
    check-cast v1, Lg21/a;

    .line 1464
    .line 1465
    const-string v2, "$this$factory"

    .line 1466
    .line 1467
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1468
    .line 1469
    .line 1470
    const-string v2, "it"

    .line 1471
    .line 1472
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1473
    .line 1474
    .line 1475
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1476
    .line 1477
    const-class v2, Landroid/content/Context;

    .line 1478
    .line 1479
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1480
    .line 1481
    .line 1482
    move-result-object v2

    .line 1483
    const/4 v3, 0x0

    .line 1484
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1485
    .line 1486
    .line 1487
    move-result-object v2

    .line 1488
    const-class v4, Lij0/a;

    .line 1489
    .line 1490
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1491
    .line 1492
    .line 1493
    move-result-object v1

    .line 1494
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v0

    .line 1498
    check-cast v0, Lij0/a;

    .line 1499
    .line 1500
    check-cast v2, Landroid/content/Context;

    .line 1501
    .line 1502
    new-instance v1, Loq0/a;

    .line 1503
    .line 1504
    invoke-direct {v1, v2, v0}, Loq0/a;-><init>(Landroid/content/Context;Lij0/a;)V

    .line 1505
    .line 1506
    .line 1507
    return-object v1

    .line 1508
    :pswitch_18
    move-object/from16 v0, p1

    .line 1509
    .line 1510
    check-cast v0, Lk21/a;

    .line 1511
    .line 1512
    move-object/from16 v1, p2

    .line 1513
    .line 1514
    check-cast v1, Lg21/a;

    .line 1515
    .line 1516
    const-string v2, "$this$factory"

    .line 1517
    .line 1518
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1519
    .line 1520
    .line 1521
    const-string v2, "it"

    .line 1522
    .line 1523
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1524
    .line 1525
    .line 1526
    const-class v1, Llp0/a;

    .line 1527
    .line 1528
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1529
    .line 1530
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1531
    .line 1532
    .line 1533
    move-result-object v1

    .line 1534
    const/4 v2, 0x0

    .line 1535
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v0

    .line 1539
    check-cast v0, Llp0/a;

    .line 1540
    .line 1541
    new-instance v1, Llp0/b;

    .line 1542
    .line 1543
    invoke-direct {v1, v0}, Llp0/b;-><init>(Llp0/a;)V

    .line 1544
    .line 1545
    .line 1546
    return-object v1

    .line 1547
    :pswitch_19
    move-object/from16 v0, p1

    .line 1548
    .line 1549
    check-cast v0, Lk21/a;

    .line 1550
    .line 1551
    move-object/from16 v1, p2

    .line 1552
    .line 1553
    check-cast v1, Lg21/a;

    .line 1554
    .line 1555
    const-string v2, "$this$factory"

    .line 1556
    .line 1557
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1558
    .line 1559
    .line 1560
    const-string v2, "it"

    .line 1561
    .line 1562
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1563
    .line 1564
    .line 1565
    const-class v1, Llp0/a;

    .line 1566
    .line 1567
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1568
    .line 1569
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1570
    .line 1571
    .line 1572
    move-result-object v1

    .line 1573
    const/4 v2, 0x0

    .line 1574
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1575
    .line 1576
    .line 1577
    move-result-object v0

    .line 1578
    check-cast v0, Llp0/a;

    .line 1579
    .line 1580
    new-instance v1, Llp0/d;

    .line 1581
    .line 1582
    invoke-direct {v1, v0}, Llp0/d;-><init>(Llp0/a;)V

    .line 1583
    .line 1584
    .line 1585
    return-object v1

    .line 1586
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1587
    .line 1588
    check-cast v0, Lk21/a;

    .line 1589
    .line 1590
    move-object/from16 v1, p2

    .line 1591
    .line 1592
    check-cast v1, Lg21/a;

    .line 1593
    .line 1594
    const-string v2, "$this$single"

    .line 1595
    .line 1596
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1597
    .line 1598
    .line 1599
    const-string v0, "it"

    .line 1600
    .line 1601
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1602
    .line 1603
    .line 1604
    new-instance v0, Lnm0/b;

    .line 1605
    .line 1606
    const/4 v1, 0x0

    .line 1607
    invoke-direct {v0, v1}, Lnm0/b;-><init>(I)V

    .line 1608
    .line 1609
    .line 1610
    return-object v0

    .line 1611
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1612
    .line 1613
    check-cast v0, Lk21/a;

    .line 1614
    .line 1615
    move-object/from16 v1, p2

    .line 1616
    .line 1617
    check-cast v1, Lg21/a;

    .line 1618
    .line 1619
    const-string v2, "$this$single"

    .line 1620
    .line 1621
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1622
    .line 1623
    .line 1624
    const-string v2, "it"

    .line 1625
    .line 1626
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1627
    .line 1628
    .line 1629
    const-class v1, Ljm0/a;

    .line 1630
    .line 1631
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1632
    .line 1633
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1634
    .line 1635
    .line 1636
    move-result-object v1

    .line 1637
    const/4 v2, 0x0

    .line 1638
    invoke-virtual {v0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1639
    .line 1640
    .line 1641
    move-result-object v0

    .line 1642
    check-cast v0, Ljm0/a;

    .line 1643
    .line 1644
    new-instance v1, Lnm0/a;

    .line 1645
    .line 1646
    invoke-direct {v1, v0}, Lnm0/a;-><init>(Ljm0/a;)V

    .line 1647
    .line 1648
    .line 1649
    return-object v1

    .line 1650
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1651
    .line 1652
    check-cast v0, Lk21/a;

    .line 1653
    .line 1654
    move-object/from16 v1, p2

    .line 1655
    .line 1656
    check-cast v1, Lg21/a;

    .line 1657
    .line 1658
    const-string v2, "$this$single"

    .line 1659
    .line 1660
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1661
    .line 1662
    .line 1663
    const-string v0, "it"

    .line 1664
    .line 1665
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1666
    .line 1667
    .line 1668
    new-instance v0, Ljm0/a;

    .line 1669
    .line 1670
    invoke-direct {v0}, Ljm0/a;-><init>()V

    .line 1671
    .line 1672
    .line 1673
    return-object v0

    .line 1674
    nop

    .line 1675
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
