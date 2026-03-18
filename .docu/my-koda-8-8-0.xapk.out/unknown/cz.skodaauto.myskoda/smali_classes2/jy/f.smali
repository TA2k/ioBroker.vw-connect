.class public final Ljy/f;
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
    iput p1, p0, Ljy/f;->d:I

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
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Ljy/f;->d:I

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
    const-class v2, Lkf0/z;

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
    const-class v4, Lwr0/e;

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
    const-class v5, Ll00/f;

    .line 50
    .line 51
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    const-class v6, Ll00/l;

    .line 60
    .line 61
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Ll00/l;

    .line 70
    .line 71
    check-cast v5, Ll00/f;

    .line 72
    .line 73
    check-cast v4, Lwr0/e;

    .line 74
    .line 75
    check-cast v2, Lkf0/z;

    .line 76
    .line 77
    new-instance v1, Ll00/i;

    .line 78
    .line 79
    invoke-direct {v1, v2, v4, v5, v0}, Ll00/i;-><init>(Lkf0/z;Lwr0/e;Ll00/f;Ll00/l;)V

    .line 80
    .line 81
    .line 82
    return-object v1

    .line 83
    :pswitch_0
    move-object/from16 v0, p1

    .line 84
    .line 85
    check-cast v0, Lk21/a;

    .line 86
    .line 87
    move-object/from16 v1, p2

    .line 88
    .line 89
    check-cast v1, Lg21/a;

    .line 90
    .line 91
    const-string v2, "$this$viewModel"

    .line 92
    .line 93
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const-string v2, "it"

    .line 97
    .line 98
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 102
    .line 103
    const-class v2, Lky/x;

    .line 104
    .line 105
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const/4 v3, 0x0

    .line 110
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    const-class v4, Lky/o;

    .line 115
    .line 116
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    invoke-virtual {v0, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    const-class v5, Luh0/d;

    .line 125
    .line 126
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    const-class v6, Lky/j0;

    .line 135
    .line 136
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 137
    .line 138
    .line 139
    move-result-object v6

    .line 140
    invoke-virtual {v0, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    const-class v7, Lgf0/g;

    .line 145
    .line 146
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 147
    .line 148
    .line 149
    move-result-object v7

    .line 150
    invoke-virtual {v0, v7, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v7

    .line 154
    const-class v8, Lgf0/d;

    .line 155
    .line 156
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    invoke-virtual {v0, v8, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    const-class v9, Lkc0/q;

    .line 165
    .line 166
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    invoke-virtual {v0, v9, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v9

    .line 174
    const-class v10, Lky/w;

    .line 175
    .line 176
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 177
    .line 178
    .line 179
    move-result-object v10

    .line 180
    invoke-virtual {v0, v10, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v10

    .line 184
    const-class v11, Lz30/b;

    .line 185
    .line 186
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 187
    .line 188
    .line 189
    move-result-object v11

    .line 190
    invoke-virtual {v0, v11, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v11

    .line 194
    const-class v12, Lwi0/p;

    .line 195
    .line 196
    invoke-virtual {v1, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 197
    .line 198
    .line 199
    move-result-object v12

    .line 200
    invoke-virtual {v0, v12, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v12

    .line 204
    const-class v13, Lwi0/b;

    .line 205
    .line 206
    invoke-virtual {v1, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 207
    .line 208
    .line 209
    move-result-object v13

    .line 210
    invoke-virtual {v0, v13, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v13

    .line 214
    const-class v14, Lfz/c;

    .line 215
    .line 216
    invoke-virtual {v1, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 217
    .line 218
    .line 219
    move-result-object v14

    .line 220
    invoke-virtual {v0, v14, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v14

    .line 224
    const-class v15, Lam0/z;

    .line 225
    .line 226
    invoke-virtual {v1, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 227
    .line 228
    .line 229
    move-result-object v15

    .line 230
    invoke-virtual {v0, v15, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v15

    .line 234
    move-object/from16 p0, v2

    .line 235
    .line 236
    const-class v2, Lq70/i;

    .line 237
    .line 238
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    move-object/from16 p1, v2

    .line 247
    .line 248
    const-class v2, Lq70/e;

    .line 249
    .line 250
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    move-object/from16 p2, v2

    .line 259
    .line 260
    const-class v2, Lq70/g;

    .line 261
    .line 262
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    move-object/from16 v16, v2

    .line 271
    .line 272
    const-class v2, Lq70/d;

    .line 273
    .line 274
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    move-object/from16 v17, v2

    .line 283
    .line 284
    const-class v2, Lcs0/f;

    .line 285
    .line 286
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v2

    .line 294
    move-object/from16 v18, v2

    .line 295
    .line 296
    const-class v2, Lzo0/a0;

    .line 297
    .line 298
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v2

    .line 306
    move-object/from16 v19, v2

    .line 307
    .line 308
    const-class v2, Lzo0/c;

    .line 309
    .line 310
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v2

    .line 318
    move-object/from16 v20, v2

    .line 319
    .line 320
    const-class v2, Lky/r;

    .line 321
    .line 322
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 323
    .line 324
    .line 325
    move-result-object v2

    .line 326
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v2

    .line 330
    move-object/from16 v21, v2

    .line 331
    .line 332
    const-class v2, Lte0/f;

    .line 333
    .line 334
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    move-object/from16 v44, v0

    .line 343
    .line 344
    check-cast v44, Lte0/f;

    .line 345
    .line 346
    move-object/from16 v43, v21

    .line 347
    .line 348
    check-cast v43, Lky/r;

    .line 349
    .line 350
    move-object/from16 v42, v20

    .line 351
    .line 352
    check-cast v42, Lzo0/c;

    .line 353
    .line 354
    move-object/from16 v41, v19

    .line 355
    .line 356
    check-cast v41, Lzo0/a0;

    .line 357
    .line 358
    move-object/from16 v40, v18

    .line 359
    .line 360
    check-cast v40, Lcs0/f;

    .line 361
    .line 362
    move-object/from16 v39, v17

    .line 363
    .line 364
    check-cast v39, Lq70/d;

    .line 365
    .line 366
    move-object/from16 v38, v16

    .line 367
    .line 368
    check-cast v38, Lq70/g;

    .line 369
    .line 370
    move-object/from16 v37, p2

    .line 371
    .line 372
    check-cast v37, Lq70/e;

    .line 373
    .line 374
    move-object/from16 v36, p1

    .line 375
    .line 376
    check-cast v36, Lq70/i;

    .line 377
    .line 378
    move-object/from16 v35, v15

    .line 379
    .line 380
    check-cast v35, Lam0/z;

    .line 381
    .line 382
    move-object/from16 v34, v14

    .line 383
    .line 384
    check-cast v34, Lfz/c;

    .line 385
    .line 386
    move-object/from16 v33, v13

    .line 387
    .line 388
    check-cast v33, Lwi0/b;

    .line 389
    .line 390
    move-object/from16 v32, v12

    .line 391
    .line 392
    check-cast v32, Lwi0/p;

    .line 393
    .line 394
    move-object/from16 v31, v11

    .line 395
    .line 396
    check-cast v31, Lz30/b;

    .line 397
    .line 398
    move-object/from16 v30, v10

    .line 399
    .line 400
    check-cast v30, Lky/w;

    .line 401
    .line 402
    move-object/from16 v29, v9

    .line 403
    .line 404
    check-cast v29, Lkc0/q;

    .line 405
    .line 406
    move-object/from16 v28, v8

    .line 407
    .line 408
    check-cast v28, Lgf0/d;

    .line 409
    .line 410
    move-object/from16 v27, v7

    .line 411
    .line 412
    check-cast v27, Lgf0/g;

    .line 413
    .line 414
    move-object/from16 v26, v6

    .line 415
    .line 416
    check-cast v26, Lky/j0;

    .line 417
    .line 418
    move-object/from16 v25, v5

    .line 419
    .line 420
    check-cast v25, Luh0/d;

    .line 421
    .line 422
    move-object/from16 v24, v4

    .line 423
    .line 424
    check-cast v24, Lky/o;

    .line 425
    .line 426
    move-object/from16 v23, p0

    .line 427
    .line 428
    check-cast v23, Lky/x;

    .line 429
    .line 430
    new-instance v22, Lmy/d;

    .line 431
    .line 432
    invoke-direct/range {v22 .. v44}, Lmy/d;-><init>(Lky/x;Lky/o;Luh0/d;Lky/j0;Lgf0/g;Lgf0/d;Lkc0/q;Lky/w;Lz30/b;Lwi0/p;Lwi0/b;Lfz/c;Lam0/z;Lq70/i;Lq70/e;Lq70/g;Lq70/d;Lcs0/f;Lzo0/a0;Lzo0/c;Lky/r;Lte0/f;)V

    .line 433
    .line 434
    .line 435
    return-object v22

    .line 436
    :pswitch_1
    move-object/from16 v0, p1

    .line 437
    .line 438
    check-cast v0, Lk21/a;

    .line 439
    .line 440
    move-object/from16 v1, p2

    .line 441
    .line 442
    check-cast v1, Lg21/a;

    .line 443
    .line 444
    const-string v2, "$this$single"

    .line 445
    .line 446
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 447
    .line 448
    .line 449
    const-string v2, "it"

    .line 450
    .line 451
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 452
    .line 453
    .line 454
    new-instance v1, Ljy/h;

    .line 455
    .line 456
    const/16 v2, 0x9

    .line 457
    .line 458
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 459
    .line 460
    .line 461
    return-object v1

    .line 462
    :pswitch_2
    move-object/from16 v0, p1

    .line 463
    .line 464
    check-cast v0, Lk21/a;

    .line 465
    .line 466
    move-object/from16 v1, p2

    .line 467
    .line 468
    check-cast v1, Lg21/a;

    .line 469
    .line 470
    const-string v2, "$this$single"

    .line 471
    .line 472
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    const-string v2, "it"

    .line 476
    .line 477
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 478
    .line 479
    .line 480
    new-instance v1, Ljy/h;

    .line 481
    .line 482
    const/16 v2, 0x8

    .line 483
    .line 484
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 485
    .line 486
    .line 487
    return-object v1

    .line 488
    :pswitch_3
    move-object/from16 v0, p1

    .line 489
    .line 490
    check-cast v0, Lk21/a;

    .line 491
    .line 492
    move-object/from16 v1, p2

    .line 493
    .line 494
    check-cast v1, Lg21/a;

    .line 495
    .line 496
    const-string v2, "$this$single"

    .line 497
    .line 498
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 499
    .line 500
    .line 501
    const-string v2, "it"

    .line 502
    .line 503
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    new-instance v1, Ljy/h;

    .line 507
    .line 508
    const/4 v2, 0x7

    .line 509
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 510
    .line 511
    .line 512
    return-object v1

    .line 513
    :pswitch_4
    move-object/from16 v0, p1

    .line 514
    .line 515
    check-cast v0, Lk21/a;

    .line 516
    .line 517
    move-object/from16 v1, p2

    .line 518
    .line 519
    check-cast v1, Lg21/a;

    .line 520
    .line 521
    const-string v2, "$this$single"

    .line 522
    .line 523
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 524
    .line 525
    .line 526
    const-string v2, "it"

    .line 527
    .line 528
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 529
    .line 530
    .line 531
    new-instance v1, Ljy/h;

    .line 532
    .line 533
    const/4 v2, 0x6

    .line 534
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 535
    .line 536
    .line 537
    return-object v1

    .line 538
    :pswitch_5
    move-object/from16 v0, p1

    .line 539
    .line 540
    check-cast v0, Lk21/a;

    .line 541
    .line 542
    move-object/from16 v1, p2

    .line 543
    .line 544
    check-cast v1, Lg21/a;

    .line 545
    .line 546
    const-string v2, "$this$single"

    .line 547
    .line 548
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 549
    .line 550
    .line 551
    const-string v2, "it"

    .line 552
    .line 553
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 554
    .line 555
    .line 556
    new-instance v1, Ljy/h;

    .line 557
    .line 558
    const/4 v2, 0x5

    .line 559
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 560
    .line 561
    .line 562
    return-object v1

    .line 563
    :pswitch_6
    move-object/from16 v0, p1

    .line 564
    .line 565
    check-cast v0, Lk21/a;

    .line 566
    .line 567
    move-object/from16 v1, p2

    .line 568
    .line 569
    check-cast v1, Lg21/a;

    .line 570
    .line 571
    const-string v2, "$this$single"

    .line 572
    .line 573
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 574
    .line 575
    .line 576
    const-string v2, "it"

    .line 577
    .line 578
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    new-instance v1, Ljy/h;

    .line 582
    .line 583
    const/4 v2, 0x3

    .line 584
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 585
    .line 586
    .line 587
    return-object v1

    .line 588
    :pswitch_7
    move-object/from16 v0, p1

    .line 589
    .line 590
    check-cast v0, Lk21/a;

    .line 591
    .line 592
    move-object/from16 v1, p2

    .line 593
    .line 594
    check-cast v1, Lg21/a;

    .line 595
    .line 596
    const-string v2, "$this$single"

    .line 597
    .line 598
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 599
    .line 600
    .line 601
    const-string v2, "it"

    .line 602
    .line 603
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    new-instance v1, Ljy/h;

    .line 607
    .line 608
    const/4 v2, 0x4

    .line 609
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 610
    .line 611
    .line 612
    return-object v1

    .line 613
    :pswitch_8
    move-object/from16 v0, p1

    .line 614
    .line 615
    check-cast v0, Lk21/a;

    .line 616
    .line 617
    move-object/from16 v1, p2

    .line 618
    .line 619
    check-cast v1, Lg21/a;

    .line 620
    .line 621
    const-string v2, "$this$single"

    .line 622
    .line 623
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 624
    .line 625
    .line 626
    const-string v2, "it"

    .line 627
    .line 628
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 629
    .line 630
    .line 631
    new-instance v1, Ljy/e;

    .line 632
    .line 633
    const/16 v2, 0x16

    .line 634
    .line 635
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 636
    .line 637
    .line 638
    return-object v1

    .line 639
    :pswitch_9
    move-object/from16 v0, p1

    .line 640
    .line 641
    check-cast v0, Lk21/a;

    .line 642
    .line 643
    move-object/from16 v1, p2

    .line 644
    .line 645
    check-cast v1, Lg21/a;

    .line 646
    .line 647
    const-string v2, "$this$single"

    .line 648
    .line 649
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 650
    .line 651
    .line 652
    const-string v2, "it"

    .line 653
    .line 654
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    new-instance v1, Ljy/h;

    .line 658
    .line 659
    const/4 v2, 0x2

    .line 660
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 661
    .line 662
    .line 663
    return-object v1

    .line 664
    :pswitch_a
    move-object/from16 v0, p1

    .line 665
    .line 666
    check-cast v0, Lk21/a;

    .line 667
    .line 668
    move-object/from16 v1, p2

    .line 669
    .line 670
    check-cast v1, Lg21/a;

    .line 671
    .line 672
    const-string v2, "$this$single"

    .line 673
    .line 674
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 675
    .line 676
    .line 677
    const-string v2, "it"

    .line 678
    .line 679
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 680
    .line 681
    .line 682
    new-instance v1, Ljy/h;

    .line 683
    .line 684
    const/4 v2, 0x1

    .line 685
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 686
    .line 687
    .line 688
    return-object v1

    .line 689
    :pswitch_b
    move-object/from16 v0, p1

    .line 690
    .line 691
    check-cast v0, Lk21/a;

    .line 692
    .line 693
    move-object/from16 v1, p2

    .line 694
    .line 695
    check-cast v1, Lg21/a;

    .line 696
    .line 697
    const-string v2, "$this$single"

    .line 698
    .line 699
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 700
    .line 701
    .line 702
    const-string v2, "it"

    .line 703
    .line 704
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 705
    .line 706
    .line 707
    new-instance v1, Ljy/h;

    .line 708
    .line 709
    const/4 v2, 0x0

    .line 710
    invoke-direct {v1, v0, v2}, Ljy/h;-><init>(Lk21/a;I)V

    .line 711
    .line 712
    .line 713
    return-object v1

    .line 714
    :pswitch_c
    move-object/from16 v0, p1

    .line 715
    .line 716
    check-cast v0, Lk21/a;

    .line 717
    .line 718
    move-object/from16 v1, p2

    .line 719
    .line 720
    check-cast v1, Lg21/a;

    .line 721
    .line 722
    const-string v2, "$this$single"

    .line 723
    .line 724
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 725
    .line 726
    .line 727
    const-string v2, "it"

    .line 728
    .line 729
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 730
    .line 731
    .line 732
    new-instance v1, Ljy/e;

    .line 733
    .line 734
    const/16 v2, 0x1d

    .line 735
    .line 736
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 737
    .line 738
    .line 739
    return-object v1

    .line 740
    :pswitch_d
    move-object/from16 v0, p1

    .line 741
    .line 742
    check-cast v0, Lk21/a;

    .line 743
    .line 744
    move-object/from16 v1, p2

    .line 745
    .line 746
    check-cast v1, Lg21/a;

    .line 747
    .line 748
    const-string v2, "$this$single"

    .line 749
    .line 750
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 751
    .line 752
    .line 753
    const-string v2, "it"

    .line 754
    .line 755
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 756
    .line 757
    .line 758
    new-instance v1, Ljy/e;

    .line 759
    .line 760
    const/16 v2, 0x1c

    .line 761
    .line 762
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 763
    .line 764
    .line 765
    return-object v1

    .line 766
    :pswitch_e
    move-object/from16 v0, p1

    .line 767
    .line 768
    check-cast v0, Lk21/a;

    .line 769
    .line 770
    move-object/from16 v1, p2

    .line 771
    .line 772
    check-cast v1, Lg21/a;

    .line 773
    .line 774
    const-string v2, "$this$single"

    .line 775
    .line 776
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 777
    .line 778
    .line 779
    const-string v2, "it"

    .line 780
    .line 781
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 782
    .line 783
    .line 784
    new-instance v1, Ljy/e;

    .line 785
    .line 786
    const/16 v2, 0x1b

    .line 787
    .line 788
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 789
    .line 790
    .line 791
    return-object v1

    .line 792
    :pswitch_f
    move-object/from16 v0, p1

    .line 793
    .line 794
    check-cast v0, Lk21/a;

    .line 795
    .line 796
    move-object/from16 v1, p2

    .line 797
    .line 798
    check-cast v1, Lg21/a;

    .line 799
    .line 800
    const-string v2, "$this$single"

    .line 801
    .line 802
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 803
    .line 804
    .line 805
    const-string v2, "it"

    .line 806
    .line 807
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 808
    .line 809
    .line 810
    new-instance v1, Ljy/e;

    .line 811
    .line 812
    const/16 v2, 0x1a

    .line 813
    .line 814
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 815
    .line 816
    .line 817
    return-object v1

    .line 818
    :pswitch_10
    move-object/from16 v0, p1

    .line 819
    .line 820
    check-cast v0, Lk21/a;

    .line 821
    .line 822
    move-object/from16 v1, p2

    .line 823
    .line 824
    check-cast v1, Lg21/a;

    .line 825
    .line 826
    const-string v2, "$this$single"

    .line 827
    .line 828
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 829
    .line 830
    .line 831
    const-string v2, "it"

    .line 832
    .line 833
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 834
    .line 835
    .line 836
    new-instance v1, Ljy/e;

    .line 837
    .line 838
    const/16 v2, 0x19

    .line 839
    .line 840
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 841
    .line 842
    .line 843
    return-object v1

    .line 844
    :pswitch_11
    move-object/from16 v0, p1

    .line 845
    .line 846
    check-cast v0, Lk21/a;

    .line 847
    .line 848
    move-object/from16 v1, p2

    .line 849
    .line 850
    check-cast v1, Lg21/a;

    .line 851
    .line 852
    const-string v2, "$this$single"

    .line 853
    .line 854
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 855
    .line 856
    .line 857
    const-string v2, "it"

    .line 858
    .line 859
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 860
    .line 861
    .line 862
    new-instance v1, Ljy/e;

    .line 863
    .line 864
    const/16 v2, 0x18

    .line 865
    .line 866
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 867
    .line 868
    .line 869
    return-object v1

    .line 870
    :pswitch_12
    move-object/from16 v0, p1

    .line 871
    .line 872
    check-cast v0, Lk21/a;

    .line 873
    .line 874
    move-object/from16 v1, p2

    .line 875
    .line 876
    check-cast v1, Lg21/a;

    .line 877
    .line 878
    const-string v2, "$this$single"

    .line 879
    .line 880
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 881
    .line 882
    .line 883
    const-string v2, "it"

    .line 884
    .line 885
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    new-instance v1, Ljy/e;

    .line 889
    .line 890
    const/16 v2, 0x17

    .line 891
    .line 892
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 893
    .line 894
    .line 895
    return-object v1

    .line 896
    :pswitch_13
    move-object/from16 v0, p1

    .line 897
    .line 898
    check-cast v0, Lk21/a;

    .line 899
    .line 900
    move-object/from16 v1, p2

    .line 901
    .line 902
    check-cast v1, Lg21/a;

    .line 903
    .line 904
    const-string v2, "$this$single"

    .line 905
    .line 906
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 907
    .line 908
    .line 909
    const-string v2, "it"

    .line 910
    .line 911
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 912
    .line 913
    .line 914
    new-instance v1, Ljy/e;

    .line 915
    .line 916
    const/16 v2, 0xb

    .line 917
    .line 918
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 919
    .line 920
    .line 921
    return-object v1

    .line 922
    :pswitch_14
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
    const-string v2, "$this$single"

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
    new-instance v1, Ljy/e;

    .line 941
    .line 942
    const/16 v2, 0x15

    .line 943
    .line 944
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 945
    .line 946
    .line 947
    return-object v1

    .line 948
    :pswitch_15
    move-object/from16 v0, p1

    .line 949
    .line 950
    check-cast v0, Lk21/a;

    .line 951
    .line 952
    move-object/from16 v1, p2

    .line 953
    .line 954
    check-cast v1, Lg21/a;

    .line 955
    .line 956
    const-string v2, "$this$single"

    .line 957
    .line 958
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 959
    .line 960
    .line 961
    const-string v2, "it"

    .line 962
    .line 963
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 964
    .line 965
    .line 966
    new-instance v1, Ljy/e;

    .line 967
    .line 968
    const/16 v2, 0x14

    .line 969
    .line 970
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 971
    .line 972
    .line 973
    return-object v1

    .line 974
    :pswitch_16
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
    const-string v2, "$this$single"

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
    new-instance v1, Ljy/e;

    .line 993
    .line 994
    const/16 v2, 0x13

    .line 995
    .line 996
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 997
    .line 998
    .line 999
    return-object v1

    .line 1000
    :pswitch_17
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
    const-string v2, "$this$single"

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
    new-instance v1, Ljy/e;

    .line 1019
    .line 1020
    const/16 v2, 0x12

    .line 1021
    .line 1022
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1023
    .line 1024
    .line 1025
    return-object v1

    .line 1026
    :pswitch_18
    move-object/from16 v0, p1

    .line 1027
    .line 1028
    check-cast v0, Lk21/a;

    .line 1029
    .line 1030
    move-object/from16 v1, p2

    .line 1031
    .line 1032
    check-cast v1, Lg21/a;

    .line 1033
    .line 1034
    const-string v2, "$this$single"

    .line 1035
    .line 1036
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1037
    .line 1038
    .line 1039
    const-string v2, "it"

    .line 1040
    .line 1041
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1042
    .line 1043
    .line 1044
    new-instance v1, Ljy/e;

    .line 1045
    .line 1046
    const/16 v2, 0x11

    .line 1047
    .line 1048
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1049
    .line 1050
    .line 1051
    return-object v1

    .line 1052
    :pswitch_19
    move-object/from16 v0, p1

    .line 1053
    .line 1054
    check-cast v0, Lk21/a;

    .line 1055
    .line 1056
    move-object/from16 v1, p2

    .line 1057
    .line 1058
    check-cast v1, Lg21/a;

    .line 1059
    .line 1060
    const-string v2, "$this$single"

    .line 1061
    .line 1062
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1063
    .line 1064
    .line 1065
    const-string v2, "it"

    .line 1066
    .line 1067
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1068
    .line 1069
    .line 1070
    new-instance v1, Ljy/e;

    .line 1071
    .line 1072
    const/16 v2, 0x10

    .line 1073
    .line 1074
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1075
    .line 1076
    .line 1077
    return-object v1

    .line 1078
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1079
    .line 1080
    check-cast v0, Lk21/a;

    .line 1081
    .line 1082
    move-object/from16 v1, p2

    .line 1083
    .line 1084
    check-cast v1, Lg21/a;

    .line 1085
    .line 1086
    const-string v2, "$this$single"

    .line 1087
    .line 1088
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1089
    .line 1090
    .line 1091
    const-string v2, "it"

    .line 1092
    .line 1093
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1094
    .line 1095
    .line 1096
    new-instance v1, Ljy/e;

    .line 1097
    .line 1098
    const/16 v2, 0xf

    .line 1099
    .line 1100
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1101
    .line 1102
    .line 1103
    return-object v1

    .line 1104
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1105
    .line 1106
    check-cast v0, Lk21/a;

    .line 1107
    .line 1108
    move-object/from16 v1, p2

    .line 1109
    .line 1110
    check-cast v1, Lg21/a;

    .line 1111
    .line 1112
    const-string v2, "$this$single"

    .line 1113
    .line 1114
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1115
    .line 1116
    .line 1117
    const-string v2, "it"

    .line 1118
    .line 1119
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1120
    .line 1121
    .line 1122
    new-instance v1, Ljy/e;

    .line 1123
    .line 1124
    const/16 v2, 0xe

    .line 1125
    .line 1126
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1127
    .line 1128
    .line 1129
    return-object v1

    .line 1130
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1131
    .line 1132
    check-cast v0, Lk21/a;

    .line 1133
    .line 1134
    move-object/from16 v1, p2

    .line 1135
    .line 1136
    check-cast v1, Lg21/a;

    .line 1137
    .line 1138
    const-string v2, "$this$single"

    .line 1139
    .line 1140
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1141
    .line 1142
    .line 1143
    const-string v2, "it"

    .line 1144
    .line 1145
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1146
    .line 1147
    .line 1148
    new-instance v1, Ljy/e;

    .line 1149
    .line 1150
    const/16 v2, 0xd

    .line 1151
    .line 1152
    invoke-direct {v1, v0, v2}, Ljy/e;-><init>(Lk21/a;I)V

    .line 1153
    .line 1154
    .line 1155
    return-object v1

    .line 1156
    nop

    .line 1157
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
