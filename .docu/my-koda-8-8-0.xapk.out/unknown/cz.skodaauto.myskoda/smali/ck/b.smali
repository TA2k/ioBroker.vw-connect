.class public final synthetic Lck/b;
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
    iput p1, p0, Lck/b;->d:I

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
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lck/b;->d:I

    .line 4
    .line 5
    const-string v1, "_connection"

    .line 6
    .line 7
    const-string v2, "NOT_STARTED"

    .line 8
    .line 9
    const/16 v3, 0x18

    .line 10
    .line 11
    const/16 v4, 0xc

    .line 12
    .line 13
    const-string v5, "<this>"

    .line 14
    .line 15
    const/4 v6, 0x0

    .line 16
    const/4 v7, 0x2

    .line 17
    const/4 v8, 0x1

    .line 18
    const/4 v9, 0x0

    .line 19
    const-string v10, "$this$module"

    .line 20
    .line 21
    const-string v11, "it"

    .line 22
    .line 23
    const/16 v12, 0xa

    .line 24
    .line 25
    const-string v13, "$this$request"

    .line 26
    .line 27
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    packed-switch v0, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    move-object/from16 v0, p1

    .line 33
    .line 34
    check-cast v0, Lhi/c;

    .line 35
    .line 36
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Ldj/a;

    .line 40
    .line 41
    invoke-direct {v1, v9}, Ldj/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    new-instance v2, Lii/b;

    .line 45
    .line 46
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    const-class v4, Lcj/f;

    .line 49
    .line 50
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    invoke-direct {v2, v9, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, v0, Lhi/c;->a:Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    new-instance v1, Ldj/a;

    .line 63
    .line 64
    invoke-direct {v1, v8}, Ldj/a;-><init>(I)V

    .line 65
    .line 66
    .line 67
    new-instance v2, Lii/b;

    .line 68
    .line 69
    const-class v4, Ldj/f;

    .line 70
    .line 71
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-direct {v2, v9, v1, v3}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    return-object v14

    .line 82
    :pswitch_0
    move-object/from16 v0, p1

    .line 83
    .line 84
    check-cast v0, Le21/a;

    .line 85
    .line 86
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    new-instance v1, Ld60/a;

    .line 90
    .line 91
    const/16 v2, 0xd

    .line 92
    .line 93
    invoke-direct {v1, v2}, Ld60/a;-><init>(I)V

    .line 94
    .line 95
    .line 96
    sget-object v16, Li21/b;->e:Lh21/b;

    .line 97
    .line 98
    sget-object v20, La21/c;->e:La21/c;

    .line 99
    .line 100
    new-instance v15, La21/a;

    .line 101
    .line 102
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 103
    .line 104
    const-class v3, Lee0/d;

    .line 105
    .line 106
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 107
    .line 108
    .line 109
    move-result-object v17

    .line 110
    const/16 v18, 0x0

    .line 111
    .line 112
    move-object/from16 v19, v1

    .line 113
    .line 114
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 115
    .line 116
    .line 117
    new-instance v1, Lc21/a;

    .line 118
    .line 119
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 123
    .line 124
    .line 125
    new-instance v1, Ld60/a;

    .line 126
    .line 127
    const/16 v3, 0xe

    .line 128
    .line 129
    invoke-direct {v1, v3}, Ld60/a;-><init>(I)V

    .line 130
    .line 131
    .line 132
    new-instance v15, La21/a;

    .line 133
    .line 134
    const-class v3, Lee0/b;

    .line 135
    .line 136
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 137
    .line 138
    .line 139
    move-result-object v17

    .line 140
    move-object/from16 v19, v1

    .line 141
    .line 142
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 143
    .line 144
    .line 145
    new-instance v1, Lc21/a;

    .line 146
    .line 147
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 151
    .line 152
    .line 153
    new-instance v1, Ld60/a;

    .line 154
    .line 155
    const/16 v3, 0xf

    .line 156
    .line 157
    invoke-direct {v1, v3}, Ld60/a;-><init>(I)V

    .line 158
    .line 159
    .line 160
    new-instance v15, La21/a;

    .line 161
    .line 162
    const-class v3, Lee0/f;

    .line 163
    .line 164
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 165
    .line 166
    .line 167
    move-result-object v17

    .line 168
    move-object/from16 v19, v1

    .line 169
    .line 170
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 171
    .line 172
    .line 173
    new-instance v1, Lc21/a;

    .line 174
    .line 175
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 179
    .line 180
    .line 181
    new-instance v1, Ld60/a;

    .line 182
    .line 183
    const/16 v3, 0x10

    .line 184
    .line 185
    invoke-direct {v1, v3}, Ld60/a;-><init>(I)V

    .line 186
    .line 187
    .line 188
    new-instance v15, La21/a;

    .line 189
    .line 190
    const-class v3, Lee0/h;

    .line 191
    .line 192
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 193
    .line 194
    .line 195
    move-result-object v17

    .line 196
    move-object/from16 v19, v1

    .line 197
    .line 198
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 199
    .line 200
    .line 201
    new-instance v1, Lc21/a;

    .line 202
    .line 203
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 207
    .line 208
    .line 209
    new-instance v1, Ld80/m;

    .line 210
    .line 211
    invoke-direct {v1, v4}, Ld80/m;-><init>(I)V

    .line 212
    .line 213
    .line 214
    sget-object v20, La21/c;->d:La21/c;

    .line 215
    .line 216
    new-instance v15, La21/a;

    .line 217
    .line 218
    const-class v3, Lce0/d;

    .line 219
    .line 220
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 221
    .line 222
    .line 223
    move-result-object v17

    .line 224
    move-object/from16 v19, v1

    .line 225
    .line 226
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 227
    .line 228
    .line 229
    new-instance v1, Lc21/d;

    .line 230
    .line 231
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 235
    .line 236
    .line 237
    new-instance v1, Ld60/a;

    .line 238
    .line 239
    const/16 v3, 0x11

    .line 240
    .line 241
    invoke-direct {v1, v3}, Ld60/a;-><init>(I)V

    .line 242
    .line 243
    .line 244
    new-instance v15, La21/a;

    .line 245
    .line 246
    const-class v3, Lce0/b;

    .line 247
    .line 248
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 249
    .line 250
    .line 251
    move-result-object v17

    .line 252
    move-object/from16 v19, v1

    .line 253
    .line 254
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 255
    .line 256
    .line 257
    invoke-static {v15, v0}, Lia/b;->d(La21/a;Le21/a;)Lc21/d;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    new-instance v3, La21/d;

    .line 262
    .line 263
    invoke-direct {v3, v0, v1}, La21/d;-><init>(Le21/a;Lc21/b;)V

    .line 264
    .line 265
    .line 266
    const-class v0, Lee0/a;

    .line 267
    .line 268
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    const-class v1, Lme0/a;

    .line 273
    .line 274
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    new-array v2, v7, [Lhy0/d;

    .line 279
    .line 280
    aput-object v0, v2, v9

    .line 281
    .line 282
    aput-object v1, v2, v8

    .line 283
    .line 284
    invoke-static {v3, v2}, Llp/le;->a(La21/d;[Lhy0/d;)V

    .line 285
    .line 286
    .line 287
    return-object v14

    .line 288
    :pswitch_1
    move-object/from16 v0, p1

    .line 289
    .line 290
    check-cast v0, Lhi/a;

    .line 291
    .line 292
    const-string v1, "$this$single"

    .line 293
    .line 294
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    const-class v1, Lretrofit2/Retrofit;

    .line 298
    .line 299
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 300
    .line 301
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    check-cast v0, Lii/a;

    .line 306
    .line 307
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    check-cast v0, Lretrofit2/Retrofit;

    .line 312
    .line 313
    const-class v1, Lfe/d;

    .line 314
    .line 315
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    check-cast v0, Lfe/d;

    .line 320
    .line 321
    new-instance v1, Lfe/c;

    .line 322
    .line 323
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-direct {v1, v0}, Lfe/c;-><init>(Lfe/d;)V

    .line 327
    .line 328
    .line 329
    return-object v1

    .line 330
    :pswitch_2
    move-object/from16 v0, p1

    .line 331
    .line 332
    check-cast v0, Le21/a;

    .line 333
    .line 334
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    new-instance v1, Ld60/a;

    .line 338
    .line 339
    const/16 v2, 0xb

    .line 340
    .line 341
    invoke-direct {v1, v2}, Ld60/a;-><init>(I)V

    .line 342
    .line 343
    .line 344
    sget-object v6, Li21/b;->e:Lh21/b;

    .line 345
    .line 346
    sget-object v10, La21/c;->e:La21/c;

    .line 347
    .line 348
    new-instance v15, La21/a;

    .line 349
    .line 350
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 351
    .line 352
    const-class v3, Lga0/o;

    .line 353
    .line 354
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 355
    .line 356
    .line 357
    move-result-object v17

    .line 358
    const/16 v18, 0x0

    .line 359
    .line 360
    move-object/from16 v19, v1

    .line 361
    .line 362
    move-object/from16 v16, v6

    .line 363
    .line 364
    move-object/from16 v20, v10

    .line 365
    .line 366
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 367
    .line 368
    .line 369
    new-instance v1, Lc21/a;

    .line 370
    .line 371
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 372
    .line 373
    .line 374
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 375
    .line 376
    .line 377
    new-instance v9, Ld60/a;

    .line 378
    .line 379
    invoke-direct {v9, v4}, Ld60/a;-><init>(I)V

    .line 380
    .line 381
    .line 382
    new-instance v5, La21/a;

    .line 383
    .line 384
    const-class v1, Lga0/h0;

    .line 385
    .line 386
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 387
    .line 388
    .line 389
    move-result-object v7

    .line 390
    const/4 v8, 0x0

    .line 391
    invoke-direct/range {v5 .. v10}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 392
    .line 393
    .line 394
    new-instance v1, Lc21/a;

    .line 395
    .line 396
    invoke-direct {v1, v5}, Lc21/b;-><init>(La21/a;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 400
    .line 401
    .line 402
    new-instance v9, Ld60/a;

    .line 403
    .line 404
    const/16 v1, 0x8

    .line 405
    .line 406
    invoke-direct {v9, v1}, Ld60/a;-><init>(I)V

    .line 407
    .line 408
    .line 409
    new-instance v5, La21/a;

    .line 410
    .line 411
    const-class v1, Lea0/b;

    .line 412
    .line 413
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 414
    .line 415
    .line 416
    move-result-object v7

    .line 417
    invoke-direct/range {v5 .. v10}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 418
    .line 419
    .line 420
    new-instance v1, Lc21/a;

    .line 421
    .line 422
    invoke-direct {v1, v5}, Lc21/b;-><init>(La21/a;)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 426
    .line 427
    .line 428
    new-instance v9, Ld60/a;

    .line 429
    .line 430
    const/16 v1, 0x9

    .line 431
    .line 432
    invoke-direct {v9, v1}, Ld60/a;-><init>(I)V

    .line 433
    .line 434
    .line 435
    new-instance v5, La21/a;

    .line 436
    .line 437
    const-class v1, Lea0/c;

    .line 438
    .line 439
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 440
    .line 441
    .line 442
    move-result-object v7

    .line 443
    invoke-direct/range {v5 .. v10}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 444
    .line 445
    .line 446
    new-instance v1, Lc21/a;

    .line 447
    .line 448
    invoke-direct {v1, v5}, Lc21/b;-><init>(La21/a;)V

    .line 449
    .line 450
    .line 451
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 452
    .line 453
    .line 454
    new-instance v9, Ld60/a;

    .line 455
    .line 456
    invoke-direct {v9, v12}, Ld60/a;-><init>(I)V

    .line 457
    .line 458
    .line 459
    new-instance v5, La21/a;

    .line 460
    .line 461
    const-class v1, Lea0/a;

    .line 462
    .line 463
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 464
    .line 465
    .line 466
    move-result-object v7

    .line 467
    invoke-direct/range {v5 .. v10}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 468
    .line 469
    .line 470
    invoke-static {v5, v0}, Lvj/b;->v(La21/a;Le21/a;)V

    .line 471
    .line 472
    .line 473
    return-object v14

    .line 474
    :pswitch_3
    move-object/from16 v0, p1

    .line 475
    .line 476
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 477
    .line 478
    const-string v1, "input"

    .line 479
    .line 480
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    instance-of v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 484
    .line 485
    if-eqz v1, :cond_2

    .line 486
    .line 487
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 488
    .line 489
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;->getData()Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    move-result-object v0

    .line 493
    instance-of v1, v0, Lk71/b;

    .line 494
    .line 495
    if-eqz v1, :cond_0

    .line 496
    .line 497
    check-cast v0, Lk71/b;

    .line 498
    .line 499
    goto :goto_0

    .line 500
    :cond_0
    move-object v0, v6

    .line 501
    :goto_0
    if-eqz v0, :cond_1

    .line 502
    .line 503
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 504
    .line 505
    goto :goto_1

    .line 506
    :cond_1
    move-object v0, v6

    .line 507
    :goto_1
    sget-object v1, Lk71/c;->e:Lk71/c;

    .line 508
    .line 509
    if-ne v0, v1, :cond_2

    .line 510
    .line 511
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connected;

    .line 512
    .line 513
    invoke-direct {v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connected;-><init>()V

    .line 514
    .line 515
    .line 516
    :cond_2
    return-object v6

    .line 517
    :pswitch_4
    move-object/from16 v0, p1

    .line 518
    .line 519
    check-cast v0, Lql0/f;

    .line 520
    .line 521
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 522
    .line 523
    .line 524
    return-object v14

    .line 525
    :pswitch_5
    move-object/from16 v0, p1

    .line 526
    .line 527
    check-cast v0, Lql0/f;

    .line 528
    .line 529
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 530
    .line 531
    .line 532
    return-object v14

    .line 533
    :pswitch_6
    move-object/from16 v0, p1

    .line 534
    .line 535
    check-cast v0, Lg3/d;

    .line 536
    .line 537
    const-string v1, "$this$LinearProgressIndicator"

    .line 538
    .line 539
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    return-object v14

    .line 543
    :pswitch_7
    move-object/from16 v0, p1

    .line 544
    .line 545
    check-cast v0, Lvz0/i;

    .line 546
    .line 547
    const-string v1, "$this$Json"

    .line 548
    .line 549
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    iput-boolean v8, v0, Lvz0/i;->a:Z

    .line 553
    .line 554
    iput-boolean v8, v0, Lvz0/i;->c:Z

    .line 555
    .line 556
    return-object v14

    .line 557
    :pswitch_8
    move-object/from16 v0, p1

    .line 558
    .line 559
    check-cast v0, Le21/a;

    .line 560
    .line 561
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    new-instance v1, Ld60/a;

    .line 565
    .line 566
    const/4 v2, 0x6

    .line 567
    invoke-direct {v1, v2}, Ld60/a;-><init>(I)V

    .line 568
    .line 569
    .line 570
    sget-object v16, Li21/b;->e:Lh21/b;

    .line 571
    .line 572
    sget-object v20, La21/c;->e:La21/c;

    .line 573
    .line 574
    new-instance v15, La21/a;

    .line 575
    .line 576
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 577
    .line 578
    const-class v4, Lg60/b0;

    .line 579
    .line 580
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 581
    .line 582
    .line 583
    move-result-object v17

    .line 584
    const/16 v18, 0x0

    .line 585
    .line 586
    move-object/from16 v19, v1

    .line 587
    .line 588
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 589
    .line 590
    .line 591
    new-instance v1, Lc21/a;

    .line 592
    .line 593
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 597
    .line 598
    .line 599
    new-instance v1, Ld60/a;

    .line 600
    .line 601
    const/4 v4, 0x7

    .line 602
    invoke-direct {v1, v4}, Ld60/a;-><init>(I)V

    .line 603
    .line 604
    .line 605
    new-instance v15, La21/a;

    .line 606
    .line 607
    const-class v4, Lg60/i;

    .line 608
    .line 609
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 610
    .line 611
    .line 612
    move-result-object v17

    .line 613
    move-object/from16 v19, v1

    .line 614
    .line 615
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 616
    .line 617
    .line 618
    new-instance v1, Lc21/a;

    .line 619
    .line 620
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 621
    .line 622
    .line 623
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 624
    .line 625
    .line 626
    new-instance v1, Lbs0/a;

    .line 627
    .line 628
    const/16 v4, 0x1c

    .line 629
    .line 630
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 631
    .line 632
    .line 633
    new-instance v15, La21/a;

    .line 634
    .line 635
    const-class v4, Le60/b;

    .line 636
    .line 637
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 638
    .line 639
    .line 640
    move-result-object v17

    .line 641
    move-object/from16 v19, v1

    .line 642
    .line 643
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 644
    .line 645
    .line 646
    new-instance v1, Lc21/a;

    .line 647
    .line 648
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 649
    .line 650
    .line 651
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 652
    .line 653
    .line 654
    new-instance v1, Lbs0/a;

    .line 655
    .line 656
    const/16 v4, 0x1d

    .line 657
    .line 658
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 659
    .line 660
    .line 661
    new-instance v15, La21/a;

    .line 662
    .line 663
    const-class v4, Le60/c;

    .line 664
    .line 665
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 666
    .line 667
    .line 668
    move-result-object v17

    .line 669
    move-object/from16 v19, v1

    .line 670
    .line 671
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 672
    .line 673
    .line 674
    new-instance v1, Lc21/a;

    .line 675
    .line 676
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 677
    .line 678
    .line 679
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 680
    .line 681
    .line 682
    new-instance v1, Ld60/a;

    .line 683
    .line 684
    invoke-direct {v1, v9}, Ld60/a;-><init>(I)V

    .line 685
    .line 686
    .line 687
    new-instance v15, La21/a;

    .line 688
    .line 689
    const-class v4, Le60/n;

    .line 690
    .line 691
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 692
    .line 693
    .line 694
    move-result-object v17

    .line 695
    move-object/from16 v19, v1

    .line 696
    .line 697
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 698
    .line 699
    .line 700
    new-instance v1, Lc21/a;

    .line 701
    .line 702
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 703
    .line 704
    .line 705
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 706
    .line 707
    .line 708
    new-instance v1, Ld60/a;

    .line 709
    .line 710
    invoke-direct {v1, v8}, Ld60/a;-><init>(I)V

    .line 711
    .line 712
    .line 713
    new-instance v15, La21/a;

    .line 714
    .line 715
    const-class v4, Le60/f;

    .line 716
    .line 717
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 718
    .line 719
    .line 720
    move-result-object v17

    .line 721
    move-object/from16 v19, v1

    .line 722
    .line 723
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 724
    .line 725
    .line 726
    new-instance v1, Lc21/a;

    .line 727
    .line 728
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 729
    .line 730
    .line 731
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 732
    .line 733
    .line 734
    new-instance v1, Ld60/a;

    .line 735
    .line 736
    invoke-direct {v1, v7}, Ld60/a;-><init>(I)V

    .line 737
    .line 738
    .line 739
    new-instance v15, La21/a;

    .line 740
    .line 741
    const-class v4, Le60/h;

    .line 742
    .line 743
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 744
    .line 745
    .line 746
    move-result-object v17

    .line 747
    move-object/from16 v19, v1

    .line 748
    .line 749
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 750
    .line 751
    .line 752
    new-instance v1, Lc21/a;

    .line 753
    .line 754
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 755
    .line 756
    .line 757
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 758
    .line 759
    .line 760
    new-instance v1, Ld60/a;

    .line 761
    .line 762
    const/4 v4, 0x3

    .line 763
    invoke-direct {v1, v4}, Ld60/a;-><init>(I)V

    .line 764
    .line 765
    .line 766
    new-instance v15, La21/a;

    .line 767
    .line 768
    const-class v4, Le60/j;

    .line 769
    .line 770
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 771
    .line 772
    .line 773
    move-result-object v17

    .line 774
    move-object/from16 v19, v1

    .line 775
    .line 776
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 777
    .line 778
    .line 779
    new-instance v1, Lc21/a;

    .line 780
    .line 781
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 782
    .line 783
    .line 784
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 785
    .line 786
    .line 787
    new-instance v1, Ld60/a;

    .line 788
    .line 789
    const/4 v4, 0x4

    .line 790
    invoke-direct {v1, v4}, Ld60/a;-><init>(I)V

    .line 791
    .line 792
    .line 793
    new-instance v15, La21/a;

    .line 794
    .line 795
    const-class v4, Le60/k;

    .line 796
    .line 797
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 798
    .line 799
    .line 800
    move-result-object v17

    .line 801
    move-object/from16 v19, v1

    .line 802
    .line 803
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 804
    .line 805
    .line 806
    new-instance v1, Lc21/a;

    .line 807
    .line 808
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 809
    .line 810
    .line 811
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 812
    .line 813
    .line 814
    new-instance v1, Ld60/a;

    .line 815
    .line 816
    const/4 v4, 0x5

    .line 817
    invoke-direct {v1, v4}, Ld60/a;-><init>(I)V

    .line 818
    .line 819
    .line 820
    new-instance v15, La21/a;

    .line 821
    .line 822
    const-class v4, Le60/i;

    .line 823
    .line 824
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 825
    .line 826
    .line 827
    move-result-object v17

    .line 828
    move-object/from16 v19, v1

    .line 829
    .line 830
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 831
    .line 832
    .line 833
    new-instance v1, Lc21/a;

    .line 834
    .line 835
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 836
    .line 837
    .line 838
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 839
    .line 840
    .line 841
    new-instance v1, Lck/a;

    .line 842
    .line 843
    invoke-direct {v1, v3}, Lck/a;-><init>(I)V

    .line 844
    .line 845
    .line 846
    sget-object v20, La21/c;->d:La21/c;

    .line 847
    .line 848
    new-instance v15, La21/a;

    .line 849
    .line 850
    const-class v3, Lc60/b;

    .line 851
    .line 852
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 853
    .line 854
    .line 855
    move-result-object v17

    .line 856
    move-object/from16 v19, v1

    .line 857
    .line 858
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 859
    .line 860
    .line 861
    invoke-static {v15, v0}, Lf2/m0;->t(La21/a;Le21/a;)V

    .line 862
    .line 863
    .line 864
    return-object v14

    .line 865
    :pswitch_9
    move-object/from16 v0, p1

    .line 866
    .line 867
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;

    .line 868
    .line 869
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 870
    .line 871
    .line 872
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getPointBalance()I

    .line 873
    .line 874
    .line 875
    move-result v15

    .line 876
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getEnrollmentCountryCode()Ljava/lang/String;

    .line 877
    .line 878
    .line 879
    move-result-object v1

    .line 880
    const-string v2, "isoCode"

    .line 881
    .line 882
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 883
    .line 884
    .line 885
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 886
    .line 887
    .line 888
    move-result v2

    .line 889
    if-ne v2, v7, :cond_7

    .line 890
    .line 891
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 892
    .line 893
    invoke-virtual {v1, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 894
    .line 895
    .line 896
    move-result-object v1

    .line 897
    const-string v2, "toUpperCase(...)"

    .line 898
    .line 899
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 900
    .line 901
    .line 902
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getMemberReferralCode()Ljava/lang/String;

    .line 903
    .line 904
    .line 905
    move-result-object v17

    .line 906
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getDailyCheckInCollected()Z

    .line 907
    .line 908
    .line 909
    move-result v18

    .line 910
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getInProgressChallenges()Ljava/util/List;

    .line 911
    .line 912
    .line 913
    move-result-object v2

    .line 914
    check-cast v2, Ljava/lang/Iterable;

    .line 915
    .line 916
    new-instance v3, Ljava/util/ArrayList;

    .line 917
    .line 918
    invoke-static {v2, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 919
    .line 920
    .line 921
    move-result v4

    .line 922
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 923
    .line 924
    .line 925
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 926
    .line 927
    .line 928
    move-result-object v2

    .line 929
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 930
    .line 931
    .line 932
    move-result v4

    .line 933
    if-eqz v4, :cond_3

    .line 934
    .line 935
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object v4

    .line 939
    check-cast v4, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;

    .line 940
    .line 941
    invoke-static {v4}, Ljp/gf;->c(Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;)Lg40/p;

    .line 942
    .line 943
    .line 944
    move-result-object v4

    .line 945
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 946
    .line 947
    .line 948
    goto :goto_2

    .line 949
    :cond_3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getActiveRewards()Ljava/util/List;

    .line 950
    .line 951
    .line 952
    move-result-object v2

    .line 953
    check-cast v2, Ljava/lang/Iterable;

    .line 954
    .line 955
    new-instance v4, Ljava/util/ArrayList;

    .line 956
    .line 957
    invoke-static {v2, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 958
    .line 959
    .line 960
    move-result v5

    .line 961
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 962
    .line 963
    .line 964
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 965
    .line 966
    .line 967
    move-result-object v2

    .line 968
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 969
    .line 970
    .line 971
    move-result v5

    .line 972
    if-eqz v5, :cond_4

    .line 973
    .line 974
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 975
    .line 976
    .line 977
    move-result-object v5

    .line 978
    check-cast v5, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;

    .line 979
    .line 980
    invoke-static {v5}, Ljp/jf;->c(Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;)Lg40/a;

    .line 981
    .line 982
    .line 983
    move-result-object v5

    .line 984
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 985
    .line 986
    .line 987
    goto :goto_3

    .line 988
    :cond_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getDailyCheckInChallenge()Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 989
    .line 990
    .line 991
    move-result-object v2

    .line 992
    if-eqz v2, :cond_5

    .line 993
    .line 994
    new-instance v5, Lg40/y;

    .line 995
    .line 996
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;->getChallengeLength()I

    .line 997
    .line 998
    .line 999
    move-result v7

    .line 1000
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;->getStreakLength()I

    .line 1001
    .line 1002
    .line 1003
    move-result v2

    .line 1004
    invoke-direct {v5, v7, v2}, Lg40/y;-><init>(II)V

    .line 1005
    .line 1006
    .line 1007
    move-object/from16 v21, v5

    .line 1008
    .line 1009
    goto :goto_4

    .line 1010
    :cond_5
    move-object/from16 v21, v6

    .line 1011
    .line 1012
    :goto_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getReferralChallenge()Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v2

    .line 1016
    if-eqz v2, :cond_6

    .line 1017
    .line 1018
    new-instance v7, Lg40/r0;

    .line 1019
    .line 1020
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getName()Ljava/lang/String;

    .line 1021
    .line 1022
    .line 1023
    move-result-object v8

    .line 1024
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getDescription()Ljava/lang/String;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v9

    .line 1028
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getDetailedDescription()Ljava/lang/String;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v10

    .line 1032
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getPoints()I

    .line 1033
    .line 1034
    .line 1035
    move-result v11

    .line 1036
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getImageUrl()Ljava/lang/String;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v12

    .line 1040
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getTotalActivities()I

    .line 1041
    .line 1042
    .line 1043
    move-result v13

    .line 1044
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/ReferralChallengeDto;->getCompletedActivities()I

    .line 1045
    .line 1046
    .line 1047
    move-result v14

    .line 1048
    invoke-direct/range {v7 .. v14}, Lg40/r0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;II)V

    .line 1049
    .line 1050
    .line 1051
    move-object/from16 v22, v7

    .line 1052
    .line 1053
    goto :goto_5

    .line 1054
    :cond_6
    move-object/from16 v22, v6

    .line 1055
    .line 1056
    :goto_5
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getEnrolledToLoyaltyBadges()Z

    .line 1057
    .line 1058
    .line 1059
    move-result v23

    .line 1060
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfileDto;->getConsentRequired()Z

    .line 1061
    .line 1062
    .line 1063
    move-result v24

    .line 1064
    new-instance v14, Lg40/o0;

    .line 1065
    .line 1066
    move-object/from16 v16, v1

    .line 1067
    .line 1068
    move-object/from16 v19, v3

    .line 1069
    .line 1070
    move-object/from16 v20, v4

    .line 1071
    .line 1072
    invoke-direct/range {v14 .. v24}, Lg40/o0;-><init>(ILjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;Ljava/util/ArrayList;Lg40/y;Lg40/r0;ZZ)V

    .line 1073
    .line 1074
    .line 1075
    return-object v14

    .line 1076
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1077
    .line 1078
    const-string v1, "Iso code doesn\'t match ISO 3166-1 Alpha-2"

    .line 1079
    .line 1080
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1081
    .line 1082
    .line 1083
    throw v0

    .line 1084
    :pswitch_a
    move-object/from16 v0, p1

    .line 1085
    .line 1086
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;

    .line 1087
    .line 1088
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1089
    .line 1090
    .line 1091
    new-instance v14, Lg40/i;

    .line 1092
    .line 1093
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getId()Ljava/lang/String;

    .line 1094
    .line 1095
    .line 1096
    move-result-object v15

    .line 1097
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getName()Ljava/lang/String;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v16

    .line 1101
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getDescription()Ljava/lang/String;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v17

    .line 1105
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getDisclaimer()Ljava/lang/String;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v18

    .line 1109
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getCategory()Ljava/lang/String;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v19

    .line 1113
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getButton()Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailButtonDto;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1118
    .line 1119
    .line 1120
    new-instance v3, Lg40/j;

    .line 1121
    .line 1122
    invoke-virtual {v1}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailButtonDto;->getTitle()Ljava/lang/String;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v4

    .line 1126
    invoke-virtual {v1}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailButtonDto;->getAction()Ljava/lang/String;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v1

    .line 1130
    if-eqz v1, :cond_9

    .line 1131
    .line 1132
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 1133
    .line 1134
    .line 1135
    move-result v6

    .line 1136
    sparse-switch v6, :sswitch_data_0

    .line 1137
    .line 1138
    .line 1139
    goto :goto_7

    .line 1140
    :sswitch_0
    const-string v6, "COLLECT"

    .line 1141
    .line 1142
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1143
    .line 1144
    .line 1145
    move-result v1

    .line 1146
    if-eqz v1, :cond_8

    .line 1147
    .line 1148
    sget-object v1, Lg40/k;->h:Lg40/k;

    .line 1149
    .line 1150
    :goto_6
    move-object v6, v1

    .line 1151
    goto :goto_8

    .line 1152
    :sswitch_1
    const-string v6, "CONSENTS"

    .line 1153
    .line 1154
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1155
    .line 1156
    .line 1157
    move-result v1

    .line 1158
    if-eqz v1, :cond_8

    .line 1159
    .line 1160
    sget-object v1, Lg40/k;->g:Lg40/k;

    .line 1161
    .line 1162
    goto :goto_6

    .line 1163
    :sswitch_2
    const-string v6, "SERVICE_PARTNER"

    .line 1164
    .line 1165
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1166
    .line 1167
    .line 1168
    move-result v1

    .line 1169
    if-eqz v1, :cond_8

    .line 1170
    .line 1171
    sget-object v1, Lg40/k;->e:Lg40/k;

    .line 1172
    .line 1173
    goto :goto_6

    .line 1174
    :sswitch_3
    const-string v6, "INVITE_FRIENDS"

    .line 1175
    .line 1176
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1177
    .line 1178
    .line 1179
    move-result v1

    .line 1180
    if-eqz v1, :cond_8

    .line 1181
    .line 1182
    sget-object v1, Lg40/k;->f:Lg40/k;

    .line 1183
    .line 1184
    goto :goto_6

    .line 1185
    :cond_8
    :goto_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1186
    .line 1187
    const-string v1, "Unsupported badge detail button action"

    .line 1188
    .line 1189
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1190
    .line 1191
    .line 1192
    throw v0

    .line 1193
    :cond_9
    :goto_8
    invoke-direct {v3, v4, v6}, Lg40/j;-><init>(Ljava/lang/String;Lg40/k;)V

    .line 1194
    .line 1195
    .line 1196
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getImage()Ljava/lang/String;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v21

    .line 1200
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDetailDto;->getProgress()Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v0

    .line 1204
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1205
    .line 1206
    .line 1207
    new-instance v1, Lg40/l;

    .line 1208
    .line 1209
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->getStatus()Ljava/lang/String;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v4

    .line 1213
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1214
    .line 1215
    .line 1216
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 1217
    .line 1218
    .line 1219
    move-result v5

    .line 1220
    sparse-switch v5, :sswitch_data_1

    .line 1221
    .line 1222
    .line 1223
    goto :goto_a

    .line 1224
    :sswitch_4
    const-string v2, "COMPLETED"

    .line 1225
    .line 1226
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1227
    .line 1228
    .line 1229
    move-result v2

    .line 1230
    if-eqz v2, :cond_a

    .line 1231
    .line 1232
    sget-object v2, Lg40/m;->f:Lg40/m;

    .line 1233
    .line 1234
    goto :goto_9

    .line 1235
    :sswitch_5
    const-string v2, "UNKNOWN"

    .line 1236
    .line 1237
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1238
    .line 1239
    .line 1240
    move-result v2

    .line 1241
    if-eqz v2, :cond_a

    .line 1242
    .line 1243
    sget-object v2, Lg40/m;->g:Lg40/m;

    .line 1244
    .line 1245
    goto :goto_9

    .line 1246
    :sswitch_6
    const-string v2, "IN_PROGRESS"

    .line 1247
    .line 1248
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1249
    .line 1250
    .line 1251
    move-result v2

    .line 1252
    if-eqz v2, :cond_a

    .line 1253
    .line 1254
    sget-object v2, Lg40/m;->e:Lg40/m;

    .line 1255
    .line 1256
    goto :goto_9

    .line 1257
    :sswitch_7
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1258
    .line 1259
    .line 1260
    move-result v2

    .line 1261
    if-eqz v2, :cond_a

    .line 1262
    .line 1263
    sget-object v2, Lg40/m;->d:Lg40/m;

    .line 1264
    .line 1265
    :goto_9
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->getProgressInPct()I

    .line 1266
    .line 1267
    .line 1268
    move-result v4

    .line 1269
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->getCollected()Z

    .line 1270
    .line 1271
    .line 1272
    move-result v5

    .line 1273
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeProgressDto;->getCollectedAt()Ljava/time/OffsetDateTime;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v0

    .line 1277
    invoke-direct {v1, v2, v4, v5, v0}, Lg40/l;-><init>(Lg40/m;IZLjava/time/OffsetDateTime;)V

    .line 1278
    .line 1279
    .line 1280
    move-object/from16 v22, v1

    .line 1281
    .line 1282
    move-object/from16 v20, v3

    .line 1283
    .line 1284
    invoke-direct/range {v14 .. v22}, Lg40/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lg40/j;Ljava/lang/String;Lg40/l;)V

    .line 1285
    .line 1286
    .line 1287
    return-object v14

    .line 1288
    :cond_a
    :goto_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1289
    .line 1290
    const-string v1, "Unsupported badge progress status"

    .line 1291
    .line 1292
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1293
    .line 1294
    .line 1295
    throw v0

    .line 1296
    :pswitch_b
    move-object/from16 v0, p1

    .line 1297
    .line 1298
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;

    .line 1299
    .line 1300
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1301
    .line 1302
    .line 1303
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->getAccountPointBalance()I

    .line 1304
    .line 1305
    .line 1306
    move-result v1

    .line 1307
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->getDailyCheckInCollected()Z

    .line 1308
    .line 1309
    .line 1310
    move-result v2

    .line 1311
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->getChallenges()Ljava/util/List;

    .line 1312
    .line 1313
    .line 1314
    move-result-object v3

    .line 1315
    check-cast v3, Ljava/lang/Iterable;

    .line 1316
    .line 1317
    new-instance v4, Ljava/util/ArrayList;

    .line 1318
    .line 1319
    invoke-static {v3, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1320
    .line 1321
    .line 1322
    move-result v5

    .line 1323
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 1324
    .line 1325
    .line 1326
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v3

    .line 1330
    :goto_b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1331
    .line 1332
    .line 1333
    move-result v5

    .line 1334
    if-eqz v5, :cond_b

    .line 1335
    .line 1336
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v5

    .line 1340
    check-cast v5, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;

    .line 1341
    .line 1342
    invoke-static {v5}, Ljp/gf;->c(Lcz/myskoda/api/bff_loyalty_program/v2/ChallengeDto;)Lg40/p;

    .line 1343
    .line 1344
    .line 1345
    move-result-object v5

    .line 1346
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1347
    .line 1348
    .line 1349
    goto :goto_b

    .line 1350
    :cond_b
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ChallengesDto;->getDailyCheckInChallenge()Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v0

    .line 1354
    if-eqz v0, :cond_c

    .line 1355
    .line 1356
    new-instance v6, Lg40/y;

    .line 1357
    .line 1358
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;->getChallengeLength()I

    .line 1359
    .line 1360
    .line 1361
    move-result v3

    .line 1362
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/DailyCheckInChallengeDto;->getStreakLength()I

    .line 1363
    .line 1364
    .line 1365
    move-result v0

    .line 1366
    invoke-direct {v6, v3, v0}, Lg40/y;-><init>(II)V

    .line 1367
    .line 1368
    .line 1369
    :cond_c
    new-instance v0, Lg40/t;

    .line 1370
    .line 1371
    invoke-direct {v0, v1, v2, v4, v6}, Lg40/t;-><init>(IZLjava/util/ArrayList;Lg40/y;)V

    .line 1372
    .line 1373
    .line 1374
    return-object v0

    .line 1375
    :pswitch_c
    move-object/from16 v0, p1

    .line 1376
    .line 1377
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;

    .line 1378
    .line 1379
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1380
    .line 1381
    .line 1382
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getAccountPointBalance()I

    .line 1383
    .line 1384
    .line 1385
    move-result v15

    .line 1386
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getAvailableRewards()Ljava/util/List;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v1

    .line 1390
    check-cast v1, Ljava/lang/Iterable;

    .line 1391
    .line 1392
    new-instance v2, Ljava/util/ArrayList;

    .line 1393
    .line 1394
    invoke-static {v1, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1395
    .line 1396
    .line 1397
    move-result v3

    .line 1398
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1399
    .line 1400
    .line 1401
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1402
    .line 1403
    .line 1404
    move-result-object v1

    .line 1405
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1406
    .line 1407
    .line 1408
    move-result v3

    .line 1409
    if-eqz v3, :cond_d

    .line 1410
    .line 1411
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1412
    .line 1413
    .line 1414
    move-result-object v3

    .line 1415
    check-cast v3, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;

    .line 1416
    .line 1417
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1418
    .line 1419
    .line 1420
    new-instance v16, Lg40/f;

    .line 1421
    .line 1422
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getId()Ljava/lang/String;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v17

    .line 1426
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getName()Ljava/lang/String;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v18

    .line 1430
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getDescription()Ljava/lang/String;

    .line 1431
    .line 1432
    .line 1433
    move-result-object v19

    .line 1434
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getDetailedDescription()Ljava/lang/String;

    .line 1435
    .line 1436
    .line 1437
    move-result-object v20

    .line 1438
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getPointsRequired()I

    .line 1439
    .line 1440
    .line 1441
    move-result v21

    .line 1442
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableRewardDto;->getImageUrls()Ljava/util/List;

    .line 1443
    .line 1444
    .line 1445
    move-result-object v22

    .line 1446
    invoke-direct/range {v16 .. v22}, Lg40/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/util/List;)V

    .line 1447
    .line 1448
    .line 1449
    move-object/from16 v3, v16

    .line 1450
    .line 1451
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1452
    .line 1453
    .line 1454
    goto :goto_c

    .line 1455
    :cond_d
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getActiveRewards()Ljava/util/List;

    .line 1456
    .line 1457
    .line 1458
    move-result-object v1

    .line 1459
    check-cast v1, Ljava/lang/Iterable;

    .line 1460
    .line 1461
    new-instance v3, Ljava/util/ArrayList;

    .line 1462
    .line 1463
    invoke-static {v1, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1464
    .line 1465
    .line 1466
    move-result v4

    .line 1467
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 1468
    .line 1469
    .line 1470
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1471
    .line 1472
    .line 1473
    move-result-object v1

    .line 1474
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1475
    .line 1476
    .line 1477
    move-result v4

    .line 1478
    if-eqz v4, :cond_e

    .line 1479
    .line 1480
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1481
    .line 1482
    .line 1483
    move-result-object v4

    .line 1484
    check-cast v4, Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;

    .line 1485
    .line 1486
    invoke-static {v4}, Ljp/jf;->c(Lcz/myskoda/api/bff_loyalty_program/v2/ActiveRewardDto;)Lg40/a;

    .line 1487
    .line 1488
    .line 1489
    move-result-object v4

    .line 1490
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1491
    .line 1492
    .line 1493
    goto :goto_d

    .line 1494
    :cond_e
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getRedeemedRewards()Ljava/util/List;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v1

    .line 1498
    check-cast v1, Ljava/lang/Iterable;

    .line 1499
    .line 1500
    new-instance v4, Ljava/util/ArrayList;

    .line 1501
    .line 1502
    invoke-static {v1, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1503
    .line 1504
    .line 1505
    move-result v6

    .line 1506
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 1507
    .line 1508
    .line 1509
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1510
    .line 1511
    .line 1512
    move-result-object v1

    .line 1513
    :goto_e
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1514
    .line 1515
    .line 1516
    move-result v6

    .line 1517
    if-eqz v6, :cond_f

    .line 1518
    .line 1519
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v6

    .line 1523
    check-cast v6, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedRewardDto;

    .line 1524
    .line 1525
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1526
    .line 1527
    .line 1528
    new-instance v7, Lg40/p0;

    .line 1529
    .line 1530
    invoke-virtual {v6}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedRewardDto;->getId()Ljava/lang/String;

    .line 1531
    .line 1532
    .line 1533
    move-result-object v8

    .line 1534
    invoke-virtual {v6}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedRewardDto;->getName()Ljava/lang/String;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v9

    .line 1538
    invoke-virtual {v6}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedRewardDto;->getImageUrls()Ljava/util/List;

    .line 1539
    .line 1540
    .line 1541
    move-result-object v6

    .line 1542
    invoke-direct {v7, v8, v9, v6}, Lg40/p0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 1543
    .line 1544
    .line 1545
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1546
    .line 1547
    .line 1548
    goto :goto_e

    .line 1549
    :cond_f
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getAvailableVouchers()Ljava/util/List;

    .line 1550
    .line 1551
    .line 1552
    move-result-object v1

    .line 1553
    check-cast v1, Ljava/lang/Iterable;

    .line 1554
    .line 1555
    new-instance v6, Ljava/util/ArrayList;

    .line 1556
    .line 1557
    invoke-static {v1, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1558
    .line 1559
    .line 1560
    move-result v7

    .line 1561
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 1562
    .line 1563
    .line 1564
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1565
    .line 1566
    .line 1567
    move-result-object v1

    .line 1568
    :goto_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1569
    .line 1570
    .line 1571
    move-result v7

    .line 1572
    if-eqz v7, :cond_10

    .line 1573
    .line 1574
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1575
    .line 1576
    .line 1577
    move-result-object v7

    .line 1578
    check-cast v7, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;

    .line 1579
    .line 1580
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1581
    .line 1582
    .line 1583
    new-instance v16, Lg40/g;

    .line 1584
    .line 1585
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getId()Ljava/lang/String;

    .line 1586
    .line 1587
    .line 1588
    move-result-object v17

    .line 1589
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getName()Ljava/lang/String;

    .line 1590
    .line 1591
    .line 1592
    move-result-object v18

    .line 1593
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getDescription()Ljava/lang/String;

    .line 1594
    .line 1595
    .line 1596
    move-result-object v19

    .line 1597
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getDetailedDescription()Ljava/lang/String;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v20

    .line 1601
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getTermsAndConditionsUrl()Ljava/lang/String;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v21

    .line 1605
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getPointsRequired()I

    .line 1606
    .line 1607
    .line 1608
    move-result v22

    .line 1609
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getImageUrls()Ljava/util/List;

    .line 1610
    .line 1611
    .line 1612
    move-result-object v23

    .line 1613
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getValue()Ljava/lang/Double;

    .line 1614
    .line 1615
    .line 1616
    move-result-object v24

    .line 1617
    invoke-virtual {v7}, Lcz/myskoda/api/bff_loyalty_program/v2/AvailableVoucherDto;->getCurrency()Ljava/lang/String;

    .line 1618
    .line 1619
    .line 1620
    move-result-object v25

    .line 1621
    invoke-direct/range {v16 .. v25}, Lg40/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/util/List;Ljava/lang/Double;Ljava/lang/String;)V

    .line 1622
    .line 1623
    .line 1624
    move-object/from16 v7, v16

    .line 1625
    .line 1626
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1627
    .line 1628
    .line 1629
    goto :goto_f

    .line 1630
    :cond_10
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getIssuedVouchers()Ljava/util/List;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v1

    .line 1634
    check-cast v1, Ljava/lang/Iterable;

    .line 1635
    .line 1636
    new-instance v7, Ljava/util/ArrayList;

    .line 1637
    .line 1638
    invoke-static {v1, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1639
    .line 1640
    .line 1641
    move-result v8

    .line 1642
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 1643
    .line 1644
    .line 1645
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1646
    .line 1647
    .line 1648
    move-result-object v1

    .line 1649
    :goto_10
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1650
    .line 1651
    .line 1652
    move-result v8

    .line 1653
    if-eqz v8, :cond_11

    .line 1654
    .line 1655
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1656
    .line 1657
    .line 1658
    move-result-object v8

    .line 1659
    check-cast v8, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;

    .line 1660
    .line 1661
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1662
    .line 1663
    .line 1664
    new-instance v16, Lg40/b0;

    .line 1665
    .line 1666
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getId()Ljava/lang/String;

    .line 1667
    .line 1668
    .line 1669
    move-result-object v19

    .line 1670
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getCategory()Ljava/lang/String;

    .line 1671
    .line 1672
    .line 1673
    move-result-object v9

    .line 1674
    invoke-static {v9}, Ljp/jf;->b(Ljava/lang/String;)Lg40/c0;

    .line 1675
    .line 1676
    .line 1677
    move-result-object v17

    .line 1678
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getName()Ljava/lang/String;

    .line 1679
    .line 1680
    .line 1681
    move-result-object v20

    .line 1682
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getDescription()Ljava/lang/String;

    .line 1683
    .line 1684
    .line 1685
    move-result-object v21

    .line 1686
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getDetailedDescription()Ljava/lang/String;

    .line 1687
    .line 1688
    .line 1689
    move-result-object v22

    .line 1690
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getTermsAndConditionsUrl()Ljava/lang/String;

    .line 1691
    .line 1692
    .line 1693
    move-result-object v23

    .line 1694
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getVoucherCode()Ljava/lang/String;

    .line 1695
    .line 1696
    .line 1697
    move-result-object v24

    .line 1698
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getExpirationDate()Ljava/time/LocalDate;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v27

    .line 1702
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getImageUrls()Ljava/util/List;

    .line 1703
    .line 1704
    .line 1705
    move-result-object v28

    .line 1706
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getProductCode()Ljava/lang/String;

    .line 1707
    .line 1708
    .line 1709
    move-result-object v25

    .line 1710
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getValue()Ljava/lang/Double;

    .line 1711
    .line 1712
    .line 1713
    move-result-object v18

    .line 1714
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/IssuedVoucherDto;->getCurrency()Ljava/lang/String;

    .line 1715
    .line 1716
    .line 1717
    move-result-object v26

    .line 1718
    invoke-direct/range {v16 .. v28}, Lg40/b0;-><init>(Lg40/c0;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/util/List;)V

    .line 1719
    .line 1720
    .line 1721
    move-object/from16 v8, v16

    .line 1722
    .line 1723
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1724
    .line 1725
    .line 1726
    goto :goto_10

    .line 1727
    :cond_11
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/RewardsDto;->getRedeemedVouchers()Ljava/util/List;

    .line 1728
    .line 1729
    .line 1730
    move-result-object v0

    .line 1731
    check-cast v0, Ljava/lang/Iterable;

    .line 1732
    .line 1733
    new-instance v1, Ljava/util/ArrayList;

    .line 1734
    .line 1735
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1736
    .line 1737
    .line 1738
    move-result v8

    .line 1739
    invoke-direct {v1, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 1740
    .line 1741
    .line 1742
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1743
    .line 1744
    .line 1745
    move-result-object v0

    .line 1746
    :goto_11
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1747
    .line 1748
    .line 1749
    move-result v8

    .line 1750
    if-eqz v8, :cond_12

    .line 1751
    .line 1752
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1753
    .line 1754
    .line 1755
    move-result-object v8

    .line 1756
    check-cast v8, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;

    .line 1757
    .line 1758
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1759
    .line 1760
    .line 1761
    new-instance v9, Lg40/q0;

    .line 1762
    .line 1763
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;->getId()Ljava/lang/String;

    .line 1764
    .line 1765
    .line 1766
    move-result-object v10

    .line 1767
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;->getName()Ljava/lang/String;

    .line 1768
    .line 1769
    .line 1770
    move-result-object v11

    .line 1771
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;->getImageUrls()Ljava/util/List;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v12

    .line 1775
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;->getValue()Ljava/lang/Double;

    .line 1776
    .line 1777
    .line 1778
    move-result-object v13

    .line 1779
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/RedeemedVoucherDto;->getCurrency()Ljava/lang/String;

    .line 1780
    .line 1781
    .line 1782
    move-result-object v14

    .line 1783
    invoke-direct/range {v9 .. v14}, Lg40/q0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/Double;Ljava/lang/String;)V

    .line 1784
    .line 1785
    .line 1786
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1787
    .line 1788
    .line 1789
    goto :goto_11

    .line 1790
    :cond_12
    new-instance v14, Lg40/t0;

    .line 1791
    .line 1792
    move-object/from16 v21, v1

    .line 1793
    .line 1794
    move-object/from16 v16, v2

    .line 1795
    .line 1796
    move-object/from16 v17, v3

    .line 1797
    .line 1798
    move-object/from16 v18, v4

    .line 1799
    .line 1800
    move-object/from16 v19, v6

    .line 1801
    .line 1802
    move-object/from16 v20, v7

    .line 1803
    .line 1804
    invoke-direct/range {v14 .. v21}, Lg40/t0;-><init>(ILjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 1805
    .line 1806
    .line 1807
    return-object v14

    .line 1808
    :pswitch_d
    move-object/from16 v0, p1

    .line 1809
    .line 1810
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;

    .line 1811
    .line 1812
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1813
    .line 1814
    .line 1815
    new-instance v1, Lg40/v;

    .line 1816
    .line 1817
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getCategory()Ljava/lang/String;

    .line 1818
    .line 1819
    .line 1820
    move-result-object v2

    .line 1821
    invoke-static {v2}, Ljp/jf;->b(Ljava/lang/String;)Lg40/c0;

    .line 1822
    .line 1823
    .line 1824
    move-result-object v2

    .line 1825
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getName()Ljava/lang/String;

    .line 1826
    .line 1827
    .line 1828
    move-result-object v3

    .line 1829
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getVoucherCode()Ljava/lang/String;

    .line 1830
    .line 1831
    .line 1832
    move-result-object v4

    .line 1833
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getExpirationDate()Ljava/time/LocalDate;

    .line 1834
    .line 1835
    .line 1836
    move-result-object v5

    .line 1837
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getImageUrls()Ljava/util/List;

    .line 1838
    .line 1839
    .line 1840
    move-result-object v6

    .line 1841
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getProductCode()Ljava/lang/String;

    .line 1842
    .line 1843
    .line 1844
    move-result-object v7

    .line 1845
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getValue()Ljava/lang/Double;

    .line 1846
    .line 1847
    .line 1848
    move-result-object v8

    .line 1849
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/ClaimRewardResponseDto;->getCurrency()Ljava/lang/String;

    .line 1850
    .line 1851
    .line 1852
    move-result-object v9

    .line 1853
    invoke-direct/range {v1 .. v9}, Lg40/v;-><init>(Lg40/c0;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/util/List;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/String;)V

    .line 1854
    .line 1855
    .line 1856
    return-object v1

    .line 1857
    :pswitch_e
    move-object/from16 v0, p1

    .line 1858
    .line 1859
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDetailsDto;

    .line 1860
    .line 1861
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1862
    .line 1863
    .line 1864
    new-instance v1, Lg40/i0;

    .line 1865
    .line 1866
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDetailsDto;->getName()Ljava/lang/String;

    .line 1867
    .line 1868
    .line 1869
    move-result-object v2

    .line 1870
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramDetailsDto;->getRewardsAvailable()Z

    .line 1871
    .line 1872
    .line 1873
    move-result v0

    .line 1874
    invoke-direct {v1, v2, v0}, Lg40/i0;-><init>(Ljava/lang/String;Z)V

    .line 1875
    .line 1876
    .line 1877
    return-object v1

    .line 1878
    :pswitch_f
    move-object/from16 v0, p1

    .line 1879
    .line 1880
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/GamesResponseDto;

    .line 1881
    .line 1882
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1883
    .line 1884
    .line 1885
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/GamesResponseDto;->getGames()Ljava/util/List;

    .line 1886
    .line 1887
    .line 1888
    move-result-object v0

    .line 1889
    check-cast v0, Ljava/lang/Iterable;

    .line 1890
    .line 1891
    new-instance v1, Ljava/util/ArrayList;

    .line 1892
    .line 1893
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1894
    .line 1895
    .line 1896
    move-result v3

    .line 1897
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1898
    .line 1899
    .line 1900
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1901
    .line 1902
    .line 1903
    move-result-object v0

    .line 1904
    :goto_12
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1905
    .line 1906
    .line 1907
    move-result v3

    .line 1908
    if-eqz v3, :cond_1a

    .line 1909
    .line 1910
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1911
    .line 1912
    .line 1913
    move-result-object v3

    .line 1914
    check-cast v3, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;

    .line 1915
    .line 1916
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1917
    .line 1918
    .line 1919
    new-instance v13, Lg40/d0;

    .line 1920
    .line 1921
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getId()Ljava/lang/String;

    .line 1922
    .line 1923
    .line 1924
    move-result-object v14

    .line 1925
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getName()Ljava/lang/String;

    .line 1926
    .line 1927
    .line 1928
    move-result-object v15

    .line 1929
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getDescription()Ljava/lang/String;

    .line 1930
    .line 1931
    .line 1932
    move-result-object v16

    .line 1933
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getOrganizer()Ljava/lang/String;

    .line 1934
    .line 1935
    .line 1936
    move-result-object v17

    .line 1937
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getImageUrls()Ljava/util/List;

    .line 1938
    .line 1939
    .line 1940
    move-result-object v18

    .line 1941
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->isEnrolled()Z

    .line 1942
    .line 1943
    .line 1944
    move-result v19

    .line 1945
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->isUnlocked()Z

    .line 1946
    .line 1947
    .line 1948
    move-result v20

    .line 1949
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getStatus()Ljava/lang/String;

    .line 1950
    .line 1951
    .line 1952
    move-result-object v4

    .line 1953
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1954
    .line 1955
    .line 1956
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 1957
    .line 1958
    .line 1959
    move-result v6

    .line 1960
    sparse-switch v6, :sswitch_data_2

    .line 1961
    .line 1962
    .line 1963
    goto :goto_14

    .line 1964
    :sswitch_8
    const-string v6, "STARTED"

    .line 1965
    .line 1966
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1967
    .line 1968
    .line 1969
    move-result v4

    .line 1970
    if-nez v4, :cond_13

    .line 1971
    .line 1972
    goto :goto_14

    .line 1973
    :cond_13
    sget-object v4, Lg40/g0;->e:Lg40/g0;

    .line 1974
    .line 1975
    :goto_13
    move-object/from16 v21, v4

    .line 1976
    .line 1977
    goto :goto_15

    .line 1978
    :sswitch_9
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1979
    .line 1980
    .line 1981
    move-result v4

    .line 1982
    if-nez v4, :cond_14

    .line 1983
    .line 1984
    goto :goto_14

    .line 1985
    :cond_14
    sget-object v4, Lg40/g0;->d:Lg40/g0;

    .line 1986
    .line 1987
    goto :goto_13

    .line 1988
    :sswitch_a
    const-string v6, "WINNERS_ANNOUNCED"

    .line 1989
    .line 1990
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1991
    .line 1992
    .line 1993
    move-result v4

    .line 1994
    if-nez v4, :cond_15

    .line 1995
    .line 1996
    goto :goto_14

    .line 1997
    :cond_15
    sget-object v4, Lg40/g0;->h:Lg40/g0;

    .line 1998
    .line 1999
    goto :goto_13

    .line 2000
    :sswitch_b
    const-string v6, "MISSED"

    .line 2001
    .line 2002
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2003
    .line 2004
    .line 2005
    move-result v4

    .line 2006
    if-nez v4, :cond_16

    .line 2007
    .line 2008
    goto :goto_14

    .line 2009
    :cond_16
    sget-object v4, Lg40/g0;->g:Lg40/g0;

    .line 2010
    .line 2011
    goto :goto_13

    .line 2012
    :sswitch_c
    const-string v6, "JOINED"

    .line 2013
    .line 2014
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2015
    .line 2016
    .line 2017
    move-result v4

    .line 2018
    if-nez v4, :cond_17

    .line 2019
    .line 2020
    :goto_14
    sget-object v4, Lg40/g0;->i:Lg40/g0;

    .line 2021
    .line 2022
    goto :goto_13

    .line 2023
    :cond_17
    sget-object v4, Lg40/g0;->f:Lg40/g0;

    .line 2024
    .line 2025
    goto :goto_13

    .line 2026
    :goto_15
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getConsentUrl()Ljava/lang/String;

    .line 2027
    .line 2028
    .line 2029
    move-result-object v22

    .line 2030
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getType()Ljava/lang/String;

    .line 2031
    .line 2032
    .line 2033
    move-result-object v4

    .line 2034
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2035
    .line 2036
    .line 2037
    const-string v6, "LUCKY_DRAW"

    .line 2038
    .line 2039
    invoke-virtual {v4, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 2040
    .line 2041
    .line 2042
    move-result v4

    .line 2043
    if-eqz v4, :cond_18

    .line 2044
    .line 2045
    sget-object v4, Lg40/h0;->d:Lg40/h0;

    .line 2046
    .line 2047
    :goto_16
    move-object/from16 v23, v4

    .line 2048
    .line 2049
    goto :goto_17

    .line 2050
    :cond_18
    sget-object v4, Lg40/h0;->e:Lg40/h0;

    .line 2051
    .line 2052
    goto :goto_16

    .line 2053
    :goto_17
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getStartDate()Ljava/time/LocalDate;

    .line 2054
    .line 2055
    .line 2056
    move-result-object v24

    .line 2057
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getEndDate()Ljava/time/LocalDate;

    .line 2058
    .line 2059
    .line 2060
    move-result-object v25

    .line 2061
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getWinnerAnnouncementDate()Ljava/time/LocalDate;

    .line 2062
    .line 2063
    .line 2064
    move-result-object v26

    .line 2065
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getReward()Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardDto;

    .line 2066
    .line 2067
    .line 2068
    move-result-object v4

    .line 2069
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2070
    .line 2071
    .line 2072
    invoke-virtual {v4}, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardDto;->getTitle()Ljava/lang/String;

    .line 2073
    .line 2074
    .line 2075
    move-result-object v6

    .line 2076
    invoke-virtual {v4}, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardDto;->getOptions()Ljava/util/List;

    .line 2077
    .line 2078
    .line 2079
    move-result-object v7

    .line 2080
    check-cast v7, Ljava/lang/Iterable;

    .line 2081
    .line 2082
    new-instance v8, Ljava/util/ArrayList;

    .line 2083
    .line 2084
    invoke-static {v7, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2085
    .line 2086
    .line 2087
    move-result v9

    .line 2088
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 2089
    .line 2090
    .line 2091
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2092
    .line 2093
    .line 2094
    move-result-object v7

    .line 2095
    :goto_18
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 2096
    .line 2097
    .line 2098
    move-result v9

    .line 2099
    if-eqz v9, :cond_19

    .line 2100
    .line 2101
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2102
    .line 2103
    .line 2104
    move-result-object v9

    .line 2105
    check-cast v9, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardOptionDto;

    .line 2106
    .line 2107
    invoke-static {v9, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2108
    .line 2109
    .line 2110
    new-instance v10, Lg40/f0;

    .line 2111
    .line 2112
    invoke-virtual {v9}, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardOptionDto;->getName()Ljava/lang/String;

    .line 2113
    .line 2114
    .line 2115
    move-result-object v9

    .line 2116
    invoke-direct {v10, v9}, Lg40/f0;-><init>(Ljava/lang/String;)V

    .line 2117
    .line 2118
    .line 2119
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2120
    .line 2121
    .line 2122
    goto :goto_18

    .line 2123
    :cond_19
    invoke-virtual {v4}, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardDto;->getDescription()Ljava/lang/String;

    .line 2124
    .line 2125
    .line 2126
    move-result-object v7

    .line 2127
    invoke-virtual {v4}, Lcz/myskoda/api/bff_loyalty_program/v2/GameRewardDto;->getSelectedOption()Ljava/lang/String;

    .line 2128
    .line 2129
    .line 2130
    move-result-object v4

    .line 2131
    new-instance v9, Lg40/e0;

    .line 2132
    .line 2133
    invoke-direct {v9, v6, v8, v7, v4}, Lg40/e0;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 2134
    .line 2135
    .line 2136
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getUnlockCriteria()Ljava/lang/String;

    .line 2137
    .line 2138
    .line 2139
    move-result-object v28

    .line 2140
    invoke-virtual {v3}, Lcz/myskoda/api/bff_loyalty_program/v2/GameDto;->getConsentText()Ljava/lang/String;

    .line 2141
    .line 2142
    .line 2143
    move-result-object v29

    .line 2144
    move-object/from16 v27, v9

    .line 2145
    .line 2146
    invoke-direct/range {v13 .. v29}, Lg40/d0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZLg40/g0;Ljava/lang/String;Lg40/h0;Ljava/time/LocalDate;Ljava/time/LocalDate;Ljava/time/LocalDate;Lg40/e0;Ljava/lang/String;Ljava/lang/String;)V

    .line 2147
    .line 2148
    .line 2149
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2150
    .line 2151
    .line 2152
    goto/16 :goto_12

    .line 2153
    .line 2154
    :cond_1a
    return-object v1

    .line 2155
    :pswitch_10
    move-object/from16 v0, p1

    .line 2156
    .line 2157
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionsDto;

    .line 2158
    .line 2159
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2160
    .line 2161
    .line 2162
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionsDto;->getTransactions()Ljava/util/List;

    .line 2163
    .line 2164
    .line 2165
    move-result-object v0

    .line 2166
    check-cast v0, Ljava/lang/Iterable;

    .line 2167
    .line 2168
    new-instance v1, Ljava/util/ArrayList;

    .line 2169
    .line 2170
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2171
    .line 2172
    .line 2173
    move-result v2

    .line 2174
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2175
    .line 2176
    .line 2177
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2178
    .line 2179
    .line 2180
    move-result-object v0

    .line 2181
    :goto_19
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2182
    .line 2183
    .line 2184
    move-result v2

    .line 2185
    if-eqz v2, :cond_1b

    .line 2186
    .line 2187
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2188
    .line 2189
    .line 2190
    move-result-object v2

    .line 2191
    check-cast v2, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;

    .line 2192
    .line 2193
    invoke-static {v2}, Ljp/kf;->f(Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;)Lg40/w0;

    .line 2194
    .line 2195
    .line 2196
    move-result-object v2

    .line 2197
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2198
    .line 2199
    .line 2200
    goto :goto_19

    .line 2201
    :cond_1b
    return-object v1

    .line 2202
    :pswitch_11
    move-object/from16 v0, p1

    .line 2203
    .line 2204
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;

    .line 2205
    .line 2206
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2207
    .line 2208
    .line 2209
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;->getPointBalance()I

    .line 2210
    .line 2211
    .line 2212
    move-result v1

    .line 2213
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;->getMemberReferralCode()Ljava/lang/String;

    .line 2214
    .line 2215
    .line 2216
    move-result-object v2

    .line 2217
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberEnrollmentResponseDto;->getTransactions()Ljava/util/List;

    .line 2218
    .line 2219
    .line 2220
    move-result-object v0

    .line 2221
    check-cast v0, Ljava/lang/Iterable;

    .line 2222
    .line 2223
    new-instance v3, Ljava/util/ArrayList;

    .line 2224
    .line 2225
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2226
    .line 2227
    .line 2228
    move-result v4

    .line 2229
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 2230
    .line 2231
    .line 2232
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2233
    .line 2234
    .line 2235
    move-result-object v0

    .line 2236
    :goto_1a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2237
    .line 2238
    .line 2239
    move-result v4

    .line 2240
    if-eqz v4, :cond_1c

    .line 2241
    .line 2242
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2243
    .line 2244
    .line 2245
    move-result-object v4

    .line 2246
    check-cast v4, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;

    .line 2247
    .line 2248
    invoke-static {v4}, Ljp/kf;->f(Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;)Lg40/w0;

    .line 2249
    .line 2250
    .line 2251
    move-result-object v4

    .line 2252
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2253
    .line 2254
    .line 2255
    goto :goto_1a

    .line 2256
    :cond_1c
    new-instance v0, Lg40/k0;

    .line 2257
    .line 2258
    invoke-direct {v0, v1, v2, v3}, Lg40/k0;-><init>(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 2259
    .line 2260
    .line 2261
    return-object v0

    .line 2262
    :pswitch_12
    move-object/from16 v0, p1

    .line 2263
    .line 2264
    check-cast v0, Lcz/myskoda/api/bff_loyalty_program/v2/BadgesResponseDto;

    .line 2265
    .line 2266
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2267
    .line 2268
    .line 2269
    invoke-virtual {v0}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgesResponseDto;->getCategoryBadges()Ljava/util/List;

    .line 2270
    .line 2271
    .line 2272
    move-result-object v0

    .line 2273
    check-cast v0, Ljava/lang/Iterable;

    .line 2274
    .line 2275
    new-instance v1, Ljava/util/ArrayList;

    .line 2276
    .line 2277
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2278
    .line 2279
    .line 2280
    move-result v2

    .line 2281
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2282
    .line 2283
    .line 2284
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2285
    .line 2286
    .line 2287
    move-result-object v0

    .line 2288
    :goto_1b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2289
    .line 2290
    .line 2291
    move-result v2

    .line 2292
    if-eqz v2, :cond_1e

    .line 2293
    .line 2294
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2295
    .line 2296
    .line 2297
    move-result-object v2

    .line 2298
    check-cast v2, Lcz/myskoda/api/bff_loyalty_program/v2/CategoryBadgesDto;

    .line 2299
    .line 2300
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2301
    .line 2302
    .line 2303
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/CategoryBadgesDto;->getName()Ljava/lang/String;

    .line 2304
    .line 2305
    .line 2306
    move-result-object v3

    .line 2307
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/CategoryBadgesDto;->getWeight()D

    .line 2308
    .line 2309
    .line 2310
    move-result-wide v6

    .line 2311
    invoke-virtual {v2}, Lcz/myskoda/api/bff_loyalty_program/v2/CategoryBadgesDto;->getBadges()Ljava/util/List;

    .line 2312
    .line 2313
    .line 2314
    move-result-object v2

    .line 2315
    check-cast v2, Ljava/lang/Iterable;

    .line 2316
    .line 2317
    new-instance v4, Ljava/util/ArrayList;

    .line 2318
    .line 2319
    invoke-static {v2, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2320
    .line 2321
    .line 2322
    move-result v8

    .line 2323
    invoke-direct {v4, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 2324
    .line 2325
    .line 2326
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2327
    .line 2328
    .line 2329
    move-result-object v2

    .line 2330
    :goto_1c
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 2331
    .line 2332
    .line 2333
    move-result v8

    .line 2334
    if-eqz v8, :cond_1d

    .line 2335
    .line 2336
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2337
    .line 2338
    .line 2339
    move-result-object v8

    .line 2340
    check-cast v8, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;

    .line 2341
    .line 2342
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2343
    .line 2344
    .line 2345
    new-instance v13, Lg40/h;

    .line 2346
    .line 2347
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getId()Ljava/lang/String;

    .line 2348
    .line 2349
    .line 2350
    move-result-object v14

    .line 2351
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getName()Ljava/lang/String;

    .line 2352
    .line 2353
    .line 2354
    move-result-object v15

    .line 2355
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getDescription()Ljava/lang/String;

    .line 2356
    .line 2357
    .line 2358
    move-result-object v19

    .line 2359
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getImage()Ljava/lang/String;

    .line 2360
    .line 2361
    .line 2362
    move-result-object v20

    .line 2363
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getCollected()Z

    .line 2364
    .line 2365
    .line 2366
    move-result v16

    .line 2367
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getWeight()D

    .line 2368
    .line 2369
    .line 2370
    move-result-wide v17

    .line 2371
    invoke-virtual {v8}, Lcz/myskoda/api/bff_loyalty_program/v2/BadgeDto;->getCollectedAt()Ljava/time/OffsetDateTime;

    .line 2372
    .line 2373
    .line 2374
    move-result-object v21

    .line 2375
    invoke-direct/range {v13 .. v21}, Lg40/h;-><init>(Ljava/lang/String;Ljava/lang/String;ZDLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    .line 2376
    .line 2377
    .line 2378
    invoke-virtual {v4, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2379
    .line 2380
    .line 2381
    goto :goto_1c

    .line 2382
    :cond_1d
    new-instance v2, Lg40/o;

    .line 2383
    .line 2384
    invoke-direct {v2, v3, v6, v7, v4}, Lg40/o;-><init>(Ljava/lang/String;DLjava/util/List;)V

    .line 2385
    .line 2386
    .line 2387
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2388
    .line 2389
    .line 2390
    goto :goto_1b

    .line 2391
    :cond_1e
    return-object v1

    .line 2392
    :pswitch_13
    move-object/from16 v0, p1

    .line 2393
    .line 2394
    check-cast v0, Le21/a;

    .line 2395
    .line 2396
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2397
    .line 2398
    .line 2399
    new-instance v1, Lbs0/a;

    .line 2400
    .line 2401
    const/16 v2, 0x1a

    .line 2402
    .line 2403
    invoke-direct {v1, v2}, Lbs0/a;-><init>(I)V

    .line 2404
    .line 2405
    .line 2406
    sget-object v16, Li21/b;->e:Lh21/b;

    .line 2407
    .line 2408
    sget-object v20, La21/c;->e:La21/c;

    .line 2409
    .line 2410
    new-instance v15, La21/a;

    .line 2411
    .line 2412
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2413
    .line 2414
    const-class v4, Lg10/b;

    .line 2415
    .line 2416
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2417
    .line 2418
    .line 2419
    move-result-object v17

    .line 2420
    const/16 v18, 0x0

    .line 2421
    .line 2422
    move-object/from16 v19, v1

    .line 2423
    .line 2424
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2425
    .line 2426
    .line 2427
    new-instance v1, Lc21/a;

    .line 2428
    .line 2429
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2430
    .line 2431
    .line 2432
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2433
    .line 2434
    .line 2435
    new-instance v1, Lbs0/a;

    .line 2436
    .line 2437
    const/16 v4, 0x1b

    .line 2438
    .line 2439
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 2440
    .line 2441
    .line 2442
    new-instance v15, La21/a;

    .line 2443
    .line 2444
    const-class v4, Lg10/f;

    .line 2445
    .line 2446
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2447
    .line 2448
    .line 2449
    move-result-object v17

    .line 2450
    move-object/from16 v19, v1

    .line 2451
    .line 2452
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2453
    .line 2454
    .line 2455
    new-instance v1, Lc21/a;

    .line 2456
    .line 2457
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2458
    .line 2459
    .line 2460
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2461
    .line 2462
    .line 2463
    new-instance v1, Lbs0/a;

    .line 2464
    .line 2465
    const/16 v4, 0x15

    .line 2466
    .line 2467
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 2468
    .line 2469
    .line 2470
    new-instance v15, La21/a;

    .line 2471
    .line 2472
    const-class v4, Le10/e;

    .line 2473
    .line 2474
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2475
    .line 2476
    .line 2477
    move-result-object v17

    .line 2478
    move-object/from16 v19, v1

    .line 2479
    .line 2480
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2481
    .line 2482
    .line 2483
    new-instance v1, Lc21/a;

    .line 2484
    .line 2485
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2486
    .line 2487
    .line 2488
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2489
    .line 2490
    .line 2491
    new-instance v1, Lbs0/a;

    .line 2492
    .line 2493
    const/16 v4, 0x16

    .line 2494
    .line 2495
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 2496
    .line 2497
    .line 2498
    new-instance v15, La21/a;

    .line 2499
    .line 2500
    const-class v4, Le10/f;

    .line 2501
    .line 2502
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2503
    .line 2504
    .line 2505
    move-result-object v17

    .line 2506
    move-object/from16 v19, v1

    .line 2507
    .line 2508
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2509
    .line 2510
    .line 2511
    new-instance v1, Lc21/a;

    .line 2512
    .line 2513
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2514
    .line 2515
    .line 2516
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2517
    .line 2518
    .line 2519
    new-instance v1, Lbs0/a;

    .line 2520
    .line 2521
    const/16 v4, 0x17

    .line 2522
    .line 2523
    invoke-direct {v1, v4}, Lbs0/a;-><init>(I)V

    .line 2524
    .line 2525
    .line 2526
    new-instance v15, La21/a;

    .line 2527
    .line 2528
    const-class v5, Le10/d;

    .line 2529
    .line 2530
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2531
    .line 2532
    .line 2533
    move-result-object v17

    .line 2534
    move-object/from16 v19, v1

    .line 2535
    .line 2536
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2537
    .line 2538
    .line 2539
    new-instance v1, Lc21/a;

    .line 2540
    .line 2541
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2542
    .line 2543
    .line 2544
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2545
    .line 2546
    .line 2547
    new-instance v1, Lbs0/a;

    .line 2548
    .line 2549
    invoke-direct {v1, v3}, Lbs0/a;-><init>(I)V

    .line 2550
    .line 2551
    .line 2552
    new-instance v15, La21/a;

    .line 2553
    .line 2554
    const-class v3, Le10/b;

    .line 2555
    .line 2556
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2557
    .line 2558
    .line 2559
    move-result-object v17

    .line 2560
    move-object/from16 v19, v1

    .line 2561
    .line 2562
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2563
    .line 2564
    .line 2565
    new-instance v1, Lc21/a;

    .line 2566
    .line 2567
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2568
    .line 2569
    .line 2570
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2571
    .line 2572
    .line 2573
    new-instance v1, Lck/a;

    .line 2574
    .line 2575
    invoke-direct {v1, v4}, Lck/a;-><init>(I)V

    .line 2576
    .line 2577
    .line 2578
    sget-object v20, La21/c;->d:La21/c;

    .line 2579
    .line 2580
    new-instance v15, La21/a;

    .line 2581
    .line 2582
    const-class v3, Lc10/b;

    .line 2583
    .line 2584
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2585
    .line 2586
    .line 2587
    move-result-object v17

    .line 2588
    move-object/from16 v19, v1

    .line 2589
    .line 2590
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2591
    .line 2592
    .line 2593
    new-instance v1, Lc21/d;

    .line 2594
    .line 2595
    invoke-direct {v1, v15}, Lc21/b;-><init>(La21/a;)V

    .line 2596
    .line 2597
    .line 2598
    invoke-virtual {v0, v1}, Le21/a;->a(Lc21/b;)V

    .line 2599
    .line 2600
    .line 2601
    new-instance v1, Lbs0/a;

    .line 2602
    .line 2603
    const/16 v3, 0x19

    .line 2604
    .line 2605
    invoke-direct {v1, v3}, Lbs0/a;-><init>(I)V

    .line 2606
    .line 2607
    .line 2608
    new-instance v15, La21/a;

    .line 2609
    .line 2610
    const-class v3, Lc10/a;

    .line 2611
    .line 2612
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2613
    .line 2614
    .line 2615
    move-result-object v17

    .line 2616
    move-object/from16 v19, v1

    .line 2617
    .line 2618
    invoke-direct/range {v15 .. v20}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 2619
    .line 2620
    .line 2621
    invoke-static {v15, v0}, Lia/b;->d(La21/a;Le21/a;)Lc21/d;

    .line 2622
    .line 2623
    .line 2624
    move-result-object v1

    .line 2625
    new-instance v3, La21/d;

    .line 2626
    .line 2627
    invoke-direct {v3, v0, v1}, La21/d;-><init>(Le21/a;Lc21/b;)V

    .line 2628
    .line 2629
    .line 2630
    const-class v0, Le10/c;

    .line 2631
    .line 2632
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2633
    .line 2634
    .line 2635
    move-result-object v0

    .line 2636
    const-class v1, Lme0/b;

    .line 2637
    .line 2638
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 2639
    .line 2640
    .line 2641
    move-result-object v1

    .line 2642
    new-array v2, v7, [Lhy0/d;

    .line 2643
    .line 2644
    aput-object v0, v2, v9

    .line 2645
    .line 2646
    aput-object v1, v2, v8

    .line 2647
    .line 2648
    invoke-static {v3, v2}, Llp/le;->a(La21/d;[Lhy0/d;)V

    .line 2649
    .line 2650
    .line 2651
    return-object v14

    .line 2652
    :pswitch_14
    move-object/from16 v0, p1

    .line 2653
    .line 2654
    check-cast v0, Lt4/f;

    .line 2655
    .line 2656
    return-object v14

    .line 2657
    :pswitch_15
    move-object/from16 v0, p1

    .line 2658
    .line 2659
    check-cast v0, Ljava/lang/String;

    .line 2660
    .line 2661
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2662
    .line 2663
    .line 2664
    return-object v14

    .line 2665
    :pswitch_16
    move-object/from16 v0, p1

    .line 2666
    .line 2667
    check-cast v0, Ljava/lang/String;

    .line 2668
    .line 2669
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2670
    .line 2671
    .line 2672
    return-object v14

    .line 2673
    :pswitch_17
    move-object/from16 v0, p1

    .line 2674
    .line 2675
    check-cast v0, Lbz/k;

    .line 2676
    .line 2677
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2678
    .line 2679
    .line 2680
    return-object v14

    .line 2681
    :pswitch_18
    move-object/from16 v0, p1

    .line 2682
    .line 2683
    check-cast v0, Lbz/i;

    .line 2684
    .line 2685
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2686
    .line 2687
    .line 2688
    return-object v14

    .line 2689
    :pswitch_19
    move-object/from16 v0, p1

    .line 2690
    .line 2691
    check-cast v0, Lua/a;

    .line 2692
    .line 2693
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2694
    .line 2695
    .line 2696
    const-string v1, "DELETE FROM vehicle_fuel_level"

    .line 2697
    .line 2698
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2699
    .line 2700
    .line 2701
    move-result-object v1

    .line 2702
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2703
    .line 2704
    .line 2705
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2706
    .line 2707
    .line 2708
    return-object v14

    .line 2709
    :catchall_0
    move-exception v0

    .line 2710
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2711
    .line 2712
    .line 2713
    throw v0

    .line 2714
    :pswitch_1a
    move-object/from16 v0, p1

    .line 2715
    .line 2716
    check-cast v0, Lua/a;

    .line 2717
    .line 2718
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2719
    .line 2720
    .line 2721
    const-string v1, "DELETE FROM range_ice"

    .line 2722
    .line 2723
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2724
    .line 2725
    .line 2726
    move-result-object v1

    .line 2727
    :try_start_1
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 2728
    .line 2729
    .line 2730
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2731
    .line 2732
    .line 2733
    return-object v14

    .line 2734
    :catchall_1
    move-exception v0

    .line 2735
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2736
    .line 2737
    .line 2738
    throw v0

    .line 2739
    :pswitch_1b
    move-object/from16 v0, p1

    .line 2740
    .line 2741
    check-cast v0, Ltd/o;

    .line 2742
    .line 2743
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2744
    .line 2745
    .line 2746
    return-object v14

    .line 2747
    :pswitch_1c
    move-object/from16 v0, p1

    .line 2748
    .line 2749
    check-cast v0, Ltd/o;

    .line 2750
    .line 2751
    invoke-static {v0, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2752
    .line 2753
    .line 2754
    return-object v14

    .line 2755
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

    .line 2756
    .line 2757
    .line 2758
    .line 2759
    .line 2760
    .line 2761
    .line 2762
    .line 2763
    .line 2764
    .line 2765
    .line 2766
    .line 2767
    .line 2768
    .line 2769
    .line 2770
    .line 2771
    .line 2772
    .line 2773
    .line 2774
    .line 2775
    .line 2776
    .line 2777
    .line 2778
    .line 2779
    .line 2780
    .line 2781
    .line 2782
    .line 2783
    .line 2784
    .line 2785
    .line 2786
    .line 2787
    .line 2788
    .line 2789
    .line 2790
    .line 2791
    .line 2792
    .line 2793
    .line 2794
    .line 2795
    .line 2796
    .line 2797
    .line 2798
    .line 2799
    .line 2800
    .line 2801
    .line 2802
    .line 2803
    .line 2804
    .line 2805
    .line 2806
    .line 2807
    .line 2808
    .line 2809
    .line 2810
    .line 2811
    .line 2812
    .line 2813
    .line 2814
    .line 2815
    .line 2816
    .line 2817
    :sswitch_data_0
    .sparse-switch
        -0x2ecf79c1 -> :sswitch_3
        -0x1e760302 -> :sswitch_2
        0xcc73399 -> :sswitch_1
        0x6362ed0a -> :sswitch_0
    .end sparse-switch

    .line 2818
    .line 2819
    .line 2820
    .line 2821
    .line 2822
    .line 2823
    .line 2824
    .line 2825
    .line 2826
    .line 2827
    .line 2828
    .line 2829
    .line 2830
    .line 2831
    .line 2832
    .line 2833
    .line 2834
    .line 2835
    :sswitch_data_1
    .sparse-switch
        -0x52ecc12b -> :sswitch_7
        -0x2408abf9 -> :sswitch_6
        0x19d1382a -> :sswitch_5
        0x5279062b -> :sswitch_4
    .end sparse-switch

    .line 2836
    .line 2837
    .line 2838
    .line 2839
    .line 2840
    .line 2841
    .line 2842
    .line 2843
    .line 2844
    .line 2845
    .line 2846
    .line 2847
    .line 2848
    .line 2849
    .line 2850
    .line 2851
    .line 2852
    .line 2853
    :sswitch_data_2
    .sparse-switch
        -0x7d3dc4b7 -> :sswitch_c
        -0x786f2965 -> :sswitch_b
        -0x6dddc990 -> :sswitch_a
        -0x52ecc12b -> :sswitch_9
        -0x4649339f -> :sswitch_8
    .end sparse-switch
.end method
