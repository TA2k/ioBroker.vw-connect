.class public final synthetic Lge/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lge/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lge/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lge/a;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Lge/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast v0, Lwk0/d2;

    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lp1/p;

    .line 15
    .line 16
    move-object/from16 v2, p2

    .line 17
    .line 18
    check-cast v2, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    move-object/from16 v8, p3

    .line 25
    .line 26
    check-cast v8, Ll2/o;

    .line 27
    .line 28
    move-object/from16 v3, p4

    .line 29
    .line 30
    check-cast v3, Ljava/lang/Integer;

    .line 31
    .line 32
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    const-string v3, "$this$HorizontalPager"

    .line 36
    .line 37
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iget-object v1, v0, Lwk0/d2;->c:Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    check-cast v1, Lwk0/c2;

    .line 47
    .line 48
    iget-object v4, v1, Lwk0/c2;->a:Ljava/util/ArrayList;

    .line 49
    .line 50
    iget-object v1, v0, Lwk0/d2;->c:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Lwk0/c2;

    .line 57
    .line 58
    iget-object v6, v1, Lwk0/c2;->b:Ljava/lang/Float;

    .line 59
    .line 60
    iget-object v7, v0, Lwk0/d2;->d:Ljava/util/ArrayList;

    .line 61
    .line 62
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 63
    .line 64
    const/high16 v1, 0x3f800000    # 1.0f

    .line 65
    .line 66
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    const-string v1, "poi_popular_times_chart"

    .line 71
    .line 72
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    const/4 v5, 0x0

    .line 77
    const/4 v9, 0x6

    .line 78
    invoke-static/range {v3 .. v9}, Lxf0/z2;->d(Lx2/s;Ljava/util/ArrayList;ILjava/lang/Float;Ljava/util/List;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object v0

    .line 84
    :pswitch_0
    check-cast v0, [Lxf0/o3;

    .line 85
    .line 86
    move-object/from16 v1, p1

    .line 87
    .line 88
    check-cast v1, Lp1/p;

    .line 89
    .line 90
    move-object/from16 v2, p2

    .line 91
    .line 92
    check-cast v2, Ljava/lang/Integer;

    .line 93
    .line 94
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    move-object/from16 v3, p3

    .line 99
    .line 100
    check-cast v3, Ll2/o;

    .line 101
    .line 102
    move-object/from16 v4, p4

    .line 103
    .line 104
    check-cast v4, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    const-string v4, "$this$HorizontalPager"

    .line 110
    .line 111
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    aget-object v0, v0, v2

    .line 115
    .line 116
    iget-object v0, v0, Lxf0/o3;->d:Lt2/b;

    .line 117
    .line 118
    check-cast v3, Ll2/t;

    .line 119
    .line 120
    const v1, 0x609e284a

    .line 121
    .line 122
    .line 123
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 124
    .line 125
    .line 126
    const/4 v1, 0x0

    .line 127
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    invoke-virtual {v0, v3, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v3, v1}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    return-object v0

    .line 140
    :pswitch_1
    check-cast v0, Landroidx/sqlite/db/SupportSQLiteQuery;

    .line 141
    .line 142
    move-object/from16 v1, p1

    .line 143
    .line 144
    check-cast v1, Landroid/database/sqlite/SQLiteDatabase;

    .line 145
    .line 146
    move-object/from16 v1, p2

    .line 147
    .line 148
    check-cast v1, Landroid/database/sqlite/SQLiteCursorDriver;

    .line 149
    .line 150
    move-object/from16 v2, p3

    .line 151
    .line 152
    check-cast v2, Ljava/lang/String;

    .line 153
    .line 154
    move-object/from16 v3, p4

    .line 155
    .line 156
    check-cast v3, Landroid/database/sqlite/SQLiteQuery;

    .line 157
    .line 158
    new-instance v4, Lwa/i;

    .line 159
    .line 160
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    invoke-direct {v4, v3}, Lwa/i;-><init>(Landroid/database/sqlite/SQLiteProgram;)V

    .line 164
    .line 165
    .line 166
    invoke-interface {v0, v4}, Landroidx/sqlite/db/SupportSQLiteQuery;->f(Lva/a;)V

    .line 167
    .line 168
    .line 169
    new-instance v0, Landroid/database/sqlite/SQLiteCursor;

    .line 170
    .line 171
    invoke-direct {v0, v1, v2, v3}, Landroid/database/sqlite/SQLiteCursor;-><init>(Landroid/database/sqlite/SQLiteCursorDriver;Ljava/lang/String;Landroid/database/sqlite/SQLiteQuery;)V

    .line 172
    .line 173
    .line 174
    return-object v0

    .line 175
    :pswitch_2
    check-cast v0, Lo4/c;

    .line 176
    .line 177
    move-object/from16 v1, p1

    .line 178
    .line 179
    check-cast v1, Lk4/n;

    .line 180
    .line 181
    move-object/from16 v2, p2

    .line 182
    .line 183
    check-cast v2, Lk4/x;

    .line 184
    .line 185
    move-object/from16 v3, p3

    .line 186
    .line 187
    check-cast v3, Lk4/t;

    .line 188
    .line 189
    move-object/from16 v4, p4

    .line 190
    .line 191
    check-cast v4, Lk4/u;

    .line 192
    .line 193
    iget-object v5, v0, Lo4/c;->h:Lk4/m;

    .line 194
    .line 195
    iget v3, v3, Lk4/t;->a:I

    .line 196
    .line 197
    iget v4, v4, Lk4/u;->a:I

    .line 198
    .line 199
    check-cast v5, Lk4/o;

    .line 200
    .line 201
    invoke-virtual {v5, v1, v2, v3, v4}, Lk4/o;->b(Lk4/n;Lk4/x;II)Lk4/i0;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    instance-of v2, v1, Lk4/h0;

    .line 206
    .line 207
    const-string v3, "null cannot be cast to non-null type android.graphics.Typeface"

    .line 208
    .line 209
    if-nez v2, :cond_0

    .line 210
    .line 211
    new-instance v2, Lil/g;

    .line 212
    .line 213
    iget-object v4, v0, Lo4/c;->m:Lil/g;

    .line 214
    .line 215
    invoke-direct {v2, v1, v4}, Lil/g;-><init>(Lk4/i0;Lil/g;)V

    .line 216
    .line 217
    .line 218
    iput-object v2, v0, Lo4/c;->m:Lil/g;

    .line 219
    .line 220
    iget-object v0, v2, Lil/g;->g:Ljava/lang/Object;

    .line 221
    .line 222
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    check-cast v0, Landroid/graphics/Typeface;

    .line 226
    .line 227
    goto :goto_0

    .line 228
    :cond_0
    check-cast v1, Lk4/h0;

    .line 229
    .line 230
    iget-object v0, v1, Lk4/h0;->d:Ljava/lang/Object;

    .line 231
    .line 232
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    check-cast v0, Landroid/graphics/Typeface;

    .line 236
    .line 237
    :goto_0
    return-object v0

    .line 238
    :pswitch_3
    check-cast v0, Lm10/c;

    .line 239
    .line 240
    move-object/from16 v1, p1

    .line 241
    .line 242
    check-cast v1, Lp1/p;

    .line 243
    .line 244
    move-object/from16 v2, p2

    .line 245
    .line 246
    check-cast v2, Ljava/lang/Integer;

    .line 247
    .line 248
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 249
    .line 250
    .line 251
    move-result v2

    .line 252
    move-object/from16 v3, p3

    .line 253
    .line 254
    check-cast v3, Ll2/o;

    .line 255
    .line 256
    move-object/from16 v4, p4

    .line 257
    .line 258
    check-cast v4, Ljava/lang/Integer;

    .line 259
    .line 260
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 261
    .line 262
    .line 263
    const-string v4, "$this$HorizontalPager"

    .line 264
    .line 265
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    iget-object v0, v0, Lm10/c;->a:Ljava/util/List;

    .line 269
    .line 270
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v0

    .line 274
    check-cast v0, Lm10/a;

    .line 275
    .line 276
    iget-object v1, v0, Lm10/a;->d:Lm10/b;

    .line 277
    .line 278
    sget-object v2, Lm10/b;->e:Lm10/b;

    .line 279
    .line 280
    const/4 v4, 0x0

    .line 281
    if-ne v1, v2, :cond_1

    .line 282
    .line 283
    check-cast v3, Ll2/t;

    .line 284
    .line 285
    const v1, -0x77f848b

    .line 286
    .line 287
    .line 288
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 289
    .line 290
    .line 291
    invoke-static {v0, v3, v4}, Ljp/t1;->a(Lm10/a;Ll2/o;I)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 295
    .line 296
    .line 297
    goto :goto_1

    .line 298
    :cond_1
    check-cast v3, Ll2/t;

    .line 299
    .line 300
    const v1, -0x77e61cc

    .line 301
    .line 302
    .line 303
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 304
    .line 305
    .line 306
    invoke-static {v0, v3, v4}, Ljp/t1;->d(Lm10/a;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    return-object v0

    .line 315
    :pswitch_4
    check-cast v0, Lyj/b;

    .line 316
    .line 317
    move-object/from16 v1, p1

    .line 318
    .line 319
    check-cast v1, Lb1/n;

    .line 320
    .line 321
    move-object/from16 v2, p2

    .line 322
    .line 323
    check-cast v2, Lz9/k;

    .line 324
    .line 325
    move-object/from16 v3, p3

    .line 326
    .line 327
    check-cast v3, Ll2/o;

    .line 328
    .line 329
    move-object/from16 v4, p4

    .line 330
    .line 331
    check-cast v4, Ljava/lang/Integer;

    .line 332
    .line 333
    const-string v5, "$this$composable"

    .line 334
    .line 335
    const-string v6, "entry"

    .line 336
    .line 337
    invoke-static {v4, v1, v5, v2, v6}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    iget-object v1, v2, Lz9/k;->l:Llx0/q;

    .line 341
    .line 342
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v1

    .line 346
    check-cast v1, Landroidx/lifecycle/s0;

    .line 347
    .line 348
    const-string v2, "navigate_with_result"

    .line 349
    .line 350
    invoke-virtual {v1, v2}, Landroidx/lifecycle/s0;->b(Ljava/lang/String;)Lyy0/l1;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    const/4 v2, 0x0

    .line 355
    invoke-static {v0, v1, v3, v2}, Ljp/e1;->a(Lyj/b;Lyy0/l1;Ll2/o;I)V

    .line 356
    .line 357
    .line 358
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 359
    .line 360
    return-object v0

    .line 361
    :pswitch_5
    check-cast v0, Lay0/a;

    .line 362
    .line 363
    move-object/from16 v1, p1

    .line 364
    .line 365
    check-cast v1, Lb1/n;

    .line 366
    .line 367
    move-object/from16 v2, p2

    .line 368
    .line 369
    check-cast v2, Lz9/k;

    .line 370
    .line 371
    move-object/from16 v3, p3

    .line 372
    .line 373
    check-cast v3, Ll2/o;

    .line 374
    .line 375
    move-object/from16 v4, p4

    .line 376
    .line 377
    check-cast v4, Ljava/lang/Integer;

    .line 378
    .line 379
    const-string v5, "$this$composable"

    .line 380
    .line 381
    const-string v6, "it"

    .line 382
    .line 383
    invoke-static {v4, v1, v5, v2, v6}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    const/4 v1, 0x0

    .line 387
    invoke-static {v0, v3, v1}, Ljp/d1;->b(Lay0/a;Ll2/o;I)V

    .line 388
    .line 389
    .line 390
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 391
    .line 392
    return-object v0

    .line 393
    :pswitch_6
    check-cast v0, Lzb/s0;

    .line 394
    .line 395
    move-object/from16 v1, p1

    .line 396
    .line 397
    check-cast v1, Lb1/n;

    .line 398
    .line 399
    move-object/from16 v2, p2

    .line 400
    .line 401
    check-cast v2, Lz9/k;

    .line 402
    .line 403
    move-object/from16 v3, p3

    .line 404
    .line 405
    check-cast v3, Ll2/o;

    .line 406
    .line 407
    move-object/from16 v4, p4

    .line 408
    .line 409
    check-cast v4, Ljava/lang/Integer;

    .line 410
    .line 411
    const-string v5, "$this$composable"

    .line 412
    .line 413
    const-string v6, "entry"

    .line 414
    .line 415
    invoke-static {v4, v1, v5, v2, v6}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 416
    .line 417
    .line 418
    const-string v1, "chargingRecordId"

    .line 419
    .line 420
    invoke-static {v2, v1}, Lzb/b;->t(Lz9/k;Ljava/lang/String;)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v1

    .line 424
    const/4 v2, 0x0

    .line 425
    invoke-static {v1, v0, v3, v2}, Llp/da;->a(Ljava/lang/String;Lzb/s0;Ll2/o;I)V

    .line 426
    .line 427
    .line 428
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 429
    .line 430
    return-object v0

    .line 431
    :pswitch_7
    check-cast v0, Lh40/m3;

    .line 432
    .line 433
    move-object/from16 v1, p1

    .line 434
    .line 435
    check-cast v1, Lp1/p;

    .line 436
    .line 437
    move-object/from16 v2, p2

    .line 438
    .line 439
    check-cast v2, Ljava/lang/Integer;

    .line 440
    .line 441
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 442
    .line 443
    .line 444
    move-result v2

    .line 445
    move-object/from16 v14, p3

    .line 446
    .line 447
    check-cast v14, Ll2/o;

    .line 448
    .line 449
    move-object/from16 v3, p4

    .line 450
    .line 451
    check-cast v3, Ljava/lang/Integer;

    .line 452
    .line 453
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 454
    .line 455
    .line 456
    const-string v3, "$this$HorizontalPager"

    .line 457
    .line 458
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 462
    .line 463
    const/high16 v3, 0x3f800000    # 1.0f

    .line 464
    .line 465
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 466
    .line 467
    .line 468
    move-result-object v4

    .line 469
    sget v5, Li40/p1;->a:F

    .line 470
    .line 471
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 472
    .line 473
    .line 474
    move-result-object v4

    .line 475
    sget-object v5, Lk1/j;->e:Lk1/f;

    .line 476
    .line 477
    sget-object v6, Lx2/c;->p:Lx2/h;

    .line 478
    .line 479
    const/4 v7, 0x6

    .line 480
    invoke-static {v5, v6, v14, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 481
    .line 482
    .line 483
    move-result-object v5

    .line 484
    move-object v6, v14

    .line 485
    check-cast v6, Ll2/t;

    .line 486
    .line 487
    iget-wide v7, v6, Ll2/t;->T:J

    .line 488
    .line 489
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 490
    .line 491
    .line 492
    move-result v7

    .line 493
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 494
    .line 495
    .line 496
    move-result-object v8

    .line 497
    invoke-static {v14, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 498
    .line 499
    .line 500
    move-result-object v4

    .line 501
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 502
    .line 503
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 504
    .line 505
    .line 506
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 507
    .line 508
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 509
    .line 510
    .line 511
    iget-boolean v10, v6, Ll2/t;->S:Z

    .line 512
    .line 513
    if-eqz v10, :cond_2

    .line 514
    .line 515
    invoke-virtual {v6, v9}, Ll2/t;->l(Lay0/a;)V

    .line 516
    .line 517
    .line 518
    goto :goto_2

    .line 519
    :cond_2
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 520
    .line 521
    .line 522
    :goto_2
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 523
    .line 524
    invoke-static {v9, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 525
    .line 526
    .line 527
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 528
    .line 529
    invoke-static {v5, v8, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 530
    .line 531
    .line 532
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 533
    .line 534
    iget-boolean v8, v6, Ll2/t;->S:Z

    .line 535
    .line 536
    if-nez v8, :cond_3

    .line 537
    .line 538
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object v8

    .line 542
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 543
    .line 544
    .line 545
    move-result-object v9

    .line 546
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    move-result v8

    .line 550
    if-nez v8, :cond_4

    .line 551
    .line 552
    :cond_3
    invoke-static {v7, v6, v7, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 553
    .line 554
    .line 555
    :cond_4
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 556
    .line 557
    invoke-static {v5, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 558
    .line 559
    .line 560
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 561
    .line 562
    .line 563
    move-result-object v4

    .line 564
    iget-object v1, v0, Lh40/m3;->e:Ljava/util/List;

    .line 565
    .line 566
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 567
    .line 568
    .line 569
    move-result v1

    .line 570
    if-eqz v1, :cond_5

    .line 571
    .line 572
    const/4 v0, 0x0

    .line 573
    :goto_3
    move-object v3, v0

    .line 574
    goto :goto_4

    .line 575
    :cond_5
    iget-object v0, v0, Lh40/m3;->e:Ljava/util/List;

    .line 576
    .line 577
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    check-cast v0, Ljava/net/URL;

    .line 582
    .line 583
    invoke-static {v0}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 584
    .line 585
    .line 586
    move-result-object v0

    .line 587
    goto :goto_3

    .line 588
    :goto_4
    sget-object v12, Li40/q;->m:Lt2/b;

    .line 589
    .line 590
    sget-object v13, Li40/q;->n:Lt2/b;

    .line 591
    .line 592
    const/16 v16, 0x6c06

    .line 593
    .line 594
    const/16 v17, 0x1bfc

    .line 595
    .line 596
    const/4 v5, 0x0

    .line 597
    move-object v0, v6

    .line 598
    const/4 v6, 0x0

    .line 599
    const/4 v7, 0x0

    .line 600
    const/4 v8, 0x0

    .line 601
    const/4 v9, 0x0

    .line 602
    sget-object v10, Lt3/j;->d:Lt3/x0;

    .line 603
    .line 604
    const/4 v11, 0x0

    .line 605
    const/16 v15, 0x30

    .line 606
    .line 607
    invoke-static/range {v3 .. v17}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 608
    .line 609
    .line 610
    const/4 v1, 0x1

    .line 611
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 612
    .line 613
    .line 614
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 615
    .line 616
    return-object v0

    .line 617
    :pswitch_8
    check-cast v0, Lxh/e;

    .line 618
    .line 619
    move-object/from16 v1, p1

    .line 620
    .line 621
    check-cast v1, Lb1/n;

    .line 622
    .line 623
    move-object/from16 v2, p2

    .line 624
    .line 625
    check-cast v2, Lz9/k;

    .line 626
    .line 627
    move-object/from16 v3, p3

    .line 628
    .line 629
    check-cast v3, Ll2/o;

    .line 630
    .line 631
    move-object/from16 v4, p4

    .line 632
    .line 633
    check-cast v4, Ljava/lang/Integer;

    .line 634
    .line 635
    const-string v5, "$this$composable"

    .line 636
    .line 637
    const-string v6, "it"

    .line 638
    .line 639
    invoke-static {v4, v1, v5, v2, v6}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 640
    .line 641
    .line 642
    const/4 v1, 0x0

    .line 643
    invoke-static {v0, v3, v1}, Llp/u0;->F(Lxh/e;Ll2/o;I)V

    .line 644
    .line 645
    .line 646
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 647
    .line 648
    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
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
