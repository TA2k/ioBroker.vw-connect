.class public final La3/g;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc3/v;Lc3/l;Lay0/k;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, La3/g;->f:I

    .line 1
    iput-object p1, p0, La3/g;->g:Ljava/lang/Object;

    iput-object p2, p0, La3/g;->h:Ljava/lang/Object;

    check-cast p3, Lkotlin/jvm/internal/n;

    iput-object p3, p0, La3/g;->i:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, La3/g;->f:I

    iput-object p1, p0, La3/g;->g:Ljava/lang/Object;

    iput-object p2, p0, La3/g;->h:Ljava/lang/Object;

    iput-object p3, p0, La3/g;->i:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La3/g;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lx21/x;

    .line 11
    .line 12
    const-string v2, "item"

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Lx21/x;->b()J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    const/16 v4, 0x20

    .line 22
    .line 23
    shr-long v4, v2, v4

    .line 24
    .line 25
    long-to-int v4, v4

    .line 26
    int-to-float v4, v4

    .line 27
    const-wide v5, 0xffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    and-long/2addr v2, v5

    .line 33
    long-to-int v2, v2

    .line 34
    int-to-float v2, v2

    .line 35
    invoke-static {v4, v2}, Ljp/bf;->a(FF)J

    .line 36
    .line 37
    .line 38
    move-result-wide v2

    .line 39
    invoke-virtual {v1}, Lx21/x;->c()J

    .line 40
    .line 41
    .line 42
    move-result-wide v4

    .line 43
    invoke-static {v4, v5}, Lkp/f9;->c(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v4

    .line 47
    invoke-static {v2, v3, v4, v5}, Ljp/cf;->c(JJ)Ld3/c;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-object v3, v0, La3/g;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v3, Lx21/y;

    .line 54
    .line 55
    iget-object v4, v3, Lx21/y;->i:Lay0/n;

    .line 56
    .line 57
    iget-object v5, v0, La3/g;->h:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v5, Ld3/c;

    .line 60
    .line 61
    invoke-interface {v4, v5, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Ljava/lang/Boolean;

    .line 66
    .line 67
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_0

    .line 72
    .line 73
    iget-object v2, v3, Lx21/y;->r:Ljava/util/HashSet;

    .line 74
    .line 75
    iget-object v3, v1, Lx21/x;->a:Lm1/m;

    .line 76
    .line 77
    iget-object v3, v3, Lm1/m;->k:Ljava/lang/Object;

    .line 78
    .line 79
    invoke-virtual {v2, v3}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    if-eqz v2, :cond_0

    .line 84
    .line 85
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v0, Lay0/k;

    .line 88
    .line 89
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    check-cast v0, Ljava/lang/Boolean;

    .line 94
    .line 95
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_0

    .line 100
    .line 101
    const/4 v0, 0x1

    .line 102
    goto :goto_0

    .line 103
    :cond_0
    const/4 v0, 0x0

    .line 104
    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    return-object v0

    .line 109
    :pswitch_0
    move-object/from16 v1, p1

    .line 110
    .line 111
    check-cast v1, Lg3/d;

    .line 112
    .line 113
    iget-object v2, v0, La3/g;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v2, Lw4/o;

    .line 116
    .line 117
    iget-object v3, v0, La3/g;->h:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v3, Lv3/h0;

    .line 120
    .line 121
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v0, Lw4/o;

    .line 124
    .line 125
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-virtual {v2}, Lw4/g;->getView()Landroid/view/View;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    const/16 v5, 0x8

    .line 142
    .line 143
    if-eq v4, v5, :cond_3

    .line 144
    .line 145
    const/4 v4, 0x1

    .line 146
    iput-boolean v4, v2, Lw4/g;->A:Z

    .line 147
    .line 148
    iget-object v3, v3, Lv3/h0;->p:Lv3/o1;

    .line 149
    .line 150
    instance-of v4, v3, Lw3/t;

    .line 151
    .line 152
    if-eqz v4, :cond_1

    .line 153
    .line 154
    check-cast v3, Lw3/t;

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_1
    const/4 v3, 0x0

    .line 158
    :goto_1
    if-eqz v3, :cond_2

    .line 159
    .line 160
    invoke-static {v1}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    invoke-virtual {v3}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0, v1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 172
    .line 173
    .line 174
    :cond_2
    const/4 v0, 0x0

    .line 175
    iput-boolean v0, v2, Lw4/g;->A:Z

    .line 176
    .line 177
    :cond_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    return-object v0

    .line 180
    :pswitch_1
    move-object/from16 v1, p1

    .line 181
    .line 182
    check-cast v1, Lg3/d;

    .line 183
    .line 184
    iget-object v2, v0, La3/g;->g:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v2, Lv3/j0;

    .line 187
    .line 188
    iget-object v3, v2, Lv3/j0;->d:Lg3/b;

    .line 189
    .line 190
    iget-object v4, v2, Lv3/j0;->e:Lv3/p;

    .line 191
    .line 192
    iget-object v5, v0, La3/g;->h:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v5, Lv3/p;

    .line 195
    .line 196
    iput-object v5, v2, Lv3/j0;->e:Lv3/p;

    .line 197
    .line 198
    :try_start_0
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    invoke-virtual {v5}, Lgw0/c;->k()Lt4/c;

    .line 203
    .line 204
    .line 205
    move-result-object v5

    .line 206
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 207
    .line 208
    .line 209
    move-result-object v6

    .line 210
    invoke-virtual {v6}, Lgw0/c;->l()Lt4/m;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    invoke-virtual {v7}, Lgw0/c;->h()Le3/r;

    .line 219
    .line 220
    .line 221
    move-result-object v7

    .line 222
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 223
    .line 224
    .line 225
    move-result-object v8

    .line 226
    invoke-virtual {v8}, Lgw0/c;->o()J

    .line 227
    .line 228
    .line 229
    move-result-wide v8

    .line 230
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    iget-object v1, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast v1, Lh3/c;

    .line 237
    .line 238
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast v0, Le81/w;

    .line 241
    .line 242
    iget-object v10, v3, Lg3/b;->e:Lgw0/c;

    .line 243
    .line 244
    invoke-virtual {v10}, Lgw0/c;->k()Lt4/c;

    .line 245
    .line 246
    .line 247
    move-result-object v10

    .line 248
    iget-object v11, v3, Lg3/b;->e:Lgw0/c;

    .line 249
    .line 250
    invoke-virtual {v11}, Lgw0/c;->l()Lt4/m;

    .line 251
    .line 252
    .line 253
    move-result-object v11

    .line 254
    iget-object v12, v3, Lg3/b;->e:Lgw0/c;

    .line 255
    .line 256
    invoke-virtual {v12}, Lgw0/c;->h()Le3/r;

    .line 257
    .line 258
    .line 259
    move-result-object v12

    .line 260
    iget-object v13, v3, Lg3/b;->e:Lgw0/c;

    .line 261
    .line 262
    invoke-virtual {v13}, Lgw0/c;->o()J

    .line 263
    .line 264
    .line 265
    move-result-wide v13

    .line 266
    iget-object v15, v3, Lg3/b;->e:Lgw0/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 267
    .line 268
    move-object/from16 p1, v4

    .line 269
    .line 270
    :try_start_1
    iget-object v4, v15, Lgw0/c;->f:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast v4, Lh3/c;

    .line 273
    .line 274
    invoke-virtual {v15, v5}, Lgw0/c;->z(Lt4/c;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v15, v6}, Lgw0/c;->A(Lt4/m;)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v15, v7}, Lgw0/c;->x(Le3/r;)V

    .line 281
    .line 282
    .line 283
    invoke-virtual {v15, v8, v9}, Lgw0/c;->B(J)V

    .line 284
    .line 285
    .line 286
    iput-object v1, v15, Lgw0/c;->f:Ljava/lang/Object;

    .line 287
    .line 288
    invoke-interface {v7}, Le3/r;->o()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 289
    .line 290
    .line 291
    :try_start_2
    invoke-virtual {v0, v2}, Le81/w;->invoke(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 292
    .line 293
    .line 294
    :try_start_3
    invoke-interface {v7}, Le3/r;->i()V

    .line 295
    .line 296
    .line 297
    iget-object v0, v3, Lg3/b;->e:Lgw0/c;

    .line 298
    .line 299
    invoke-virtual {v0, v10}, Lgw0/c;->z(Lt4/c;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v0, v11}, Lgw0/c;->A(Lt4/m;)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v0, v12}, Lgw0/c;->x(Le3/r;)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v0, v13, v14}, Lgw0/c;->B(J)V

    .line 309
    .line 310
    .line 311
    iput-object v4, v0, Lgw0/c;->f:Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 312
    .line 313
    move-object/from16 v1, p1

    .line 314
    .line 315
    iput-object v1, v2, Lv3/j0;->e:Lv3/p;

    .line 316
    .line 317
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 318
    .line 319
    return-object v0

    .line 320
    :catchall_0
    move-exception v0

    .line 321
    move-object/from16 v1, p1

    .line 322
    .line 323
    goto :goto_2

    .line 324
    :catchall_1
    move-exception v0

    .line 325
    move-object/from16 v1, p1

    .line 326
    .line 327
    :try_start_4
    invoke-interface {v7}, Le3/r;->i()V

    .line 328
    .line 329
    .line 330
    iget-object v3, v3, Lg3/b;->e:Lgw0/c;

    .line 331
    .line 332
    invoke-virtual {v3, v10}, Lgw0/c;->z(Lt4/c;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v3, v11}, Lgw0/c;->A(Lt4/m;)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v3, v12}, Lgw0/c;->x(Le3/r;)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v3, v13, v14}, Lgw0/c;->B(J)V

    .line 342
    .line 343
    .line 344
    iput-object v4, v3, Lgw0/c;->f:Ljava/lang/Object;

    .line 345
    .line 346
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 347
    :catchall_2
    move-exception v0

    .line 348
    goto :goto_2

    .line 349
    :catchall_3
    move-exception v0

    .line 350
    move-object v1, v4

    .line 351
    :goto_2
    iput-object v1, v2, Lv3/j0;->e:Lv3/p;

    .line 352
    .line 353
    throw v0

    .line 354
    :pswitch_2
    move-object/from16 v1, p1

    .line 355
    .line 356
    check-cast v1, Landroid/text/style/URLSpan;

    .line 357
    .line 358
    const-string v2, "urlSpan"

    .line 359
    .line 360
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    iget-object v2, v0, La3/g;->g:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v2, Lkotlin/jvm/internal/b0;

    .line 366
    .line 367
    const/4 v3, 0x1

    .line 368
    iput-boolean v3, v2, Lkotlin/jvm/internal/b0;->d:Z

    .line 369
    .line 370
    iget-object v2, v0, La3/g;->h:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast v2, Lg4/d;

    .line 373
    .line 374
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 375
    .line 376
    check-cast v0, Lgy0/j;

    .line 377
    .line 378
    const-string v3, "<this>"

    .line 379
    .line 380
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    const-string v3, "range"

    .line 384
    .line 385
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v1}, Landroid/text/style/URLSpan;->getURL()Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    const-string v3, "urlSpan.url"

    .line 393
    .line 394
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    iget v3, v0, Lgy0/h;->d:I

    .line 398
    .line 399
    iget v0, v0, Lgy0/h;->e:I

    .line 400
    .line 401
    const-string v4, "com.aghajari.compose.text.urlAnnotation"

    .line 402
    .line 403
    invoke-virtual {v2, v4, v1, v3, v0}, Lg4/d;->a(Ljava/lang/String;Ljava/lang/String;II)V

    .line 404
    .line 405
    .line 406
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 407
    .line 408
    return-object v0

    .line 409
    :pswitch_3
    iget-object v1, v0, La3/g;->g:Ljava/lang/Object;

    .line 410
    .line 411
    check-cast v1, Lh7/a0;

    .line 412
    .line 413
    invoke-virtual {v1}, Lh7/a0;->a()J

    .line 414
    .line 415
    .line 416
    move-result-wide v2

    .line 417
    iget-object v4, v0, La3/g;->h:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast v4, Lh7/x;

    .line 420
    .line 421
    iget-wide v5, v4, Lh7/x;->b:J

    .line 422
    .line 423
    invoke-static {v2, v3, v5, v6}, Lmy0/c;->c(JJ)I

    .line 424
    .line 425
    .line 426
    move-result v2

    .line 427
    if-gez v2, :cond_6

    .line 428
    .line 429
    iget-wide v2, v4, Lh7/x;->b:J

    .line 430
    .line 431
    iget-object v4, v1, Lh7/a0;->e:Ljava/util/concurrent/atomic/AtomicReference;

    .line 432
    .line 433
    new-instance v5, Lh7/y;

    .line 434
    .line 435
    const/4 v6, 0x0

    .line 436
    invoke-direct {v5, v2, v3, v6}, Lh7/y;-><init>(JI)V

    .line 437
    .line 438
    .line 439
    :goto_3
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    invoke-virtual {v5, v2}, Lh7/y;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    move-result-object v3

    .line 447
    :cond_4
    invoke-virtual {v4, v2, v3}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v6

    .line 451
    if-eqz v6, :cond_5

    .line 452
    .line 453
    goto :goto_4

    .line 454
    :cond_5
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v6

    .line 458
    if-eq v6, v2, :cond_4

    .line 459
    .line 460
    goto :goto_3

    .line 461
    :cond_6
    :goto_4
    new-instance v2, Lh7/e;

    .line 462
    .line 463
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 464
    .line 465
    check-cast v0, Lh7/f;

    .line 466
    .line 467
    const/4 v3, 0x1

    .line 468
    const/4 v4, 0x0

    .line 469
    invoke-direct {v2, v0, v4, v3}, Lh7/e;-><init>(Lh7/f;Lkotlin/coroutines/Continuation;I)V

    .line 470
    .line 471
    .line 472
    const/4 v0, 0x3

    .line 473
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 474
    .line 475
    .line 476
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 477
    .line 478
    return-object v0

    .line 479
    :pswitch_4
    move-object/from16 v1, p1

    .line 480
    .line 481
    check-cast v1, Lc3/v;

    .line 482
    .line 483
    iget-object v2, v0, La3/g;->g:Ljava/lang/Object;

    .line 484
    .line 485
    check-cast v2, Lc3/v;

    .line 486
    .line 487
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 488
    .line 489
    .line 490
    move-result v2

    .line 491
    if-eqz v2, :cond_7

    .line 492
    .line 493
    const/4 v0, 0x0

    .line 494
    goto :goto_5

    .line 495
    :cond_7
    iget-object v2, v0, La3/g;->h:Ljava/lang/Object;

    .line 496
    .line 497
    check-cast v2, Lc3/l;

    .line 498
    .line 499
    iget-object v2, v2, Lc3/l;->c:Lc3/v;

    .line 500
    .line 501
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 502
    .line 503
    .line 504
    move-result v2

    .line 505
    if-nez v2, :cond_8

    .line 506
    .line 507
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 508
    .line 509
    check-cast v0, Lkotlin/jvm/internal/n;

    .line 510
    .line 511
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    check-cast v0, Ljava/lang/Boolean;

    .line 516
    .line 517
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 518
    .line 519
    .line 520
    move-result v0

    .line 521
    :goto_5
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 522
    .line 523
    .line 524
    move-result-object v0

    .line 525
    return-object v0

    .line 526
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 527
    .line 528
    const-string v1, "Focus search landed at the root."

    .line 529
    .line 530
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    throw v0

    .line 534
    :pswitch_5
    move-object/from16 v1, p1

    .line 535
    .line 536
    check-cast v1, Lb1/i0;

    .line 537
    .line 538
    iget-object v2, v0, La3/g;->i:Ljava/lang/Object;

    .line 539
    .line 540
    check-cast v2, Lb1/u0;

    .line 541
    .line 542
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 543
    .line 544
    .line 545
    move-result v1

    .line 546
    const/4 v3, 0x0

    .line 547
    if-eqz v1, :cond_b

    .line 548
    .line 549
    const/4 v4, 0x1

    .line 550
    if-eq v1, v4, :cond_a

    .line 551
    .line 552
    const/4 v0, 0x2

    .line 553
    if-ne v1, v0, :cond_9

    .line 554
    .line 555
    iget-object v0, v2, Lb1/u0;->a:Lb1/i1;

    .line 556
    .line 557
    goto :goto_6

    .line 558
    :cond_9
    new-instance v0, La8/r0;

    .line 559
    .line 560
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 561
    .line 562
    .line 563
    throw v0

    .line 564
    :cond_a
    iget-object v0, v0, La3/g;->g:Ljava/lang/Object;

    .line 565
    .line 566
    move-object v3, v0

    .line 567
    check-cast v3, Le3/q0;

    .line 568
    .line 569
    goto :goto_6

    .line 570
    :cond_b
    iget-object v0, v2, Lb1/u0;->a:Lb1/i1;

    .line 571
    .line 572
    :goto_6
    if-eqz v3, :cond_c

    .line 573
    .line 574
    iget-wide v0, v3, Le3/q0;->a:J

    .line 575
    .line 576
    goto :goto_7

    .line 577
    :cond_c
    sget-wide v0, Le3/q0;->b:J

    .line 578
    .line 579
    :goto_7
    new-instance v2, Le3/q0;

    .line 580
    .line 581
    invoke-direct {v2, v0, v1}, Le3/q0;-><init>(J)V

    .line 582
    .line 583
    .line 584
    return-object v2

    .line 585
    :pswitch_6
    move-object/from16 v1, p1

    .line 586
    .line 587
    check-cast v1, Le3/k0;

    .line 588
    .line 589
    iget-object v2, v0, La3/g;->h:Ljava/lang/Object;

    .line 590
    .line 591
    check-cast v2, Ll2/t2;

    .line 592
    .line 593
    iget-object v3, v0, La3/g;->g:Ljava/lang/Object;

    .line 594
    .line 595
    check-cast v3, Ll2/t2;

    .line 596
    .line 597
    const/high16 v4, 0x3f800000    # 1.0f

    .line 598
    .line 599
    if-eqz v3, :cond_d

    .line 600
    .line 601
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    move-result-object v3

    .line 605
    check-cast v3, Ljava/lang/Number;

    .line 606
    .line 607
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 608
    .line 609
    .line 610
    move-result v3

    .line 611
    goto :goto_8

    .line 612
    :cond_d
    move v3, v4

    .line 613
    :goto_8
    invoke-virtual {v1, v3}, Le3/k0;->b(F)V

    .line 614
    .line 615
    .line 616
    if-eqz v2, :cond_e

    .line 617
    .line 618
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 619
    .line 620
    .line 621
    move-result-object v3

    .line 622
    check-cast v3, Ljava/lang/Number;

    .line 623
    .line 624
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 625
    .line 626
    .line 627
    move-result v3

    .line 628
    goto :goto_9

    .line 629
    :cond_e
    move v3, v4

    .line 630
    :goto_9
    invoke-virtual {v1, v3}, Le3/k0;->l(F)V

    .line 631
    .line 632
    .line 633
    if-eqz v2, :cond_f

    .line 634
    .line 635
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 636
    .line 637
    .line 638
    move-result-object v2

    .line 639
    check-cast v2, Ljava/lang/Number;

    .line 640
    .line 641
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 642
    .line 643
    .line 644
    move-result v4

    .line 645
    :cond_f
    invoke-virtual {v1, v4}, Le3/k0;->p(F)V

    .line 646
    .line 647
    .line 648
    iget-object v0, v0, La3/g;->i:Ljava/lang/Object;

    .line 649
    .line 650
    check-cast v0, Ll2/t2;

    .line 651
    .line 652
    if-eqz v0, :cond_10

    .line 653
    .line 654
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 655
    .line 656
    .line 657
    move-result-object v0

    .line 658
    check-cast v0, Le3/q0;

    .line 659
    .line 660
    iget-wide v2, v0, Le3/q0;->a:J

    .line 661
    .line 662
    goto :goto_a

    .line 663
    :cond_10
    sget-wide v2, Le3/q0;->b:J

    .line 664
    .line 665
    :goto_a
    invoke-virtual {v1, v2, v3}, Le3/k0;->A(J)V

    .line 666
    .line 667
    .line 668
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 669
    .line 670
    return-object v0

    .line 671
    :pswitch_7
    move-object/from16 v1, p1

    .line 672
    .line 673
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 674
    .line 675
    iget-object v1, v0, La3/g;->g:Ljava/lang/Object;

    .line 676
    .line 677
    check-cast v1, Lv2/o;

    .line 678
    .line 679
    iget-object v2, v0, La3/g;->i:Ljava/lang/Object;

    .line 680
    .line 681
    check-cast v2, Lb1/t;

    .line 682
    .line 683
    new-instance v3, Laa/q;

    .line 684
    .line 685
    iget-object v0, v0, La3/g;->h:Ljava/lang/Object;

    .line 686
    .line 687
    invoke-direct {v3, v1, v0, v2}, Laa/q;-><init>(Lv2/o;Ljava/lang/Object;Lb1/t;)V

    .line 688
    .line 689
    .line 690
    return-object v3

    .line 691
    :pswitch_8
    move-object/from16 v1, p1

    .line 692
    .line 693
    check-cast v1, Lv3/c2;

    .line 694
    .line 695
    move-object v2, v1

    .line 696
    check-cast v2, La3/h;

    .line 697
    .line 698
    iget-object v3, v0, La3/g;->h:Ljava/lang/Object;

    .line 699
    .line 700
    check-cast v3, La3/h;

    .line 701
    .line 702
    invoke-static {v3}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 703
    .line 704
    .line 705
    move-result-object v3

    .line 706
    check-cast v3, Lw3/t;

    .line 707
    .line 708
    invoke-virtual {v3}, Lw3/t;->getDragAndDropManager()La3/c;

    .line 709
    .line 710
    .line 711
    move-result-object v3

    .line 712
    check-cast v3, La3/a;

    .line 713
    .line 714
    iget-object v3, v3, La3/a;->b:Landroidx/collection/g;

    .line 715
    .line 716
    invoke-virtual {v3, v2}, Landroidx/collection/g;->contains(Ljava/lang/Object;)Z

    .line 717
    .line 718
    .line 719
    move-result v3

    .line 720
    if-eqz v3, :cond_11

    .line 721
    .line 722
    iget-object v3, v0, La3/g;->i:Ljava/lang/Object;

    .line 723
    .line 724
    check-cast v3, Lbu/c;

    .line 725
    .line 726
    invoke-static {v3}, Lcom/google/android/gms/internal/measurement/c4;->a(Lbu/c;)J

    .line 727
    .line 728
    .line 729
    move-result-wide v3

    .line 730
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/measurement/z3;->b(La3/h;J)Z

    .line 731
    .line 732
    .line 733
    move-result v2

    .line 734
    if-eqz v2, :cond_11

    .line 735
    .line 736
    iget-object v0, v0, La3/g;->g:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast v0, Lkotlin/jvm/internal/f0;

    .line 739
    .line 740
    iput-object v1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 741
    .line 742
    sget-object v0, Lv3/b2;->f:Lv3/b2;

    .line 743
    .line 744
    goto :goto_b

    .line 745
    :cond_11
    sget-object v0, Lv3/b2;->d:Lv3/b2;

    .line 746
    .line 747
    :goto_b
    return-object v0

    .line 748
    nop

    .line 749
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
