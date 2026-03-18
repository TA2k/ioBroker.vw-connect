.class public final Lh0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/l1;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh0/d0;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 9

    .line 1
    iget v0, p0, Lh0/d0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lc6/a;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p1, Ljava/util/List;

    .line 15
    .line 16
    const-string v0, "CameraPresencePrvdr"

    .line 17
    .line 18
    iget-object v1, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lh0/e0;

    .line 21
    .line 22
    iget-object v1, v1, Lh0/e0;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    goto/16 :goto_b

    .line 31
    .line 32
    :cond_0
    iget-object v1, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lh0/e0;

    .line 35
    .line 36
    iget-object v1, v1, Lh0/e0;->c:Lu/n;

    .line 37
    .line 38
    if-nez v1, :cond_1

    .line 39
    .line 40
    goto/16 :goto_b

    .line 41
    .line 42
    :cond_1
    const/16 v2, 0xa

    .line 43
    .line 44
    if-eqz p1, :cond_2

    .line 45
    .line 46
    check-cast p1, Ljava/lang/Iterable;

    .line 47
    .line 48
    new-instance v3, Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 55
    .line 56
    .line 57
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_3

    .line 66
    .line 67
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    check-cast v4, Lb0/q;

    .line 72
    .line 73
    invoke-virtual {v4}, Lb0/q;->a()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_2
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 82
    .line 83
    :cond_3
    :try_start_0
    invoke-virtual {v1, v3}, Lu/n;->e(Ljava/util/List;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Lu/n;->a()Ljava/util/LinkedHashSet;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    new-instance v1, Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 97
    .line 98
    .line 99
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-eqz v3, :cond_4

    .line 108
    .line 109
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    check-cast v3, Ljava/lang/String;

    .line 114
    .line 115
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    filled-new-array {v3}, [Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    invoke-static {v3}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    new-instance v4, Lb0/q;

    .line 127
    .line 128
    const/4 v5, 0x0

    .line 129
    invoke-direct {v4, v3, v5}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_4
    iget-object p0, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Lh0/e0;

    .line 139
    .line 140
    iget-object p1, p0, Lh0/e0;->g:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p1, Ljava/lang/Iterable;

    .line 143
    .line 144
    invoke-static {p1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    invoke-virtual {v1, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    if-eqz v3, :cond_5

    .line 153
    .line 154
    goto/16 :goto_b

    .line 155
    .line 156
    :cond_5
    check-cast p1, Ljava/lang/Iterable;

    .line 157
    .line 158
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    move-object v5, v3

    .line 167
    check-cast v5, Ljava/lang/Iterable;

    .line 168
    .line 169
    invoke-static {v4, v5}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    check-cast v4, Ljava/lang/Iterable;

    .line 174
    .line 175
    invoke-static {v3, v4}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    new-instance v4, Ljava/util/ArrayList;

    .line 180
    .line 181
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 182
    .line 183
    .line 184
    new-instance v6, Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 187
    .line 188
    .line 189
    move-result v7

    .line 190
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 194
    .line 195
    .line 196
    move-result-object v7

    .line 197
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result v8

    .line 201
    if-eqz v8, :cond_6

    .line 202
    .line 203
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    check-cast v8, Lb0/q;

    .line 208
    .line 209
    invoke-virtual {v8}, Lb0/q;->a()Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    goto :goto_2

    .line 217
    :cond_6
    :try_start_1
    move-object v7, v3

    .line 218
    check-cast v7, Ljava/lang/Iterable;

    .line 219
    .line 220
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 221
    .line 222
    .line 223
    move-result-object v7

    .line 224
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 225
    .line 226
    .line 227
    move-result v8

    .line 228
    if-eqz v8, :cond_7

    .line 229
    .line 230
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v8

    .line 234
    check-cast v8, Lb0/q;

    .line 235
    .line 236
    invoke-virtual {v8}, Lb0/q;->a()Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v8

    .line 240
    invoke-virtual {p0, v8}, Lh0/e0;->c(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    goto :goto_3

    .line 244
    :catch_0
    move-exception v1

    .line 245
    goto/16 :goto_6

    .line 246
    .line 247
    :cond_7
    iget-object v7, p0, Lh0/e0;->d:Lh0/i0;

    .line 248
    .line 249
    if-eqz v7, :cond_8

    .line 250
    .line 251
    const-string v8, "Updating CameraRepository..."

    .line 252
    .line 253
    invoke-static {v0, v8}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v7, v6}, Lh0/i0;->a(Ljava/util/List;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    const-string v7, "CameraRepository updated successfully."

    .line 263
    .line 264
    invoke-static {v0, v7}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    :cond_8
    iget-object v7, p0, Lh0/e0;->i:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 268
    .line 269
    invoke-virtual {v7}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    .line 270
    .line 271
    .line 272
    move-result v7

    .line 273
    if-nez v7, :cond_9

    .line 274
    .line 275
    new-instance v7, Ljava/lang/StringBuilder;

    .line 276
    .line 277
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 278
    .line 279
    .line 280
    const-string v8, "Updating "

    .line 281
    .line 282
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 283
    .line 284
    .line 285
    iget-object v8, p0, Lh0/e0;->i:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 286
    .line 287
    invoke-virtual {v8}, Ljava/util/concurrent/CopyOnWriteArrayList;->size()I

    .line 288
    .line 289
    .line 290
    move-result v8

    .line 291
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    const-string v8, " dependent listeners..."

    .line 295
    .line 296
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v7

    .line 303
    invoke-static {v0, v7}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    iget-object v7, p0, Lh0/e0;->i:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 307
    .line 308
    invoke-virtual {v7}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 309
    .line 310
    .line 311
    move-result-object v7

    .line 312
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 313
    .line 314
    .line 315
    move-result v8

    .line 316
    if-eqz v8, :cond_9

    .line 317
    .line 318
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v8

    .line 322
    check-cast v8, Lh0/d1;

    .line 323
    .line 324
    invoke-interface {v8, v6}, Lh0/d1;->a(Ljava/util/List;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    goto :goto_4

    .line 331
    :cond_9
    iput-object v1, p0, Lh0/e0;->g:Ljava/lang/Object;

    .line 332
    .line 333
    move-object v1, v5

    .line 334
    check-cast v1, Ljava/lang/Iterable;

    .line 335
    .line 336
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v1

    .line 340
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 341
    .line 342
    .line 343
    move-result v6

    .line 344
    if-eqz v6, :cond_a

    .line 345
    .line 346
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v6

    .line 350
    check-cast v6, Lb0/q;

    .line 351
    .line 352
    invoke-virtual {v6}, Lb0/q;->a()Ljava/lang/String;

    .line 353
    .line 354
    .line 355
    move-result-object v6

    .line 356
    invoke-virtual {p0, v6}, Lh0/e0;->a(Ljava/lang/String;)V

    .line 357
    .line 358
    .line 359
    goto :goto_5

    .line 360
    :cond_a
    invoke-virtual {p0, v5, v3}, Lh0/e0;->b(Ljava/util/Set;Ljava/util/Set;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 361
    .line 362
    .line 363
    goto/16 :goto_b

    .line 364
    .line 365
    :goto_6
    const-string v6, "A core module failed to update. Rolling back changes."

    .line 366
    .line 367
    invoke-static {v0, v6, v1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 368
    .line 369
    .line 370
    new-instance v1, Ljava/util/ArrayList;

    .line 371
    .line 372
    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 377
    .line 378
    .line 379
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 380
    .line 381
    .line 382
    move-result-object p1

    .line 383
    :goto_7
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 384
    .line 385
    .line 386
    move-result v2

    .line 387
    if-eqz v2, :cond_b

    .line 388
    .line 389
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    move-result-object v2

    .line 393
    check-cast v2, Lb0/q;

    .line 394
    .line 395
    invoke-virtual {v2}, Lb0/q;->a()Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v2

    .line 399
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    goto :goto_7

    .line 403
    :cond_b
    new-instance p1, Lmx0/z;

    .line 404
    .line 405
    invoke-direct {p1, v4}, Lmx0/z;-><init>(Ljava/util/ArrayList;)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {p1}, Lmx0/z;->iterator()Ljava/util/Iterator;

    .line 409
    .line 410
    .line 411
    move-result-object p1

    .line 412
    :goto_8
    move-object v2, p1

    .line 413
    check-cast v2, Lmx0/y;

    .line 414
    .line 415
    iget-object v4, v2, Lmx0/y;->e:Ljava/lang/Object;

    .line 416
    .line 417
    check-cast v4, Ljava/util/ListIterator;

    .line 418
    .line 419
    invoke-interface {v4}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 420
    .line 421
    .line 422
    move-result v4

    .line 423
    if-eqz v4, :cond_c

    .line 424
    .line 425
    iget-object v2, v2, Lmx0/y;->e:Ljava/lang/Object;

    .line 426
    .line 427
    check-cast v2, Ljava/util/ListIterator;

    .line 428
    .line 429
    invoke-interface {v2}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object v2

    .line 433
    check-cast v2, Lh0/d1;

    .line 434
    .line 435
    :try_start_2
    invoke-interface {v2, v1}, Lh0/d1;->a(Ljava/util/List;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 436
    .line 437
    .line 438
    goto :goto_8

    .line 439
    :catch_1
    move-exception v4

    .line 440
    new-instance v6, Ljava/lang/StringBuilder;

    .line 441
    .line 442
    const-string v7, "Failed to rollback listener: "

    .line 443
    .line 444
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 448
    .line 449
    .line 450
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v2

    .line 454
    invoke-static {v0, v2, v4}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 455
    .line 456
    .line 457
    goto :goto_8

    .line 458
    :cond_c
    check-cast v3, Ljava/lang/Iterable;

    .line 459
    .line 460
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 461
    .line 462
    .line 463
    move-result-object p1

    .line 464
    :goto_9
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 465
    .line 466
    .line 467
    move-result v0

    .line 468
    if-eqz v0, :cond_d

    .line 469
    .line 470
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    check-cast v0, Lb0/q;

    .line 475
    .line 476
    invoke-virtual {v0}, Lb0/q;->a()Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    invoke-virtual {p0, v0}, Lh0/e0;->a(Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    goto :goto_9

    .line 484
    :cond_d
    check-cast v5, Ljava/lang/Iterable;

    .line 485
    .line 486
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 487
    .line 488
    .line 489
    move-result-object p1

    .line 490
    :goto_a
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 491
    .line 492
    .line 493
    move-result v0

    .line 494
    if-eqz v0, :cond_e

    .line 495
    .line 496
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    check-cast v0, Lb0/q;

    .line 501
    .line 502
    invoke-virtual {v0}, Lb0/q;->a()Ljava/lang/String;

    .line 503
    .line 504
    .line 505
    move-result-object v0

    .line 506
    invoke-virtual {p0, v0}, Lh0/e0;->c(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    goto :goto_a

    .line 510
    :catch_2
    move-exception p1

    .line 511
    const-string v1, "CameraFactory failed to update. Triggering refresh."

    .line 512
    .line 513
    invoke-static {v0, v1, p1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 514
    .line 515
    .line 516
    iget-object p0, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast p0, Lh0/e0;

    .line 519
    .line 520
    iget-object p0, p0, Lh0/e0;->e:Lb0/d1;

    .line 521
    .line 522
    if-eqz p0, :cond_e

    .line 523
    .line 524
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 525
    .line 526
    .line 527
    :cond_e
    :goto_b
    return-void

    .line 528
    nop

    .line 529
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onError(Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    iget v0, p0, Lh0/d0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "ObserverToConsumerAdapter"

    .line 7
    .line 8
    const-string v0, "Unexpected error in Observable"

    .line 9
    .line 10
    invoke-static {p0, v0, p1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    const-string v0, "t"

    .line 15
    .line 16
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lh0/d0;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lh0/e0;

    .line 22
    .line 23
    iget-object v0, p0, Lh0/e0;->h:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const-string v0, "CameraPresencePrvdr"

    .line 33
    .line 34
    const-string v1, "Error from source camera presence observable. Triggering refresh."

    .line 35
    .line 36
    invoke-static {v0, v1, p1}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lh0/e0;->e:Lb0/d1;

    .line 40
    .line 41
    if-eqz p0, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0}, Lb0/d1;->d()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 44
    .line 45
    .line 46
    :cond_1
    :goto_0
    return-void

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
