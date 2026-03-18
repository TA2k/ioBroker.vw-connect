.class public abstract Llp/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Li31/b;Z)Ljava/util/ArrayList;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Li31/b;->b:Li31/b0;

    .line 11
    .line 12
    iget-object v3, v2, Li31/b0;->a:Ljava/util/List;

    .line 13
    .line 14
    check-cast v3, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v4, Ljava/util/ArrayList;

    .line 17
    .line 18
    const/16 v5, 0xa

    .line 19
    .line 20
    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 21
    .line 22
    .line 23
    move-result v6

    .line 24
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v6

    .line 35
    const-string v7, "; name: "

    .line 36
    .line 37
    const-string v8, "; ID: "

    .line 38
    .line 39
    const-string v9, "selected: "

    .line 40
    .line 41
    if-eqz v6, :cond_0

    .line 42
    .line 43
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    check-cast v6, Li31/a0;

    .line 48
    .line 49
    iget-object v10, v6, Li31/a0;->a:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v10, Li31/g0;

    .line 52
    .line 53
    iget v10, v10, Li31/g0;->a:I

    .line 54
    .line 55
    const-string v11, "warning_"

    .line 56
    .line 57
    invoke-static {v10, v11}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v10

    .line 61
    iget-boolean v11, v6, Li31/a0;->b:Z

    .line 62
    .line 63
    iget-object v6, v6, Li31/a0;->a:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v6, Li31/g0;

    .line 66
    .line 67
    iget v12, v6, Li31/g0;->a:I

    .line 68
    .line 69
    iget-object v6, v6, Li31/g0;->b:Ljava/lang/String;

    .line 70
    .line 71
    new-instance v13, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    invoke-direct {v13, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v13, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v13, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v13, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    new-instance v7, Llx0/l;

    .line 96
    .line 97
    invoke-direct {v7, v10, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_0
    iget-object v3, v2, Li31/b0;->b:Ljava/util/List;

    .line 105
    .line 106
    check-cast v3, Ljava/lang/Iterable;

    .line 107
    .line 108
    new-instance v6, Ljava/util/ArrayList;

    .line 109
    .line 110
    invoke-static {v3, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 111
    .line 112
    .line 113
    move-result v10

    .line 114
    invoke-direct {v6, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 115
    .line 116
    .line 117
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v10

    .line 125
    if-eqz v10, :cond_1

    .line 126
    .line 127
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    check-cast v10, Li31/a0;

    .line 132
    .line 133
    iget-object v11, v10, Li31/a0;->a:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v11, Li31/z;

    .line 136
    .line 137
    iget v11, v11, Li31/z;->b:I

    .line 138
    .line 139
    const-string v12, "prediction_"

    .line 140
    .line 141
    invoke-static {v11, v12}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v11

    .line 145
    iget-boolean v12, v10, Li31/a0;->b:Z

    .line 146
    .line 147
    iget-object v10, v10, Li31/a0;->a:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v10, Li31/z;

    .line 150
    .line 151
    iget v13, v10, Li31/z;->b:I

    .line 152
    .line 153
    iget-object v10, v10, Li31/z;->c:Ljava/lang/String;

    .line 154
    .line 155
    new-instance v14, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    invoke-direct {v14, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v14, v12}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v14, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v14, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    invoke-virtual {v14, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    invoke-virtual {v14, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v10

    .line 179
    new-instance v12, Llx0/l;

    .line 180
    .line 181
    invoke-direct {v12, v11, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    goto :goto_1

    .line 188
    :cond_1
    invoke-static {v6, v4}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    const/4 v4, 0x1

    .line 193
    const-string v6, "item_"

    .line 194
    .line 195
    if-ne v1, v4, :cond_4

    .line 196
    .line 197
    iget-object v1, v2, Li31/b0;->c:Ljava/util/List;

    .line 198
    .line 199
    check-cast v1, Ljava/lang/Iterable;

    .line 200
    .line 201
    new-instance v2, Ljava/util/ArrayList;

    .line 202
    .line 203
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 204
    .line 205
    .line 206
    move-result v4

    .line 207
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 208
    .line 209
    .line 210
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 215
    .line 216
    .line 217
    move-result v4

    .line 218
    if-eqz v4, :cond_5

    .line 219
    .line 220
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v4

    .line 224
    check-cast v4, Li31/a0;

    .line 225
    .line 226
    iget-object v5, v4, Li31/a0;->a:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast v5, Li31/c0;

    .line 229
    .line 230
    iget-object v10, v5, Li31/c0;->c:Ljava/lang/String;

    .line 231
    .line 232
    invoke-virtual {v6, v10}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object v10

    .line 236
    iget-boolean v4, v4, Li31/a0;->b:Z

    .line 237
    .line 238
    iget-object v11, v5, Li31/c0;->c:Ljava/lang/String;

    .line 239
    .line 240
    iget-object v12, v5, Li31/c0;->e:Li31/f;

    .line 241
    .line 242
    iget-object v13, v5, Li31/c0;->d:Ljava/lang/String;

    .line 243
    .line 244
    if-eqz v12, :cond_2

    .line 245
    .line 246
    iget-wide v14, v12, Li31/f;->b:D

    .line 247
    .line 248
    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 249
    .line 250
    .line 251
    move-result-object v14

    .line 252
    goto :goto_3

    .line 253
    :cond_2
    const/4 v14, 0x0

    .line 254
    :goto_3
    if-eqz v12, :cond_3

    .line 255
    .line 256
    iget-object v12, v12, Li31/f;->a:Ljava/lang/String;

    .line 257
    .line 258
    goto :goto_4

    .line 259
    :cond_3
    const/4 v12, 0x0

    .line 260
    :goto_4
    iget-object v15, v5, Li31/c0;->a:Ljava/lang/String;

    .line 261
    .line 262
    iget-object v5, v5, Li31/c0;->b:Ljava/lang/String;

    .line 263
    .line 264
    invoke-static {v9, v8, v11, v7, v4}, La7/g0;->n(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    move-result-object v4

    .line 268
    invoke-virtual {v4, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    const-string v11, "; price: "

    .line 272
    .line 273
    invoke-virtual {v4, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 274
    .line 275
    .line 276
    invoke-virtual {v4, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    const-string v11, "; currency: "

    .line 280
    .line 281
    invoke-virtual {v4, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 282
    .line 283
    .line 284
    const-string v11, "; category: ("

    .line 285
    .line 286
    const-string v13, " "

    .line 287
    .line 288
    invoke-static {v4, v12, v11, v15, v13}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    const-string v11, ")"

    .line 292
    .line 293
    invoke-static {v4, v5, v11}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v4

    .line 297
    new-instance v5, Llx0/l;

    .line 298
    .line 299
    invoke-direct {v5, v10, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    goto :goto_2

    .line 306
    :cond_4
    if-nez v1, :cond_8

    .line 307
    .line 308
    iget-object v1, v2, Li31/b0;->d:Ljava/util/List;

    .line 309
    .line 310
    check-cast v1, Ljava/lang/Iterable;

    .line 311
    .line 312
    new-instance v2, Ljava/util/ArrayList;

    .line 313
    .line 314
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 319
    .line 320
    .line 321
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 322
    .line 323
    .line 324
    move-result-object v1

    .line 325
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 326
    .line 327
    .line 328
    move-result v4

    .line 329
    if-eqz v4, :cond_5

    .line 330
    .line 331
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v4

    .line 335
    check-cast v4, Li31/a0;

    .line 336
    .line 337
    iget-object v5, v4, Li31/a0;->a:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v5, Li31/v;

    .line 340
    .line 341
    iget v5, v5, Li31/v;->a:I

    .line 342
    .line 343
    invoke-static {v5, v6}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v5

    .line 347
    iget-boolean v10, v4, Li31/a0;->b:Z

    .line 348
    .line 349
    iget-object v4, v4, Li31/a0;->a:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v4, Li31/v;

    .line 352
    .line 353
    iget v11, v4, Li31/v;->a:I

    .line 354
    .line 355
    iget-object v4, v4, Li31/v;->b:Ljava/lang/String;

    .line 356
    .line 357
    new-instance v12, Ljava/lang/StringBuilder;

    .line 358
    .line 359
    invoke-direct {v12, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v12, v10}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 363
    .line 364
    .line 365
    invoke-virtual {v12, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 366
    .line 367
    .line 368
    invoke-virtual {v12, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    invoke-virtual {v12, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 372
    .line 373
    .line 374
    invoke-virtual {v12, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 375
    .line 376
    .line 377
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    new-instance v10, Llx0/l;

    .line 382
    .line 383
    invoke-direct {v10, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 387
    .line 388
    .line 389
    goto :goto_5

    .line 390
    :cond_5
    invoke-static {v2, v3}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 391
    .line 392
    .line 393
    move-result-object v1

    .line 394
    iget-object v2, v0, Li31/b;->d:Ljava/lang/String;

    .line 395
    .line 396
    iget-object v0, v0, Li31/b;->c:Ljava/lang/Long;

    .line 397
    .line 398
    const-string v3, "appointment"

    .line 399
    .line 400
    if-eqz v2, :cond_6

    .line 401
    .line 402
    if-eqz v0, :cond_6

    .line 403
    .line 404
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 405
    .line 406
    .line 407
    move-result-wide v4

    .line 408
    const-string v0, "dd MMMM yyyy"

    .line 409
    .line 410
    invoke-static {v4, v5, v0}, Lcom/google/android/gms/internal/measurement/i5;->b(JLjava/lang/String;)Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    const-string v4, ", "

    .line 415
    .line 416
    invoke-static {v0, v4, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v0

    .line 420
    new-instance v2, Llx0/l;

    .line 421
    .line 422
    invoke-direct {v2, v3, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 423
    .line 424
    .line 425
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 426
    .line 427
    .line 428
    move-result-object v0

    .line 429
    goto :goto_6

    .line 430
    :cond_6
    if-eqz v0, :cond_7

    .line 431
    .line 432
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 433
    .line 434
    .line 435
    move-result-wide v4

    .line 436
    const-string v0, "dd MMMM yyyy, HH:mm"

    .line 437
    .line 438
    invoke-static {v4, v5, v0}, Lcom/google/android/gms/internal/measurement/i5;->b(JLjava/lang/String;)Ljava/lang/String;

    .line 439
    .line 440
    .line 441
    move-result-object v0

    .line 442
    new-instance v2, Llx0/l;

    .line 443
    .line 444
    invoke-direct {v2, v3, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 448
    .line 449
    .line 450
    move-result-object v0

    .line 451
    goto :goto_6

    .line 452
    :cond_7
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 453
    .line 454
    :goto_6
    check-cast v0, Ljava/lang/Iterable;

    .line 455
    .line 456
    invoke-static {v0, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 457
    .line 458
    .line 459
    move-result-object v0

    .line 460
    return-object v0

    .line 461
    :cond_8
    new-instance v0, La8/r0;

    .line 462
    .line 463
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 464
    .line 465
    .line 466
    throw v0
.end method
