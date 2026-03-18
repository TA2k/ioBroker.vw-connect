.class public final Lbx/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 17

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "type"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "annotations"

    .line 13
    .line 14
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    check-cast v0, Ljava/util/Collection;

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v3, 0x0

    .line 24
    if-nez v0, :cond_0

    .line 25
    .line 26
    goto/16 :goto_1

    .line 27
    .line 28
    :cond_0
    invoke-static {v1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    const-string v0, "getRawType(this)"

    .line 33
    .line 34
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v4}, Ljava/lang/Class;->isInterface()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_1

    .line 42
    .line 43
    goto/16 :goto_1

    .line 44
    .line 45
    :cond_1
    invoke-virtual {v4}, Ljava/lang/Class;->isEnum()Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    goto/16 :goto_1

    .line 52
    .line 53
    :cond_2
    const-class v0, Lkotlin/Metadata;

    .line 54
    .line 55
    invoke-virtual {v4, v0}, Ljava/lang/Class;->isAnnotationPresent(Ljava/lang/Class;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-nez v0, :cond_3

    .line 60
    .line 61
    goto/16 :goto_1

    .line 62
    .line 63
    :cond_3
    invoke-static {v4}, Lax/b;->e(Ljava/lang/Class;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    :try_start_0
    invoke-static {v2, v1, v4}, Lax/b;->c(Lcom/squareup/moshi/Moshi;Ljava/lang/reflect/Type;Ljava/lang/Class;)Lax/a;

    .line 71
    .line 72
    .line 73
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 74
    if-eqz v0, :cond_5

    .line 75
    .line 76
    return-object v0

    .line 77
    :catch_0
    move-exception v0

    .line 78
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    instance-of v5, v5, Ljava/lang/ClassNotFoundException;

    .line 83
    .line 84
    if-eqz v5, :cond_32

    .line 85
    .line 86
    :cond_5
    invoke-virtual {v4}, Ljava/lang/Class;->isLocalClass()Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-nez v0, :cond_31

    .line 91
    .line 92
    invoke-static {v4}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-interface {v0}, Lhy0/d;->isAbstract()Z

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    if-nez v5, :cond_30

    .line 101
    .line 102
    invoke-interface {v0}, Lhy0/d;->isInner()Z

    .line 103
    .line 104
    .line 105
    move-result v5

    .line 106
    if-nez v5, :cond_2f

    .line 107
    .line 108
    invoke-interface {v0}, Lhy0/d;->getObjectInstance()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    if-nez v5, :cond_2e

    .line 113
    .line 114
    invoke-interface {v0}, Lhy0/d;->isSealed()Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    if-nez v5, :cond_2d

    .line 119
    .line 120
    check-cast v0, Lkotlin/reflect/jvm/internal/KClassImpl;

    .line 121
    .line 122
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/KClassImpl;->getConstructors()Ljava/util/Collection;

    .line 123
    .line 124
    .line 125
    move-result-object v5

    .line 126
    check-cast v5, Ljava/lang/Iterable;

    .line 127
    .line 128
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    :cond_6
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 133
    .line 134
    .line 135
    move-result v6

    .line 136
    if-eqz v6, :cond_7

    .line 137
    .line 138
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    move-object v7, v6

    .line 143
    check-cast v7, Lhy0/g;

    .line 144
    .line 145
    const-string v8, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KFunctionImpl"

    .line 146
    .line 147
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    check-cast v7, Lkotlin/reflect/jvm/internal/KFunctionImpl;

    .line 151
    .line 152
    invoke-virtual {v7}, Lkotlin/reflect/jvm/internal/KFunctionImpl;->getDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    const-string v8, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ConstructorDescriptor"

    .line 157
    .line 158
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    check-cast v7, Lkotlin/reflect/jvm/internal/impl/descriptors/ConstructorDescriptor;

    .line 162
    .line 163
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/descriptors/ConstructorDescriptor;->isPrimary()Z

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    if-eqz v7, :cond_6

    .line 168
    .line 169
    goto :goto_0

    .line 170
    :cond_7
    move-object v6, v3

    .line 171
    :goto_0
    check-cast v6, Lhy0/g;

    .line 172
    .line 173
    if-nez v6, :cond_8

    .line 174
    .line 175
    :goto_1
    return-object v3

    .line 176
    :cond_8
    invoke-interface {v6}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    check-cast v5, Ljava/lang/Iterable;

    .line 181
    .line 182
    const/16 v7, 0xa

    .line 183
    .line 184
    invoke-static {v5, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 185
    .line 186
    .line 187
    move-result v8

    .line 188
    invoke-static {v8}, Lmx0/x;->k(I)I

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    const/16 v9, 0x10

    .line 193
    .line 194
    if-ge v8, v9, :cond_9

    .line 195
    .line 196
    move v8, v9

    .line 197
    :cond_9
    new-instance v9, Ljava/util/LinkedHashMap;

    .line 198
    .line 199
    invoke-direct {v9, v8}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 200
    .line 201
    .line 202
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 203
    .line 204
    .line 205
    move-result-object v5

    .line 206
    :goto_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 207
    .line 208
    .line 209
    move-result v8

    .line 210
    if-eqz v8, :cond_a

    .line 211
    .line 212
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v8

    .line 216
    move-object v10, v8

    .line 217
    check-cast v10, Lhy0/q;

    .line 218
    .line 219
    invoke-interface {v10}, Lhy0/q;->getName()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v10

    .line 223
    invoke-interface {v9, v10, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_a
    invoke-static {v6}, Llp/sc;->d(Lhy0/c;)V

    .line 228
    .line 229
    .line 230
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 231
    .line 232
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/KClassImpl;->getData()Llx0/i;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    check-cast v0, Lkotlin/reflect/jvm/internal/KClassImpl$Data;

    .line 244
    .line 245
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/KClassImpl$Data;->getAllNonStaticMembers()Ljava/util/Collection;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    check-cast v0, Ljava/lang/Iterable;

    .line 250
    .line 251
    new-instance v8, Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 254
    .line 255
    .line 256
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    :cond_b
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 261
    .line 262
    .line 263
    move-result v10

    .line 264
    if-eqz v10, :cond_d

    .line 265
    .line 266
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v10

    .line 270
    move-object v11, v10

    .line 271
    check-cast v11, Lkotlin/reflect/jvm/internal/KCallableImpl;

    .line 272
    .line 273
    invoke-virtual {v11}, Lkotlin/reflect/jvm/internal/KCallableImpl;->getDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/CallableMemberDescriptor;

    .line 274
    .line 275
    .line 276
    move-result-object v12

    .line 277
    invoke-interface {v12}, Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;->getExtensionReceiverParameter()Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;

    .line 278
    .line 279
    .line 280
    move-result-object v12

    .line 281
    if-eqz v12, :cond_c

    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_c
    instance-of v11, v11, Lhy0/w;

    .line 285
    .line 286
    if-eqz v11, :cond_b

    .line 287
    .line 288
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    goto :goto_3

    .line 292
    :cond_d
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 293
    .line 294
    .line 295
    move-result-object v0

    .line 296
    :cond_e
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 297
    .line 298
    .line 299
    move-result v8

    .line 300
    const/4 v10, 0x0

    .line 301
    if-eqz v8, :cond_27

    .line 302
    .line 303
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v8

    .line 307
    move-object v14, v8

    .line 308
    check-cast v14, Lhy0/w;

    .line 309
    .line 310
    invoke-interface {v14}, Lhy0/c;->getName()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v8

    .line 314
    invoke-virtual {v9, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v8

    .line 318
    move-object v15, v8

    .line 319
    check-cast v15, Lhy0/q;

    .line 320
    .line 321
    invoke-static {v14}, Llp/sc;->d(Lhy0/c;)V

    .line 322
    .line 323
    .line 324
    invoke-interface {v14}, Lhy0/b;->getAnnotations()Ljava/util/List;

    .line 325
    .line 326
    .line 327
    move-result-object v8

    .line 328
    check-cast v8, Ljava/lang/Iterable;

    .line 329
    .line 330
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 331
    .line 332
    .line 333
    move-result-object v8

    .line 334
    :cond_f
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 335
    .line 336
    .line 337
    move-result v11

    .line 338
    if-eqz v11, :cond_10

    .line 339
    .line 340
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v11

    .line 344
    move-object v12, v11

    .line 345
    check-cast v12, Ljava/lang/annotation/Annotation;

    .line 346
    .line 347
    instance-of v12, v12, Lcom/squareup/moshi/Json;

    .line 348
    .line 349
    if-eqz v12, :cond_f

    .line 350
    .line 351
    goto :goto_5

    .line 352
    :cond_10
    move-object v11, v3

    .line 353
    :goto_5
    check-cast v11, Lcom/squareup/moshi/Json;

    .line 354
    .line 355
    invoke-interface {v14}, Lhy0/b;->getAnnotations()Ljava/util/List;

    .line 356
    .line 357
    .line 358
    move-result-object v8

    .line 359
    check-cast v8, Ljava/util/Collection;

    .line 360
    .line 361
    invoke-static {v8}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 362
    .line 363
    .line 364
    move-result-object v8

    .line 365
    if-eqz v15, :cond_13

    .line 366
    .line 367
    invoke-interface {v15}, Lhy0/b;->getAnnotations()Ljava/util/List;

    .line 368
    .line 369
    .line 370
    move-result-object v12

    .line 371
    check-cast v12, Ljava/lang/Iterable;

    .line 372
    .line 373
    invoke-static {v12, v8}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 374
    .line 375
    .line 376
    if-nez v11, :cond_13

    .line 377
    .line 378
    invoke-interface {v15}, Lhy0/b;->getAnnotations()Ljava/util/List;

    .line 379
    .line 380
    .line 381
    move-result-object v11

    .line 382
    check-cast v11, Ljava/lang/Iterable;

    .line 383
    .line 384
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 385
    .line 386
    .line 387
    move-result-object v11

    .line 388
    :cond_11
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 389
    .line 390
    .line 391
    move-result v12

    .line 392
    if-eqz v12, :cond_12

    .line 393
    .line 394
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v12

    .line 398
    move-object v13, v12

    .line 399
    check-cast v13, Ljava/lang/annotation/Annotation;

    .line 400
    .line 401
    instance-of v13, v13, Lcom/squareup/moshi/Json;

    .line 402
    .line 403
    if-eqz v13, :cond_11

    .line 404
    .line 405
    goto :goto_6

    .line 406
    :cond_12
    move-object v12, v3

    .line 407
    :goto_6
    move-object v11, v12

    .line 408
    check-cast v11, Lcom/squareup/moshi/Json;

    .line 409
    .line 410
    :cond_13
    invoke-static {v14}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 411
    .line 412
    .line 413
    move-result-object v12

    .line 414
    if-eqz v12, :cond_14

    .line 415
    .line 416
    invoke-virtual {v12}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 417
    .line 418
    .line 419
    move-result v12

    .line 420
    goto :goto_7

    .line 421
    :cond_14
    move v12, v10

    .line 422
    :goto_7
    invoke-static {v12}, Ljava/lang/reflect/Modifier;->isTransient(I)Z

    .line 423
    .line 424
    .line 425
    move-result v12

    .line 426
    if-eqz v12, :cond_16

    .line 427
    .line 428
    if-eqz v15, :cond_e

    .line 429
    .line 430
    invoke-interface {v15}, Lhy0/q;->isOptional()Z

    .line 431
    .line 432
    .line 433
    move-result v8

    .line 434
    if-eqz v8, :cond_15

    .line 435
    .line 436
    goto/16 :goto_4

    .line 437
    .line 438
    :cond_15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 439
    .line 440
    const-string v1, "No default value for transient constructor "

    .line 441
    .line 442
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 446
    .line 447
    .line 448
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 453
    .line 454
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    throw v1

    .line 462
    :cond_16
    if-eqz v11, :cond_18

    .line 463
    .line 464
    invoke-interface {v11}, Lcom/squareup/moshi/Json;->ignore()Z

    .line 465
    .line 466
    .line 467
    move-result v12

    .line 468
    const/4 v13, 0x1

    .line 469
    if-ne v12, v13, :cond_18

    .line 470
    .line 471
    if-eqz v15, :cond_e

    .line 472
    .line 473
    invoke-interface {v15}, Lhy0/q;->isOptional()Z

    .line 474
    .line 475
    .line 476
    move-result v8

    .line 477
    if-eqz v8, :cond_17

    .line 478
    .line 479
    goto/16 :goto_4

    .line 480
    .line 481
    :cond_17
    new-instance v0, Ljava/lang/StringBuilder;

    .line 482
    .line 483
    const-string v1, "No default value for ignored constructor "

    .line 484
    .line 485
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 489
    .line 490
    .line 491
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 492
    .line 493
    .line 494
    move-result-object v0

    .line 495
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 496
    .line 497
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 502
    .line 503
    .line 504
    throw v1

    .line 505
    :cond_18
    if-eqz v15, :cond_1a

    .line 506
    .line 507
    invoke-interface {v15}, Lhy0/q;->getType()Lhy0/a0;

    .line 508
    .line 509
    .line 510
    move-result-object v12

    .line 511
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 512
    .line 513
    .line 514
    move-result-object v13

    .line 515
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    move-result v12

    .line 519
    if-eqz v12, :cond_19

    .line 520
    .line 521
    goto :goto_8

    .line 522
    :cond_19
    new-instance v0, Ljava/lang/StringBuilder;

    .line 523
    .line 524
    const-string v1, "\'"

    .line 525
    .line 526
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    invoke-interface {v14}, Lhy0/c;->getName()Ljava/lang/String;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 534
    .line 535
    .line 536
    const-string v1, "\' has a constructor parameter of type "

    .line 537
    .line 538
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 539
    .line 540
    .line 541
    invoke-interface {v15}, Lhy0/q;->getType()Lhy0/a0;

    .line 542
    .line 543
    .line 544
    move-result-object v1

    .line 545
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 546
    .line 547
    .line 548
    const-string v1, " but a property of type "

    .line 549
    .line 550
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 551
    .line 552
    .line 553
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 554
    .line 555
    .line 556
    move-result-object v1

    .line 557
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 558
    .line 559
    .line 560
    const/16 v1, 0x2e

    .line 561
    .line 562
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 563
    .line 564
    .line 565
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object v0

    .line 569
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 570
    .line 571
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 572
    .line 573
    .line 574
    move-result-object v0

    .line 575
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    throw v1

    .line 579
    :cond_1a
    :goto_8
    instance-of v12, v14, Lhy0/l;

    .line 580
    .line 581
    if-nez v12, :cond_1b

    .line 582
    .line 583
    if-eqz v15, :cond_e

    .line 584
    .line 585
    :cond_1b
    if-eqz v11, :cond_1e

    .line 586
    .line 587
    invoke-interface {v11}, Lcom/squareup/moshi/Json;->name()Ljava/lang/String;

    .line 588
    .line 589
    .line 590
    move-result-object v11

    .line 591
    if-eqz v11, :cond_1e

    .line 592
    .line 593
    const-string v12, "\u0000"

    .line 594
    .line 595
    invoke-virtual {v11, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 596
    .line 597
    .line 598
    move-result v12

    .line 599
    if-nez v12, :cond_1c

    .line 600
    .line 601
    goto :goto_9

    .line 602
    :cond_1c
    move-object v11, v3

    .line 603
    :goto_9
    if-nez v11, :cond_1d

    .line 604
    .line 605
    goto :goto_b

    .line 606
    :cond_1d
    :goto_a
    move-object v12, v11

    .line 607
    goto :goto_c

    .line 608
    :cond_1e
    :goto_b
    invoke-interface {v14}, Lhy0/c;->getName()Ljava/lang/String;

    .line 609
    .line 610
    .line 611
    move-result-object v11

    .line 612
    goto :goto_a

    .line 613
    :goto_c
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 614
    .line 615
    .line 616
    move-result-object v11

    .line 617
    invoke-interface {v11}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 618
    .line 619
    .line 620
    move-result-object v11

    .line 621
    instance-of v13, v11, Lhy0/d;

    .line 622
    .line 623
    if-eqz v13, :cond_24

    .line 624
    .line 625
    check-cast v11, Lhy0/d;

    .line 626
    .line 627
    invoke-interface {v11}, Lhy0/d;->isValue()Z

    .line 628
    .line 629
    .line 630
    move-result v13

    .line 631
    if-eqz v13, :cond_23

    .line 632
    .line 633
    invoke-static {v11}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 634
    .line 635
    .line 636
    move-result-object v11

    .line 637
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 638
    .line 639
    .line 640
    move-result-object v13

    .line 641
    invoke-interface {v13}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 642
    .line 643
    .line 644
    move-result-object v13

    .line 645
    invoke-interface {v13}, Ljava/util/List;->isEmpty()Z

    .line 646
    .line 647
    .line 648
    move-result v13

    .line 649
    if-eqz v13, :cond_1f

    .line 650
    .line 651
    goto :goto_f

    .line 652
    :cond_1f
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 653
    .line 654
    .line 655
    move-result-object v13

    .line 656
    invoke-interface {v13}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 657
    .line 658
    .line 659
    move-result-object v13

    .line 660
    check-cast v13, Ljava/lang/Iterable;

    .line 661
    .line 662
    new-instance v3, Ljava/util/ArrayList;

    .line 663
    .line 664
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 665
    .line 666
    .line 667
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 668
    .line 669
    .line 670
    move-result-object v13

    .line 671
    :goto_d
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 672
    .line 673
    .line 674
    move-result v16

    .line 675
    if-eqz v16, :cond_22

    .line 676
    .line 677
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 678
    .line 679
    .line 680
    move-result-object v16

    .line 681
    move-object/from16 v7, v16

    .line 682
    .line 683
    check-cast v7, Lhy0/d0;

    .line 684
    .line 685
    iget-object v7, v7, Lhy0/d0;->b:Lhy0/a0;

    .line 686
    .line 687
    if-eqz v7, :cond_20

    .line 688
    .line 689
    invoke-static {v7}, Ljy0/a;->c(Lhy0/a0;)Ljava/lang/reflect/Type;

    .line 690
    .line 691
    .line 692
    move-result-object v7

    .line 693
    goto :goto_e

    .line 694
    :cond_20
    const/4 v7, 0x0

    .line 695
    :goto_e
    if-eqz v7, :cond_21

    .line 696
    .line 697
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 698
    .line 699
    .line 700
    :cond_21
    const/16 v7, 0xa

    .line 701
    .line 702
    goto :goto_d

    .line 703
    :cond_22
    new-array v7, v10, [Ljava/lang/reflect/Type;

    .line 704
    .line 705
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object v3

    .line 709
    check-cast v3, [Ljava/lang/reflect/Type;

    .line 710
    .line 711
    array-length v7, v3

    .line 712
    invoke-static {v3, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 713
    .line 714
    .line 715
    move-result-object v3

    .line 716
    check-cast v3, [Ljava/lang/reflect/Type;

    .line 717
    .line 718
    invoke-static {v11, v3}, Lcom/squareup/moshi/Types;->d(Ljava/lang/Class;[Ljava/lang/reflect/Type;)Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;

    .line 719
    .line 720
    .line 721
    move-result-object v11

    .line 722
    goto :goto_f

    .line 723
    :cond_23
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 724
    .line 725
    .line 726
    move-result-object v3

    .line 727
    invoke-static {v3}, Ljy0/a;->c(Lhy0/a0;)Ljava/lang/reflect/Type;

    .line 728
    .line 729
    .line 730
    move-result-object v11

    .line 731
    goto :goto_f

    .line 732
    :cond_24
    instance-of v3, v11, Lhy0/b0;

    .line 733
    .line 734
    if-eqz v3, :cond_26

    .line 735
    .line 736
    invoke-interface {v14}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 737
    .line 738
    .line 739
    move-result-object v3

    .line 740
    invoke-static {v3}, Ljy0/a;->c(Lhy0/a0;)Ljava/lang/reflect/Type;

    .line 741
    .line 742
    .line 743
    move-result-object v11

    .line 744
    :goto_f
    new-instance v3, Ljava/util/LinkedHashSet;

    .line 745
    .line 746
    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    .line 747
    .line 748
    .line 749
    invoke-static {v1, v4, v11, v3}, Lax/b;->h(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/LinkedHashSet;)Ljava/lang/reflect/Type;

    .line 750
    .line 751
    .line 752
    move-result-object v3

    .line 753
    new-array v7, v10, [Ljava/lang/annotation/Annotation;

    .line 754
    .line 755
    invoke-virtual {v8, v7}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    move-result-object v7

    .line 759
    check-cast v7, [Ljava/lang/annotation/Annotation;

    .line 760
    .line 761
    invoke-static {v7}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 762
    .line 763
    .line 764
    move-result-object v7

    .line 765
    invoke-interface {v14}, Lhy0/c;->getName()Ljava/lang/String;

    .line 766
    .line 767
    .line 768
    move-result-object v8

    .line 769
    invoke-virtual {v2, v3, v7, v8}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 770
    .line 771
    .line 772
    move-result-object v13

    .line 773
    invoke-interface {v14}, Lhy0/c;->getName()Ljava/lang/String;

    .line 774
    .line 775
    .line 776
    move-result-object v3

    .line 777
    new-instance v11, Lbx/a;

    .line 778
    .line 779
    if-eqz v15, :cond_25

    .line 780
    .line 781
    invoke-interface {v15}, Lhy0/q;->getIndex()I

    .line 782
    .line 783
    .line 784
    move-result v7

    .line 785
    :goto_10
    move/from16 v16, v7

    .line 786
    .line 787
    goto :goto_11

    .line 788
    :cond_25
    const/4 v7, -0x1

    .line 789
    goto :goto_10

    .line 790
    :goto_11
    invoke-direct/range {v11 .. v16}, Lbx/a;-><init>(Ljava/lang/String;Lcom/squareup/moshi/JsonAdapter;Lhy0/w;Lhy0/q;I)V

    .line 791
    .line 792
    .line 793
    invoke-interface {v5, v3, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    const/4 v3, 0x0

    .line 797
    const/16 v7, 0xa

    .line 798
    .line 799
    goto/16 :goto_4

    .line 800
    .line 801
    :cond_26
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 802
    .line 803
    const-string v1, "Not possible!"

    .line 804
    .line 805
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 806
    .line 807
    .line 808
    throw v0

    .line 809
    :cond_27
    new-instance v0, Ljava/util/ArrayList;

    .line 810
    .line 811
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 812
    .line 813
    .line 814
    invoke-interface {v6}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 815
    .line 816
    .line 817
    move-result-object v1

    .line 818
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 819
    .line 820
    .line 821
    move-result-object v1

    .line 822
    :goto_12
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 823
    .line 824
    .line 825
    move-result v2

    .line 826
    if-eqz v2, :cond_2a

    .line 827
    .line 828
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 829
    .line 830
    .line 831
    move-result-object v2

    .line 832
    check-cast v2, Lhy0/q;

    .line 833
    .line 834
    invoke-interface {v2}, Lhy0/q;->getName()Ljava/lang/String;

    .line 835
    .line 836
    .line 837
    move-result-object v3

    .line 838
    invoke-static {v5}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    .line 839
    .line 840
    .line 841
    move-result-object v4

    .line 842
    invoke-interface {v4, v3}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 843
    .line 844
    .line 845
    move-result-object v3

    .line 846
    check-cast v3, Lbx/a;

    .line 847
    .line 848
    if-nez v3, :cond_29

    .line 849
    .line 850
    invoke-interface {v2}, Lhy0/q;->isOptional()Z

    .line 851
    .line 852
    .line 853
    move-result v4

    .line 854
    if-eqz v4, :cond_28

    .line 855
    .line 856
    goto :goto_13

    .line 857
    :cond_28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 858
    .line 859
    const-string v1, "No property for required constructor "

    .line 860
    .line 861
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 862
    .line 863
    .line 864
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 865
    .line 866
    .line 867
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 868
    .line 869
    .line 870
    move-result-object v0

    .line 871
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 872
    .line 873
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 874
    .line 875
    .line 876
    move-result-object v0

    .line 877
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 878
    .line 879
    .line 880
    throw v1

    .line 881
    :cond_29
    :goto_13
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 882
    .line 883
    .line 884
    goto :goto_12

    .line 885
    :cond_2a
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 886
    .line 887
    .line 888
    move-result v1

    .line 889
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 890
    .line 891
    .line 892
    move-result-object v2

    .line 893
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 894
    .line 895
    .line 896
    move-result-object v2

    .line 897
    move/from16 v16, v1

    .line 898
    .line 899
    :goto_14
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 900
    .line 901
    .line 902
    move-result v1

    .line 903
    if-eqz v1, :cond_2b

    .line 904
    .line 905
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 906
    .line 907
    .line 908
    move-result-object v1

    .line 909
    check-cast v1, Ljava/util/Map$Entry;

    .line 910
    .line 911
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 912
    .line 913
    .line 914
    move-result-object v1

    .line 915
    check-cast v1, Lbx/a;

    .line 916
    .line 917
    add-int/lit8 v3, v16, 0x1

    .line 918
    .line 919
    iget-object v12, v1, Lbx/a;->a:Ljava/lang/String;

    .line 920
    .line 921
    iget-object v13, v1, Lbx/a;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 922
    .line 923
    iget-object v14, v1, Lbx/a;->c:Lhy0/w;

    .line 924
    .line 925
    iget-object v15, v1, Lbx/a;->d:Lhy0/q;

    .line 926
    .line 927
    const-string v1, "jsonName"

    .line 928
    .line 929
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 930
    .line 931
    .line 932
    new-instance v11, Lbx/a;

    .line 933
    .line 934
    invoke-direct/range {v11 .. v16}, Lbx/a;-><init>(Ljava/lang/String;Lcom/squareup/moshi/JsonAdapter;Lhy0/w;Lhy0/q;I)V

    .line 935
    .line 936
    .line 937
    invoke-virtual {v0, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 938
    .line 939
    .line 940
    move/from16 v16, v3

    .line 941
    .line 942
    goto :goto_14

    .line 943
    :cond_2b
    invoke-static {v0}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 944
    .line 945
    .line 946
    move-result-object v1

    .line 947
    new-instance v2, Ljava/util/ArrayList;

    .line 948
    .line 949
    const/16 v3, 0xa

    .line 950
    .line 951
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 952
    .line 953
    .line 954
    move-result v3

    .line 955
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 956
    .line 957
    .line 958
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 959
    .line 960
    .line 961
    move-result-object v3

    .line 962
    :goto_15
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 963
    .line 964
    .line 965
    move-result v4

    .line 966
    if-eqz v4, :cond_2c

    .line 967
    .line 968
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 969
    .line 970
    .line 971
    move-result-object v4

    .line 972
    check-cast v4, Lbx/a;

    .line 973
    .line 974
    iget-object v4, v4, Lbx/a;->a:Ljava/lang/String;

    .line 975
    .line 976
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 977
    .line 978
    .line 979
    goto :goto_15

    .line 980
    :cond_2c
    new-array v3, v10, [Ljava/lang/String;

    .line 981
    .line 982
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 983
    .line 984
    .line 985
    move-result-object v2

    .line 986
    check-cast v2, [Ljava/lang/String;

    .line 987
    .line 988
    array-length v3, v2

    .line 989
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 990
    .line 991
    .line 992
    move-result-object v2

    .line 993
    check-cast v2, [Ljava/lang/String;

    .line 994
    .line 995
    invoke-static {v2}, Lcom/squareup/moshi/JsonReader$Options;->a([Ljava/lang/String;)Lcom/squareup/moshi/JsonReader$Options;

    .line 996
    .line 997
    .line 998
    move-result-object v2

    .line 999
    new-instance v3, Lbx/c;

    .line 1000
    .line 1001
    invoke-direct {v3, v6, v0, v1, v2}, Lbx/c;-><init>(Lhy0/g;Ljava/util/ArrayList;Ljava/util/ArrayList;Lcom/squareup/moshi/JsonReader$Options;)V

    .line 1002
    .line 1003
    .line 1004
    invoke-virtual {v3}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v0

    .line 1008
    return-object v0

    .line 1009
    :cond_2d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1010
    .line 1011
    const-string v1, "Cannot reflectively serialize sealed class "

    .line 1012
    .line 1013
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1014
    .line 1015
    .line 1016
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v1

    .line 1020
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1021
    .line 1022
    .line 1023
    const-string v1, ". Please register an adapter."

    .line 1024
    .line 1025
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1026
    .line 1027
    .line 1028
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v0

    .line 1032
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 1033
    .line 1034
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v0

    .line 1038
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    throw v1

    .line 1042
    :cond_2e
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v0

    .line 1046
    const-string v1, "Cannot serialize object declaration "

    .line 1047
    .line 1048
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v0

    .line 1052
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 1053
    .line 1054
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v0

    .line 1058
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1059
    .line 1060
    .line 1061
    throw v1

    .line 1062
    :cond_2f
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    const-string v1, "Cannot serialize inner class "

    .line 1067
    .line 1068
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v0

    .line 1072
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 1073
    .line 1074
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v0

    .line 1078
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1079
    .line 1080
    .line 1081
    throw v1

    .line 1082
    :cond_30
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1083
    .line 1084
    .line 1085
    move-result-object v0

    .line 1086
    const-string v1, "Cannot serialize abstract class "

    .line 1087
    .line 1088
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v0

    .line 1092
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 1093
    .line 1094
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v0

    .line 1098
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1099
    .line 1100
    .line 1101
    throw v1

    .line 1102
    :cond_31
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v0

    .line 1106
    const-string v1, "Cannot serialize local class or object expression "

    .line 1107
    .line 1108
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v0

    .line 1112
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 1113
    .line 1114
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v0

    .line 1118
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1119
    .line 1120
    .line 1121
    throw v1

    .line 1122
    :cond_32
    throw v0
.end method
