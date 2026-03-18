.class public final Lcom/squareup/moshi/Moshi$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/Moshi;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public b:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/squareup/moshi/Moshi$Builder;->a:Ljava/util/ArrayList;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput v0, p0, Lcom/squareup/moshi/Moshi$Builder;->b:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lcom/squareup/moshi/JsonAdapter$Factory;)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/squareup/moshi/Moshi$Builder;->b:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Lcom/squareup/moshi/Moshi$Builder;->b:I

    .line 6
    .line 7
    iget-object p0, p0, Lcom/squareup/moshi/Moshi$Builder;->a:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0, v0, p1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final b(Ljava/lang/Object;)V
    .locals 24

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    :goto_0
    const-class v3, Ljava/lang/Object;

    .line 16
    .line 17
    if-eq v2, v3, :cond_13

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    array-length v4, v3

    .line 24
    const/4 v6, 0x0

    .line 25
    :goto_1
    if-ge v6, v4, :cond_12

    .line 26
    .line 27
    aget-object v11, v3, v6

    .line 28
    .line 29
    const-class v7, Lcom/squareup/moshi/ToJson;

    .line 30
    .line 31
    invoke-virtual {v11, v7}, Ljava/lang/reflect/AccessibleObject;->isAnnotationPresent(Ljava/lang/Class;)Z

    .line 32
    .line 33
    .line 34
    move-result v7

    .line 35
    const-string v15, "Nullable"

    .line 36
    .line 37
    const-class v8, Lcom/squareup/moshi/JsonAdapter;

    .line 38
    .line 39
    const-string v9, "\n    "

    .line 40
    .line 41
    const-string v10, "Unexpected signature for "

    .line 42
    .line 43
    sget-object v12, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    .line 44
    .line 45
    const/4 v13, 0x1

    .line 46
    if-eqz v7, :cond_8

    .line 47
    .line 48
    invoke-virtual {v11, v13}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getGenericReturnType()Ljava/lang/reflect/Type;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    .line 56
    .line 57
    .line 58
    move-result-object v14

    .line 59
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    .line 60
    .line 61
    .line 62
    move-result-object v16

    .line 63
    const/16 v18, 0x0

    .line 64
    .line 65
    array-length v5, v14

    .line 66
    move/from16 v17, v13

    .line 67
    .line 68
    const/4 v13, 0x2

    .line 69
    if-lt v5, v13, :cond_3

    .line 70
    .line 71
    aget-object v5, v14, v18

    .line 72
    .line 73
    const-class v13, Lcom/squareup/moshi/JsonWriter;

    .line 74
    .line 75
    if-ne v5, v13, :cond_3

    .line 76
    .line 77
    if-ne v7, v12, :cond_3

    .line 78
    .line 79
    array-length v5, v14

    .line 80
    const/4 v13, 0x2

    .line 81
    :goto_2
    if-ge v13, v5, :cond_2

    .line 82
    .line 83
    move-object/from16 v19, v2

    .line 84
    .line 85
    aget-object v2, v14, v13

    .line 86
    .line 87
    move-object/from16 v20, v3

    .line 88
    .line 89
    instance-of v3, v2, Ljava/lang/reflect/ParameterizedType;

    .line 90
    .line 91
    if-nez v3, :cond_0

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_0
    check-cast v2, Ljava/lang/reflect/ParameterizedType;

    .line 95
    .line 96
    invoke-interface {v2}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    if-eq v2, v8, :cond_1

    .line 101
    .line 102
    :goto_3
    move-object v3, v8

    .line 103
    move-object v5, v9

    .line 104
    move-object/from16 v21, v10

    .line 105
    .line 106
    move-object/from16 v22, v12

    .line 107
    .line 108
    move/from16 v2, v17

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_1
    add-int/lit8 v13, v13, 0x1

    .line 112
    .line 113
    move-object/from16 v2, v19

    .line 114
    .line 115
    move-object/from16 v3, v20

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_2
    move-object/from16 v19, v2

    .line 119
    .line 120
    move-object/from16 v20, v3

    .line 121
    .line 122
    aget-object v2, v16, v17

    .line 123
    .line 124
    invoke-static {v2}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    new-instance v7, Lcom/squareup/moshi/AdapterMethodsFactory$2;

    .line 129
    .line 130
    move-object v3, v8

    .line 131
    aget-object v8, v14, v17

    .line 132
    .line 133
    move-object v5, v12

    .line 134
    array-length v12, v14

    .line 135
    const/4 v13, 0x2

    .line 136
    const/4 v14, 0x1

    .line 137
    move-object/from16 v22, v5

    .line 138
    .line 139
    move-object v5, v9

    .line 140
    move-object/from16 v21, v10

    .line 141
    .line 142
    move-object/from16 v10, p1

    .line 143
    .line 144
    move-object v9, v2

    .line 145
    move/from16 v2, v17

    .line 146
    .line 147
    invoke-direct/range {v7 .. v14}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;-><init>(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/Object;Ljava/lang/reflect/Method;IIZ)V

    .line 148
    .line 149
    .line 150
    move/from16 v23, v4

    .line 151
    .line 152
    move-object v2, v15

    .line 153
    move-object/from16 v4, v22

    .line 154
    .line 155
    goto :goto_8

    .line 156
    :cond_3
    move-object/from16 v19, v2

    .line 157
    .line 158
    move-object/from16 v20, v3

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :goto_4
    array-length v8, v14

    .line 162
    if-ne v8, v2, :cond_7

    .line 163
    .line 164
    move-object/from16 v8, v22

    .line 165
    .line 166
    if-eq v7, v8, :cond_7

    .line 167
    .line 168
    sget-object v9, Lax/b;->a:Ljava/util/Set;

    .line 169
    .line 170
    invoke-interface {v11}, Ljava/lang/reflect/AnnotatedElement;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 171
    .line 172
    .line 173
    move-result-object v9

    .line 174
    invoke-static {v9}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 175
    .line 176
    .line 177
    move-result-object v17

    .line 178
    aget-object v9, v16, v18

    .line 179
    .line 180
    invoke-static {v9}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 181
    .line 182
    .line 183
    move-result-object v9

    .line 184
    aget-object v10, v16, v18

    .line 185
    .line 186
    array-length v12, v10

    .line 187
    move/from16 v13, v18

    .line 188
    .line 189
    :goto_5
    if-ge v13, v12, :cond_5

    .line 190
    .line 191
    aget-object v16, v10, v13

    .line 192
    .line 193
    invoke-interface/range {v16 .. v16}, Ljava/lang/annotation/Annotation;->annotationType()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    move-result-object v16

    .line 197
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    invoke-virtual {v2, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    if-eqz v2, :cond_4

    .line 206
    .line 207
    const/4 v13, 0x1

    .line 208
    :goto_6
    move-object v2, v15

    .line 209
    move-object v15, v7

    .line 210
    goto :goto_7

    .line 211
    :cond_4
    add-int/lit8 v13, v13, 0x1

    .line 212
    .line 213
    const/4 v2, 0x1

    .line 214
    goto :goto_5

    .line 215
    :cond_5
    move/from16 v13, v18

    .line 216
    .line 217
    goto :goto_6

    .line 218
    :goto_7
    new-instance v7, Lcom/squareup/moshi/AdapterMethodsFactory$3;

    .line 219
    .line 220
    move-object v10, v8

    .line 221
    aget-object v8, v14, v18

    .line 222
    .line 223
    array-length v12, v14

    .line 224
    move-object/from16 v16, v9

    .line 225
    .line 226
    move/from16 v23, v4

    .line 227
    .line 228
    move-object v4, v10

    .line 229
    move-object/from16 v10, p1

    .line 230
    .line 231
    invoke-direct/range {v7 .. v17}, Lcom/squareup/moshi/AdapterMethodsFactory$3;-><init>(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/Object;Ljava/lang/reflect/Method;IZ[Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/util/Set;)V

    .line 232
    .line 233
    .line 234
    :goto_8
    iget-object v8, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a:Ljava/lang/reflect/Type;

    .line 235
    .line 236
    iget-object v9, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b:Ljava/util/Set;

    .line 237
    .line 238
    invoke-static {v0, v8, v9}, Lcom/squareup/moshi/AdapterMethodsFactory;->b(Ljava/util/ArrayList;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 239
    .line 240
    .line 241
    move-result-object v8

    .line 242
    if-nez v8, :cond_6

    .line 243
    .line 244
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-object/from16 v7, v21

    .line 248
    .line 249
    goto :goto_9

    .line 250
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 251
    .line 252
    new-instance v1, Ljava/lang/StringBuilder;

    .line 253
    .line 254
    const-string v2, "Conflicting @ToJson methods:\n    "

    .line 255
    .line 256
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    iget-object v2, v8, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 260
    .line 261
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 262
    .line 263
    .line 264
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    iget-object v2, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 268
    .line 269
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    throw v0

    .line 280
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 281
    .line 282
    new-instance v1, Ljava/lang/StringBuilder;

    .line 283
    .line 284
    move-object/from16 v7, v21

    .line 285
    .line 286
    invoke-direct {v1, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 290
    .line 291
    .line 292
    const-string v2, ".\n@ToJson method signatures may have one of the following structures:\n    <any access modifier> void toJson(JsonWriter writer, T value) throws <any>;\n    <any access modifier> void toJson(JsonWriter writer, T value, JsonAdapter<any> delegate, <any more delegates>) throws <any>;\n    <any access modifier> R toJson(T value) throws <any>;\n"

    .line 293
    .line 294
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 295
    .line 296
    .line 297
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    throw v0

    .line 305
    :cond_8
    move-object/from16 v19, v2

    .line 306
    .line 307
    move-object/from16 v20, v3

    .line 308
    .line 309
    move/from16 v23, v4

    .line 310
    .line 311
    move-object v3, v8

    .line 312
    move-object v5, v9

    .line 313
    move-object v7, v10

    .line 314
    move-object v4, v12

    .line 315
    move-object v2, v15

    .line 316
    const/16 v18, 0x0

    .line 317
    .line 318
    :goto_9
    const-class v8, Lcom/squareup/moshi/FromJson;

    .line 319
    .line 320
    invoke-virtual {v11, v8}, Ljava/lang/reflect/AccessibleObject;->isAnnotationPresent(Ljava/lang/Class;)Z

    .line 321
    .line 322
    .line 323
    move-result v8

    .line 324
    if-eqz v8, :cond_11

    .line 325
    .line 326
    const/4 v8, 0x1

    .line 327
    invoke-virtual {v11, v8}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getGenericReturnType()Ljava/lang/reflect/Type;

    .line 331
    .line 332
    .line 333
    move-result-object v9

    .line 334
    sget-object v10, Lax/b;->a:Ljava/util/Set;

    .line 335
    .line 336
    invoke-interface {v11}, Ljava/lang/reflect/AnnotatedElement;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 337
    .line 338
    .line 339
    move-result-object v10

    .line 340
    invoke-static {v10}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 341
    .line 342
    .line 343
    move-result-object v10

    .line 344
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    .line 345
    .line 346
    .line 347
    move-result-object v14

    .line 348
    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    .line 349
    .line 350
    .line 351
    move-result-object v12

    .line 352
    array-length v13, v14

    .line 353
    if-lt v13, v8, :cond_c

    .line 354
    .line 355
    aget-object v8, v14, v18

    .line 356
    .line 357
    const-class v13, Lcom/squareup/moshi/JsonReader;

    .line 358
    .line 359
    if-ne v8, v13, :cond_c

    .line 360
    .line 361
    if-eq v9, v4, :cond_c

    .line 362
    .line 363
    array-length v8, v14

    .line 364
    const/4 v13, 0x1

    .line 365
    :goto_a
    if-ge v13, v8, :cond_b

    .line 366
    .line 367
    aget-object v15, v14, v13

    .line 368
    .line 369
    move/from16 v21, v6

    .line 370
    .line 371
    instance-of v6, v15, Ljava/lang/reflect/ParameterizedType;

    .line 372
    .line 373
    if-nez v6, :cond_9

    .line 374
    .line 375
    goto :goto_b

    .line 376
    :cond_9
    check-cast v15, Ljava/lang/reflect/ParameterizedType;

    .line 377
    .line 378
    invoke-interface {v15}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    .line 379
    .line 380
    .line 381
    move-result-object v6

    .line 382
    if-eq v6, v3, :cond_a

    .line 383
    .line 384
    :goto_b
    move-object v8, v9

    .line 385
    move-object v9, v10

    .line 386
    goto :goto_c

    .line 387
    :cond_a
    add-int/lit8 v13, v13, 0x1

    .line 388
    .line 389
    move/from16 v6, v21

    .line 390
    .line 391
    goto :goto_a

    .line 392
    :cond_b
    move/from16 v21, v6

    .line 393
    .line 394
    new-instance v7, Lcom/squareup/moshi/AdapterMethodsFactory$4;

    .line 395
    .line 396
    array-length v12, v14

    .line 397
    const/4 v13, 0x1

    .line 398
    const/4 v14, 0x1

    .line 399
    move-object v8, v9

    .line 400
    move-object v9, v10

    .line 401
    move-object/from16 v10, p1

    .line 402
    .line 403
    invoke-direct/range {v7 .. v14}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;-><init>(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/Object;Ljava/lang/reflect/Method;IIZ)V

    .line 404
    .line 405
    .line 406
    goto :goto_f

    .line 407
    :cond_c
    move/from16 v21, v6

    .line 408
    .line 409
    goto :goto_b

    .line 410
    :goto_c
    array-length v3, v14

    .line 411
    const/4 v6, 0x1

    .line 412
    if-ne v3, v6, :cond_10

    .line 413
    .line 414
    if-eq v8, v4, :cond_10

    .line 415
    .line 416
    aget-object v3, v12, v18

    .line 417
    .line 418
    invoke-static {v3}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 419
    .line 420
    .line 421
    move-result-object v16

    .line 422
    aget-object v3, v12, v18

    .line 423
    .line 424
    array-length v4, v3

    .line 425
    move/from16 v7, v18

    .line 426
    .line 427
    :goto_d
    if-ge v7, v4, :cond_e

    .line 428
    .line 429
    aget-object v10, v3, v7

    .line 430
    .line 431
    invoke-interface {v10}, Ljava/lang/annotation/Annotation;->annotationType()Ljava/lang/Class;

    .line 432
    .line 433
    .line 434
    move-result-object v10

    .line 435
    invoke-virtual {v10}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object v10

    .line 439
    invoke-virtual {v10, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 440
    .line 441
    .line 442
    move-result v10

    .line 443
    if-eqz v10, :cond_d

    .line 444
    .line 445
    move v13, v6

    .line 446
    goto :goto_e

    .line 447
    :cond_d
    add-int/lit8 v7, v7, 0x1

    .line 448
    .line 449
    goto :goto_d

    .line 450
    :cond_e
    move/from16 v13, v18

    .line 451
    .line 452
    :goto_e
    new-instance v7, Lcom/squareup/moshi/AdapterMethodsFactory$5;

    .line 453
    .line 454
    array-length v12, v14

    .line 455
    move-object v15, v8

    .line 456
    move-object/from16 v17, v9

    .line 457
    .line 458
    move-object/from16 v10, p1

    .line 459
    .line 460
    invoke-direct/range {v7 .. v17}, Lcom/squareup/moshi/AdapterMethodsFactory$5;-><init>(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/Object;Ljava/lang/reflect/Method;IZ[Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/util/Set;)V

    .line 461
    .line 462
    .line 463
    :goto_f
    iget-object v2, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a:Ljava/lang/reflect/Type;

    .line 464
    .line 465
    iget-object v3, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b:Ljava/util/Set;

    .line 466
    .line 467
    invoke-static {v1, v2, v3}, Lcom/squareup/moshi/AdapterMethodsFactory;->b(Ljava/util/ArrayList;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 468
    .line 469
    .line 470
    move-result-object v2

    .line 471
    if-nez v2, :cond_f

    .line 472
    .line 473
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 474
    .line 475
    .line 476
    goto :goto_10

    .line 477
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 478
    .line 479
    new-instance v1, Ljava/lang/StringBuilder;

    .line 480
    .line 481
    const-string v3, "Conflicting @FromJson methods:\n    "

    .line 482
    .line 483
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    iget-object v2, v2, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 487
    .line 488
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 489
    .line 490
    .line 491
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 492
    .line 493
    .line 494
    iget-object v2, v7, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 495
    .line 496
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 497
    .line 498
    .line 499
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    throw v0

    .line 507
    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 508
    .line 509
    new-instance v1, Ljava/lang/StringBuilder;

    .line 510
    .line 511
    invoke-direct {v1, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 515
    .line 516
    .line 517
    const-string v2, ".\n@FromJson method signatures may have one of the following structures:\n    <any access modifier> R fromJson(JsonReader jsonReader) throws <any>;\n    <any access modifier> R fromJson(JsonReader jsonReader, JsonAdapter<any> delegate, <any more delegates>) throws <any>;\n    <any access modifier> R fromJson(T value) throws <any>;\n"

    .line 518
    .line 519
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 520
    .line 521
    .line 522
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 523
    .line 524
    .line 525
    move-result-object v1

    .line 526
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    throw v0

    .line 530
    :cond_11
    move/from16 v21, v6

    .line 531
    .line 532
    :goto_10
    add-int/lit8 v6, v21, 0x1

    .line 533
    .line 534
    move-object/from16 v2, v19

    .line 535
    .line 536
    move-object/from16 v3, v20

    .line 537
    .line 538
    move/from16 v4, v23

    .line 539
    .line 540
    goto/16 :goto_1

    .line 541
    .line 542
    :cond_12
    move-object/from16 v19, v2

    .line 543
    .line 544
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 545
    .line 546
    .line 547
    move-result-object v2

    .line 548
    goto/16 :goto_0

    .line 549
    .line 550
    :cond_13
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 551
    .line 552
    .line 553
    move-result v2

    .line 554
    if-eqz v2, :cond_15

    .line 555
    .line 556
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 557
    .line 558
    .line 559
    move-result v2

    .line 560
    if-nez v2, :cond_14

    .line 561
    .line 562
    goto :goto_11

    .line 563
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 564
    .line 565
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 566
    .line 567
    .line 568
    move-result-object v1

    .line 569
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 570
    .line 571
    .line 572
    move-result-object v1

    .line 573
    const-string v2, "Expected at least one @ToJson or @FromJson method on "

    .line 574
    .line 575
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 576
    .line 577
    .line 578
    move-result-object v1

    .line 579
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 580
    .line 581
    .line 582
    throw v0

    .line 583
    :cond_15
    :goto_11
    new-instance v2, Lcom/squareup/moshi/AdapterMethodsFactory;

    .line 584
    .line 585
    invoke-direct {v2, v0, v1}, Lcom/squareup/moshi/AdapterMethodsFactory;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 586
    .line 587
    .line 588
    move-object/from16 v0, p0

    .line 589
    .line 590
    invoke-virtual {v0, v2}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 591
    .line 592
    .line 593
    return-void
.end method
