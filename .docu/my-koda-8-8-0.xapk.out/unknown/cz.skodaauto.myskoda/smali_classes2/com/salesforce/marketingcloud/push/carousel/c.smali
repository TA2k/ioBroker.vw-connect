.class public final Lcom/salesforce/marketingcloud/push/carousel/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lorg/json/JSONArray;)Ljava/util/List;
    .locals 21
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/json/JSONArray;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/carousel/a$a;",
            ">;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-static {v2, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v3, Ljava/util/ArrayList;

    .line 18
    .line 19
    const/16 v4, 0xa

    .line 20
    .line 21
    invoke-static {v1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    :goto_0
    move-object v5, v1

    .line 33
    check-cast v5, Lgy0/i;

    .line 34
    .line 35
    iget-boolean v5, v5, Lgy0/i;->f:Z

    .line 36
    .line 37
    const-class v6, Ljava/lang/String;

    .line 38
    .line 39
    sget-object v7, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 40
    .line 41
    sget-object v8, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 42
    .line 43
    sget-object v9, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 44
    .line 45
    sget-object v10, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 46
    .line 47
    const-class v11, Lorg/json/JSONObject;

    .line 48
    .line 49
    const-string v12, "null cannot be cast to non-null type org.json.JSONObject"

    .line 50
    .line 51
    if-eqz v5, :cond_9

    .line 52
    .line 53
    move-object v5, v1

    .line 54
    check-cast v5, Lmx0/w;

    .line 55
    .line 56
    invoke-virtual {v5}, Lmx0/w;->nextInt()I

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    sget-object v13, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 61
    .line 62
    invoke-virtual {v13, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 63
    .line 64
    .line 65
    move-result-object v14

    .line 66
    invoke-virtual {v13, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 67
    .line 68
    .line 69
    move-result-object v11

    .line 70
    invoke-static {v14, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v11

    .line 74
    if-eqz v11, :cond_1

    .line 75
    .line 76
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    if-eqz v5, :cond_0

    .line 81
    .line 82
    goto/16 :goto_1

    .line 83
    .line 84
    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    .line 85
    .line 86
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v0

    .line 90
    :cond_1
    invoke-virtual {v13, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 91
    .line 92
    .line 93
    move-result-object v10

    .line 94
    invoke-static {v14, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v10

    .line 98
    if-eqz v10, :cond_2

    .line 99
    .line 100
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getInt(I)I

    .line 101
    .line 102
    .line 103
    move-result v5

    .line 104
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    check-cast v5, Lorg/json/JSONObject;

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_2
    invoke-virtual {v13, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    invoke-static {v14, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v9

    .line 119
    if-eqz v9, :cond_3

    .line 120
    .line 121
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getDouble(I)D

    .line 122
    .line 123
    .line 124
    move-result-wide v5

    .line 125
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    check-cast v5, Lorg/json/JSONObject;

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_3
    invoke-virtual {v13, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 133
    .line 134
    .line 135
    move-result-object v8

    .line 136
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    if-eqz v8, :cond_4

    .line 141
    .line 142
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getLong(I)J

    .line 143
    .line 144
    .line 145
    move-result-wide v5

    .line 146
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 147
    .line 148
    .line 149
    move-result-object v5

    .line 150
    check-cast v5, Lorg/json/JSONObject;

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_4
    invoke-virtual {v13, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    invoke-static {v14, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v7

    .line 161
    if-eqz v7, :cond_5

    .line 162
    .line 163
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getBoolean(I)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    check-cast v5, Lorg/json/JSONObject;

    .line 172
    .line 173
    goto :goto_1

    .line 174
    :cond_5
    invoke-virtual {v13, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    invoke-static {v14, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v6

    .line 182
    if-eqz v6, :cond_7

    .line 183
    .line 184
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    if-eqz v5, :cond_6

    .line 189
    .line 190
    check-cast v5, Lorg/json/JSONObject;

    .line 191
    .line 192
    goto :goto_1

    .line 193
    :cond_6
    new-instance v0, Ljava/lang/NullPointerException;

    .line 194
    .line 195
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw v0

    .line 199
    :cond_7
    invoke-virtual {v0, v5}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v5

    .line 203
    if-eqz v5, :cond_8

    .line 204
    .line 205
    check-cast v5, Lorg/json/JSONObject;

    .line 206
    .line 207
    :goto_1
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    goto/16 :goto_0

    .line 211
    .line 212
    :cond_8
    new-instance v0, Ljava/lang/NullPointerException;

    .line 213
    .line 214
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    throw v0

    .line 218
    :cond_9
    new-instance v0, Ljava/util/ArrayList;

    .line 219
    .line 220
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 228
    .line 229
    .line 230
    move-result v3

    .line 231
    if-eqz v3, :cond_1c

    .line 232
    .line 233
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    check-cast v3, Lorg/json/JSONObject;

    .line 238
    .line 239
    const-string v5, "optString(...)"

    .line 240
    .line 241
    const-string v13, "id"

    .line 242
    .line 243
    invoke-static {v3, v13, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v15

    .line 247
    if-eqz v15, :cond_1b

    .line 248
    .line 249
    const-string v5, "md"

    .line 250
    .line 251
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 252
    .line 253
    .line 254
    move-result-object v13

    .line 255
    if-eqz v13, :cond_1a

    .line 256
    .line 257
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/b;->f:Lcom/salesforce/marketingcloud/push/data/b$a;

    .line 258
    .line 259
    invoke-virtual {v14, v13}, Lcom/salesforce/marketingcloud/push/data/b$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/b;

    .line 260
    .line 261
    .line 262
    move-result-object v16

    .line 263
    if-eqz v16, :cond_1a

    .line 264
    .line 265
    const-string v5, "ti"

    .line 266
    .line 267
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    const/4 v13, 0x0

    .line 272
    if-eqz v5, :cond_a

    .line 273
    .line 274
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    .line 275
    .line 276
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/c;

    .line 277
    .line 278
    .line 279
    move-result-object v5

    .line 280
    move-object/from16 v17, v5

    .line 281
    .line 282
    goto :goto_3

    .line 283
    :cond_a
    move-object/from16 v17, v13

    .line 284
    .line 285
    :goto_3
    const-string v5, "sti"

    .line 286
    .line 287
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    if-eqz v5, :cond_b

    .line 292
    .line 293
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    .line 294
    .line 295
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/c;

    .line 296
    .line 297
    .line 298
    move-result-object v5

    .line 299
    move-object/from16 v18, v5

    .line 300
    .line 301
    goto :goto_4

    .line 302
    :cond_b
    move-object/from16 v18, v13

    .line 303
    .line 304
    :goto_4
    const-string v5, "s"

    .line 305
    .line 306
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 307
    .line 308
    .line 309
    move-result-object v5

    .line 310
    if-eqz v5, :cond_c

    .line 311
    .line 312
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 313
    .line 314
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    .line 315
    .line 316
    .line 317
    move-result-object v5

    .line 318
    move-object/from16 v19, v5

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_c
    move-object/from16 v19, v13

    .line 322
    .line 323
    :goto_5
    const-string v5, "ac"

    .line 324
    .line 325
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 326
    .line 327
    .line 328
    move-result-object v3

    .line 329
    if-eqz v3, :cond_19

    .line 330
    .line 331
    invoke-virtual {v3}, Lorg/json/JSONArray;->length()I

    .line 332
    .line 333
    .line 334
    move-result v5

    .line 335
    invoke-static {v2, v5}, Lkp/r9;->m(II)Lgy0/j;

    .line 336
    .line 337
    .line 338
    move-result-object v5

    .line 339
    new-instance v13, Ljava/util/ArrayList;

    .line 340
    .line 341
    invoke-static {v5, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 342
    .line 343
    .line 344
    move-result v14

    .line 345
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {v5}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 349
    .line 350
    .line 351
    move-result-object v5

    .line 352
    :goto_6
    move-object v14, v5

    .line 353
    check-cast v14, Lgy0/i;

    .line 354
    .line 355
    iget-boolean v14, v14, Lgy0/i;->f:Z

    .line 356
    .line 357
    if-eqz v14, :cond_16

    .line 358
    .line 359
    move-object v14, v5

    .line 360
    check-cast v14, Lmx0/w;

    .line 361
    .line 362
    invoke-virtual {v14}, Lmx0/w;->nextInt()I

    .line 363
    .line 364
    .line 365
    move-result v14

    .line 366
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 367
    .line 368
    invoke-virtual {v2, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 369
    .line 370
    .line 371
    move-result-object v4

    .line 372
    move-object/from16 p0, v1

    .line 373
    .line 374
    invoke-virtual {v2, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 379
    .line 380
    .line 381
    move-result v1

    .line 382
    if-eqz v1, :cond_e

    .line 383
    .line 384
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 385
    .line 386
    .line 387
    move-result-object v1

    .line 388
    if-eqz v1, :cond_d

    .line 389
    .line 390
    goto/16 :goto_7

    .line 391
    .line 392
    :cond_d
    new-instance v0, Ljava/lang/NullPointerException;

    .line 393
    .line 394
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    throw v0

    .line 398
    :cond_e
    invoke-virtual {v2, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    if-eqz v1, :cond_f

    .line 407
    .line 408
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getInt(I)I

    .line 409
    .line 410
    .line 411
    move-result v1

    .line 412
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    check-cast v1, Lorg/json/JSONObject;

    .line 417
    .line 418
    goto :goto_7

    .line 419
    :cond_f
    invoke-virtual {v2, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 420
    .line 421
    .line 422
    move-result-object v1

    .line 423
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    move-result v1

    .line 427
    if-eqz v1, :cond_10

    .line 428
    .line 429
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getDouble(I)D

    .line 430
    .line 431
    .line 432
    move-result-wide v1

    .line 433
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    check-cast v1, Lorg/json/JSONObject;

    .line 438
    .line 439
    goto :goto_7

    .line 440
    :cond_10
    invoke-virtual {v2, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 445
    .line 446
    .line 447
    move-result v1

    .line 448
    if-eqz v1, :cond_11

    .line 449
    .line 450
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getLong(I)J

    .line 451
    .line 452
    .line 453
    move-result-wide v1

    .line 454
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    check-cast v1, Lorg/json/JSONObject;

    .line 459
    .line 460
    goto :goto_7

    .line 461
    :cond_11
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 462
    .line 463
    .line 464
    move-result-object v1

    .line 465
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 466
    .line 467
    .line 468
    move-result v1

    .line 469
    if-eqz v1, :cond_12

    .line 470
    .line 471
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getBoolean(I)Z

    .line 472
    .line 473
    .line 474
    move-result v1

    .line 475
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 476
    .line 477
    .line 478
    move-result-object v1

    .line 479
    check-cast v1, Lorg/json/JSONObject;

    .line 480
    .line 481
    goto :goto_7

    .line 482
    :cond_12
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 483
    .line 484
    .line 485
    move-result-object v1

    .line 486
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 487
    .line 488
    .line 489
    move-result v1

    .line 490
    if-eqz v1, :cond_14

    .line 491
    .line 492
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object v1

    .line 496
    if-eqz v1, :cond_13

    .line 497
    .line 498
    check-cast v1, Lorg/json/JSONObject;

    .line 499
    .line 500
    goto :goto_7

    .line 501
    :cond_13
    new-instance v0, Ljava/lang/NullPointerException;

    .line 502
    .line 503
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    throw v0

    .line 507
    :cond_14
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v1

    .line 511
    if-eqz v1, :cond_15

    .line 512
    .line 513
    check-cast v1, Lorg/json/JSONObject;

    .line 514
    .line 515
    :goto_7
    invoke-virtual {v13, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    move-object/from16 v1, p0

    .line 519
    .line 520
    const/4 v2, 0x0

    .line 521
    const/16 v4, 0xa

    .line 522
    .line 523
    goto/16 :goto_6

    .line 524
    .line 525
    :cond_15
    new-instance v0, Ljava/lang/NullPointerException;

    .line 526
    .line 527
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 528
    .line 529
    .line 530
    throw v0

    .line 531
    :cond_16
    move-object/from16 p0, v1

    .line 532
    .line 533
    new-instance v1, Ljava/util/ArrayList;

    .line 534
    .line 535
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 536
    .line 537
    .line 538
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 539
    .line 540
    .line 541
    move-result-object v2

    .line 542
    :cond_17
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 543
    .line 544
    .line 545
    move-result v3

    .line 546
    if-eqz v3, :cond_18

    .line 547
    .line 548
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    move-result-object v3

    .line 552
    check-cast v3, Lorg/json/JSONObject;

    .line 553
    .line 554
    sget-object v4, Lcom/salesforce/marketingcloud/push/data/a;->c:Lcom/salesforce/marketingcloud/push/data/a$b;

    .line 555
    .line 556
    invoke-virtual {v4, v3}, Lcom/salesforce/marketingcloud/push/data/a$b;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/a;

    .line 557
    .line 558
    .line 559
    move-result-object v3

    .line 560
    if-eqz v3, :cond_17

    .line 561
    .line 562
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 563
    .line 564
    .line 565
    goto :goto_8

    .line 566
    :cond_18
    move-object/from16 v20, v1

    .line 567
    .line 568
    goto :goto_9

    .line 569
    :cond_19
    move-object/from16 p0, v1

    .line 570
    .line 571
    move-object/from16 v20, v13

    .line 572
    .line 573
    :goto_9
    new-instance v14, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 574
    .line 575
    invoke-direct/range {v14 .. v20}, Lcom/salesforce/marketingcloud/push/carousel/a$a;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/b;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/c;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

    .line 576
    .line 577
    .line 578
    invoke-virtual {v0, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 579
    .line 580
    .line 581
    move-object/from16 v1, p0

    .line 582
    .line 583
    const/4 v2, 0x0

    .line 584
    const/16 v4, 0xa

    .line 585
    .line 586
    goto/16 :goto_2

    .line 587
    .line 588
    :cond_1a
    new-instance v0, Lcom/salesforce/marketingcloud/push/e;

    .line 589
    .line 590
    invoke-direct {v0, v5}, Lcom/salesforce/marketingcloud/push/e;-><init>(Ljava/lang/String;)V

    .line 591
    .line 592
    .line 593
    throw v0

    .line 594
    :cond_1b
    new-instance v0, Lcom/salesforce/marketingcloud/push/e;

    .line 595
    .line 596
    invoke-direct {v0, v13}, Lcom/salesforce/marketingcloud/push/e;-><init>(Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    throw v0

    .line 600
    :cond_1c
    return-object v0
.end method
