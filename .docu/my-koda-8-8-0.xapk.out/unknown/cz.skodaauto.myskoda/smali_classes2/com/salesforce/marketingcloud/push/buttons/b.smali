.class public final Lcom/salesforce/marketingcloud/push/buttons/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lorg/json/JSONArray;)Ljava/util/List;
    .locals 20
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/json/JSONArray;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/push/buttons/a$c;",
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
    if-eqz v3, :cond_1a

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
    const-string v5, "id"

    .line 240
    .line 241
    const-string v13, "optString(...)"

    .line 242
    .line 243
    invoke-static {v3, v5, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v15

    .line 247
    if-eqz v15, :cond_19

    .line 248
    .line 249
    const-string v5, "ic"

    .line 250
    .line 251
    invoke-static {v3, v5, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->o(Lorg/json/JSONObject;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object v17

    .line 255
    const-string v5, "ti"

    .line 256
    .line 257
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    const/4 v13, 0x0

    .line 262
    if-eqz v5, :cond_a

    .line 263
    .line 264
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/c;->e:Lcom/salesforce/marketingcloud/push/data/c$a;

    .line 265
    .line 266
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/push/data/c$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/c;

    .line 267
    .line 268
    .line 269
    move-result-object v5

    .line 270
    move-object/from16 v16, v5

    .line 271
    .line 272
    goto :goto_3

    .line 273
    :cond_a
    move-object/from16 v16, v13

    .line 274
    .line 275
    :goto_3
    const-string v5, "s"

    .line 276
    .line 277
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 278
    .line 279
    .line 280
    move-result-object v5

    .line 281
    if-eqz v5, :cond_b

    .line 282
    .line 283
    sget-object v14, Lcom/salesforce/marketingcloud/push/data/Style;->a:Lcom/salesforce/marketingcloud/push/data/Style$a;

    .line 284
    .line 285
    invoke-virtual {v14, v5}, Lcom/salesforce/marketingcloud/push/data/Style$a;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/Style$b;

    .line 286
    .line 287
    .line 288
    move-result-object v5

    .line 289
    move-object/from16 v18, v5

    .line 290
    .line 291
    goto :goto_4

    .line 292
    :cond_b
    move-object/from16 v18, v13

    .line 293
    .line 294
    :goto_4
    const-string v5, "ac"

    .line 295
    .line 296
    invoke-virtual {v3, v5}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 297
    .line 298
    .line 299
    move-result-object v3

    .line 300
    if-eqz v3, :cond_18

    .line 301
    .line 302
    invoke-virtual {v3}, Lorg/json/JSONArray;->length()I

    .line 303
    .line 304
    .line 305
    move-result v5

    .line 306
    invoke-static {v2, v5}, Lkp/r9;->m(II)Lgy0/j;

    .line 307
    .line 308
    .line 309
    move-result-object v5

    .line 310
    new-instance v13, Ljava/util/ArrayList;

    .line 311
    .line 312
    invoke-static {v5, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 313
    .line 314
    .line 315
    move-result v14

    .line 316
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 317
    .line 318
    .line 319
    invoke-virtual {v5}, Lgy0/h;->iterator()Ljava/util/Iterator;

    .line 320
    .line 321
    .line 322
    move-result-object v5

    .line 323
    :goto_5
    move-object v14, v5

    .line 324
    check-cast v14, Lgy0/i;

    .line 325
    .line 326
    iget-boolean v14, v14, Lgy0/i;->f:Z

    .line 327
    .line 328
    if-eqz v14, :cond_15

    .line 329
    .line 330
    move-object v14, v5

    .line 331
    check-cast v14, Lmx0/w;

    .line 332
    .line 333
    invoke-virtual {v14}, Lmx0/w;->nextInt()I

    .line 334
    .line 335
    .line 336
    move-result v14

    .line 337
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 338
    .line 339
    invoke-virtual {v2, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 340
    .line 341
    .line 342
    move-result-object v4

    .line 343
    move-object/from16 p0, v1

    .line 344
    .line 345
    invoke-virtual {v2, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    if-eqz v1, :cond_d

    .line 354
    .line 355
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 356
    .line 357
    .line 358
    move-result-object v1

    .line 359
    if-eqz v1, :cond_c

    .line 360
    .line 361
    goto/16 :goto_6

    .line 362
    .line 363
    :cond_c
    new-instance v0, Ljava/lang/NullPointerException;

    .line 364
    .line 365
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    throw v0

    .line 369
    :cond_d
    invoke-virtual {v2, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    move-result v1

    .line 377
    if-eqz v1, :cond_e

    .line 378
    .line 379
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getInt(I)I

    .line 380
    .line 381
    .line 382
    move-result v1

    .line 383
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    check-cast v1, Lorg/json/JSONObject;

    .line 388
    .line 389
    goto :goto_6

    .line 390
    :cond_e
    invoke-virtual {v2, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 391
    .line 392
    .line 393
    move-result-object v1

    .line 394
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 395
    .line 396
    .line 397
    move-result v1

    .line 398
    if-eqz v1, :cond_f

    .line 399
    .line 400
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getDouble(I)D

    .line 401
    .line 402
    .line 403
    move-result-wide v1

    .line 404
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    check-cast v1, Lorg/json/JSONObject;

    .line 409
    .line 410
    goto :goto_6

    .line 411
    :cond_f
    invoke-virtual {v2, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 412
    .line 413
    .line 414
    move-result-object v1

    .line 415
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    move-result v1

    .line 419
    if-eqz v1, :cond_10

    .line 420
    .line 421
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getLong(I)J

    .line 422
    .line 423
    .line 424
    move-result-wide v1

    .line 425
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 426
    .line 427
    .line 428
    move-result-object v1

    .line 429
    check-cast v1, Lorg/json/JSONObject;

    .line 430
    .line 431
    goto :goto_6

    .line 432
    :cond_10
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    move-result v1

    .line 440
    if-eqz v1, :cond_11

    .line 441
    .line 442
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getBoolean(I)Z

    .line 443
    .line 444
    .line 445
    move-result v1

    .line 446
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    check-cast v1, Lorg/json/JSONObject;

    .line 451
    .line 452
    goto :goto_6

    .line 453
    :cond_11
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 458
    .line 459
    .line 460
    move-result v1

    .line 461
    if-eqz v1, :cond_13

    .line 462
    .line 463
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v1

    .line 467
    if-eqz v1, :cond_12

    .line 468
    .line 469
    check-cast v1, Lorg/json/JSONObject;

    .line 470
    .line 471
    goto :goto_6

    .line 472
    :cond_12
    new-instance v0, Ljava/lang/NullPointerException;

    .line 473
    .line 474
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 475
    .line 476
    .line 477
    throw v0

    .line 478
    :cond_13
    invoke-virtual {v3, v14}, Lorg/json/JSONArray;->get(I)Ljava/lang/Object;

    .line 479
    .line 480
    .line 481
    move-result-object v1

    .line 482
    if-eqz v1, :cond_14

    .line 483
    .line 484
    check-cast v1, Lorg/json/JSONObject;

    .line 485
    .line 486
    :goto_6
    invoke-virtual {v13, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 487
    .line 488
    .line 489
    move-object/from16 v1, p0

    .line 490
    .line 491
    const/4 v2, 0x0

    .line 492
    const/16 v4, 0xa

    .line 493
    .line 494
    goto/16 :goto_5

    .line 495
    .line 496
    :cond_14
    new-instance v0, Ljava/lang/NullPointerException;

    .line 497
    .line 498
    invoke-direct {v0, v12}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 499
    .line 500
    .line 501
    throw v0

    .line 502
    :cond_15
    move-object/from16 p0, v1

    .line 503
    .line 504
    new-instance v1, Ljava/util/ArrayList;

    .line 505
    .line 506
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 507
    .line 508
    .line 509
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 510
    .line 511
    .line 512
    move-result-object v2

    .line 513
    :cond_16
    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 514
    .line 515
    .line 516
    move-result v3

    .line 517
    if-eqz v3, :cond_17

    .line 518
    .line 519
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 520
    .line 521
    .line 522
    move-result-object v3

    .line 523
    check-cast v3, Lorg/json/JSONObject;

    .line 524
    .line 525
    sget-object v4, Lcom/salesforce/marketingcloud/push/data/a;->c:Lcom/salesforce/marketingcloud/push/data/a$b;

    .line 526
    .line 527
    invoke-virtual {v4, v3}, Lcom/salesforce/marketingcloud/push/data/a$b;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/push/data/a;

    .line 528
    .line 529
    .line 530
    move-result-object v3

    .line 531
    if-eqz v3, :cond_16

    .line 532
    .line 533
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    goto :goto_7

    .line 537
    :cond_17
    move-object/from16 v19, v1

    .line 538
    .line 539
    goto :goto_8

    .line 540
    :cond_18
    move-object/from16 p0, v1

    .line 541
    .line 542
    move-object/from16 v19, v13

    .line 543
    .line 544
    :goto_8
    new-instance v14, Lcom/salesforce/marketingcloud/push/buttons/a$c;

    .line 545
    .line 546
    invoke-direct/range {v14 .. v19}, Lcom/salesforce/marketingcloud/push/buttons/a$c;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/c;Ljava/lang/String;Lcom/salesforce/marketingcloud/push/data/Style;Ljava/util/List;)V

    .line 547
    .line 548
    .line 549
    invoke-virtual {v0, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 550
    .line 551
    .line 552
    move-object/from16 v1, p0

    .line 553
    .line 554
    const/4 v2, 0x0

    .line 555
    const/16 v4, 0xa

    .line 556
    .line 557
    goto/16 :goto_2

    .line 558
    .line 559
    :cond_19
    new-instance v0, Lcom/salesforce/marketingcloud/push/e;

    .line 560
    .line 561
    invoke-direct {v0, v5}, Lcom/salesforce/marketingcloud/push/e;-><init>(Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    throw v0

    .line 565
    :cond_1a
    return-object v0
.end method
