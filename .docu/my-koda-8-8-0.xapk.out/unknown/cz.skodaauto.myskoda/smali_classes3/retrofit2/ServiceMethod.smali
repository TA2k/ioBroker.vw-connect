.class abstract Lretrofit2/ServiceMethod;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static b(Lretrofit2/Retrofit;Ljava/lang/Class;Ljava/lang/reflect/Method;)Lretrofit2/HttpServiceMethod;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    new-instance v2, Lretrofit2/RequestFactory$Builder;

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    invoke-direct {v2, v0, v3, v1}, Lretrofit2/RequestFactory$Builder;-><init>(Lretrofit2/Retrofit;Ljava/lang/Class;Ljava/lang/reflect/Method;)V

    .line 10
    .line 11
    .line 12
    iget-object v3, v2, Lretrofit2/RequestFactory$Builder;->d:[Ljava/lang/annotation/Annotation;

    .line 13
    .line 14
    array-length v4, v3

    .line 15
    const/4 v5, 0x0

    .line 16
    move v6, v5

    .line 17
    :goto_0
    const-string v7, "HEAD"

    .line 18
    .line 19
    const/4 v8, 0x1

    .line 20
    const/4 v9, 0x0

    .line 21
    if-ge v6, v4, :cond_12

    .line 22
    .line 23
    aget-object v10, v3, v6

    .line 24
    .line 25
    instance-of v11, v10, Lretrofit2/http/DELETE;

    .line 26
    .line 27
    if-eqz v11, :cond_0

    .line 28
    .line 29
    check-cast v10, Lretrofit2/http/DELETE;

    .line 30
    .line 31
    invoke-interface {v10}, Lretrofit2/http/DELETE;->value()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    const-string v8, "DELETE"

    .line 36
    .line 37
    invoke-virtual {v2, v8, v7, v5}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 38
    .line 39
    .line 40
    goto/16 :goto_3

    .line 41
    .line 42
    :cond_0
    instance-of v11, v10, Lretrofit2/http/GET;

    .line 43
    .line 44
    if-eqz v11, :cond_1

    .line 45
    .line 46
    check-cast v10, Lretrofit2/http/GET;

    .line 47
    .line 48
    invoke-interface {v10}, Lretrofit2/http/GET;->value()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    const-string v8, "GET"

    .line 53
    .line 54
    invoke-virtual {v2, v8, v7, v5}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_3

    .line 58
    .line 59
    :cond_1
    instance-of v11, v10, Lretrofit2/http/HEAD;

    .line 60
    .line 61
    if-eqz v11, :cond_2

    .line 62
    .line 63
    check-cast v10, Lretrofit2/http/HEAD;

    .line 64
    .line 65
    invoke-interface {v10}, Lretrofit2/http/HEAD;->value()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    invoke-virtual {v2, v7, v8, v5}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 70
    .line 71
    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :cond_2
    instance-of v7, v10, Lretrofit2/http/PATCH;

    .line 75
    .line 76
    if-eqz v7, :cond_3

    .line 77
    .line 78
    check-cast v10, Lretrofit2/http/PATCH;

    .line 79
    .line 80
    invoke-interface {v10}, Lretrofit2/http/PATCH;->value()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    const-string v9, "PATCH"

    .line 85
    .line 86
    invoke-virtual {v2, v9, v7, v8}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 87
    .line 88
    .line 89
    goto/16 :goto_3

    .line 90
    .line 91
    :cond_3
    instance-of v7, v10, Lretrofit2/http/POST;

    .line 92
    .line 93
    if-eqz v7, :cond_4

    .line 94
    .line 95
    check-cast v10, Lretrofit2/http/POST;

    .line 96
    .line 97
    invoke-interface {v10}, Lretrofit2/http/POST;->value()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v7

    .line 101
    const-string v9, "POST"

    .line 102
    .line 103
    invoke-virtual {v2, v9, v7, v8}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 104
    .line 105
    .line 106
    goto/16 :goto_3

    .line 107
    .line 108
    :cond_4
    instance-of v7, v10, Lretrofit2/http/PUT;

    .line 109
    .line 110
    if-eqz v7, :cond_5

    .line 111
    .line 112
    check-cast v10, Lretrofit2/http/PUT;

    .line 113
    .line 114
    invoke-interface {v10}, Lretrofit2/http/PUT;->value()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    const-string v9, "PUT"

    .line 119
    .line 120
    invoke-virtual {v2, v9, v7, v8}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 121
    .line 122
    .line 123
    goto/16 :goto_3

    .line 124
    .line 125
    :cond_5
    instance-of v7, v10, Lretrofit2/http/OPTIONS;

    .line 126
    .line 127
    if-eqz v7, :cond_6

    .line 128
    .line 129
    check-cast v10, Lretrofit2/http/OPTIONS;

    .line 130
    .line 131
    invoke-interface {v10}, Lretrofit2/http/OPTIONS;->value()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    const-string v8, "OPTIONS"

    .line 136
    .line 137
    invoke-virtual {v2, v8, v7, v5}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 138
    .line 139
    .line 140
    goto/16 :goto_3

    .line 141
    .line 142
    :cond_6
    instance-of v7, v10, Lretrofit2/http/HTTP;

    .line 143
    .line 144
    if-eqz v7, :cond_7

    .line 145
    .line 146
    check-cast v10, Lretrofit2/http/HTTP;

    .line 147
    .line 148
    invoke-interface {v10}, Lretrofit2/http/HTTP;->method()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    invoke-interface {v10}, Lretrofit2/http/HTTP;->path()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    invoke-interface {v10}, Lretrofit2/http/HTTP;->hasBody()Z

    .line 157
    .line 158
    .line 159
    move-result v9

    .line 160
    invoke-virtual {v2, v7, v8, v9}, Lretrofit2/RequestFactory$Builder;->b(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 161
    .line 162
    .line 163
    goto/16 :goto_3

    .line 164
    .line 165
    :cond_7
    instance-of v7, v10, Lretrofit2/http/Headers;

    .line 166
    .line 167
    if-eqz v7, :cond_d

    .line 168
    .line 169
    check-cast v10, Lretrofit2/http/Headers;

    .line 170
    .line 171
    invoke-interface {v10}, Lretrofit2/http/Headers;->value()[Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    array-length v11, v7

    .line 176
    if-eqz v11, :cond_c

    .line 177
    .line 178
    invoke-interface {v10}, Lretrofit2/http/Headers;->allowUnsafeNonAsciiValues()Z

    .line 179
    .line 180
    .line 181
    move-result v10

    .line 182
    new-instance v11, Ld01/x;

    .line 183
    .line 184
    invoke-direct {v11, v5, v5}, Ld01/x;-><init>(BI)V

    .line 185
    .line 186
    .line 187
    array-length v12, v7

    .line 188
    move v13, v5

    .line 189
    :goto_1
    if-ge v13, v12, :cond_b

    .line 190
    .line 191
    aget-object v14, v7, v13

    .line 192
    .line 193
    const/16 v15, 0x3a

    .line 194
    .line 195
    invoke-virtual {v14, v15}, Ljava/lang/String;->indexOf(I)I

    .line 196
    .line 197
    .line 198
    move-result v15

    .line 199
    move/from16 p1, v8

    .line 200
    .line 201
    const/4 v8, -0x1

    .line 202
    if-eq v15, v8, :cond_a

    .line 203
    .line 204
    if-eqz v15, :cond_a

    .line 205
    .line 206
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 207
    .line 208
    .line 209
    move-result v8

    .line 210
    add-int/lit8 v8, v8, -0x1

    .line 211
    .line 212
    if-eq v15, v8, :cond_a

    .line 213
    .line 214
    invoke-virtual {v14, v5, v15}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v8

    .line 218
    add-int/lit8 v15, v15, 0x1

    .line 219
    .line 220
    invoke-virtual {v14, v15}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v14

    .line 224
    invoke-virtual {v14}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v14

    .line 228
    const-string v15, "Content-Type"

    .line 229
    .line 230
    invoke-virtual {v15, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 231
    .line 232
    .line 233
    move-result v15

    .line 234
    if-eqz v15, :cond_8

    .line 235
    .line 236
    :try_start_0
    sget-object v8, Ld01/d0;->e:Lly0/n;

    .line 237
    .line 238
    invoke-static {v14}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 239
    .line 240
    .line 241
    move-result-object v8

    .line 242
    iput-object v8, v2, Lretrofit2/RequestFactory$Builder;->u:Ld01/d0;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 243
    .line 244
    goto :goto_2

    .line 245
    :catch_0
    move-exception v0

    .line 246
    const-string v2, "Malformed content type: %s"

    .line 247
    .line 248
    filled-new-array {v14}, [Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v3

    .line 252
    invoke-static {v1, v0, v2, v3}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    throw v0

    .line 257
    :cond_8
    if-eqz v10, :cond_9

    .line 258
    .line 259
    invoke-virtual {v11, v8, v14}, Ld01/x;->h(Ljava/lang/String;Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    goto :goto_2

    .line 263
    :cond_9
    invoke-virtual {v11, v8, v14}, Ld01/x;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    :goto_2
    add-int/lit8 v13, v13, 0x1

    .line 267
    .line 268
    move/from16 v8, p1

    .line 269
    .line 270
    goto :goto_1

    .line 271
    :cond_a
    const-string v0, "@Headers value must be in the form \"Name: Value\". Found: \"%s\""

    .line 272
    .line 273
    filled-new-array {v14}, [Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v2

    .line 277
    invoke-static {v1, v9, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    throw v0

    .line 282
    :cond_b
    invoke-virtual {v11}, Ld01/x;->j()Ld01/y;

    .line 283
    .line 284
    .line 285
    move-result-object v7

    .line 286
    iput-object v7, v2, Lretrofit2/RequestFactory$Builder;->t:Ld01/y;

    .line 287
    .line 288
    goto :goto_3

    .line 289
    :cond_c
    const-string v0, "@Headers annotation is empty."

    .line 290
    .line 291
    new-array v2, v5, [Ljava/lang/Object;

    .line 292
    .line 293
    invoke-static {v1, v9, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    throw v0

    .line 298
    :cond_d
    move/from16 p1, v8

    .line 299
    .line 300
    instance-of v7, v10, Lretrofit2/http/Multipart;

    .line 301
    .line 302
    const-string v8, "Only one encoding annotation is allowed."

    .line 303
    .line 304
    if-eqz v7, :cond_f

    .line 305
    .line 306
    iget-boolean v7, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 307
    .line 308
    if-nez v7, :cond_e

    .line 309
    .line 310
    move/from16 v7, p1

    .line 311
    .line 312
    iput-boolean v7, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 313
    .line 314
    goto :goto_3

    .line 315
    :cond_e
    new-array v0, v5, [Ljava/lang/Object;

    .line 316
    .line 317
    invoke-static {v1, v9, v8, v0}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    throw v0

    .line 322
    :cond_f
    move/from16 v7, p1

    .line 323
    .line 324
    instance-of v10, v10, Lretrofit2/http/FormUrlEncoded;

    .line 325
    .line 326
    if-eqz v10, :cond_11

    .line 327
    .line 328
    iget-boolean v10, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 329
    .line 330
    if-nez v10, :cond_10

    .line 331
    .line 332
    iput-boolean v7, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 333
    .line 334
    goto :goto_3

    .line 335
    :cond_10
    new-array v0, v5, [Ljava/lang/Object;

    .line 336
    .line 337
    invoke-static {v1, v9, v8, v0}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    throw v0

    .line 342
    :cond_11
    :goto_3
    add-int/lit8 v6, v6, 0x1

    .line 343
    .line 344
    goto/16 :goto_0

    .line 345
    .line 346
    :cond_12
    iget-object v4, v2, Lretrofit2/RequestFactory$Builder;->o:Ljava/lang/String;

    .line 347
    .line 348
    if-eqz v4, :cond_80

    .line 349
    .line 350
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->p:Z

    .line 351
    .line 352
    if-nez v4, :cond_15

    .line 353
    .line 354
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 355
    .line 356
    if-nez v4, :cond_14

    .line 357
    .line 358
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 359
    .line 360
    if-nez v4, :cond_13

    .line 361
    .line 362
    goto :goto_4

    .line 363
    :cond_13
    const-string v0, "FormUrlEncoded can only be specified on HTTP methods with request body (e.g., @POST)."

    .line 364
    .line 365
    new-array v2, v5, [Ljava/lang/Object;

    .line 366
    .line 367
    invoke-static {v1, v9, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 368
    .line 369
    .line 370
    move-result-object v0

    .line 371
    throw v0

    .line 372
    :cond_14
    const-string v0, "Multipart can only be specified on HTTP methods with request body (e.g., @POST)."

    .line 373
    .line 374
    new-array v2, v5, [Ljava/lang/Object;

    .line 375
    .line 376
    invoke-static {v1, v9, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    throw v0

    .line 381
    :cond_15
    :goto_4
    iget-object v4, v2, Lretrofit2/RequestFactory$Builder;->e:[[Ljava/lang/annotation/Annotation;

    .line 382
    .line 383
    array-length v6, v4

    .line 384
    new-array v8, v6, [Lretrofit2/ParameterHandler;

    .line 385
    .line 386
    iput-object v8, v2, Lretrofit2/RequestFactory$Builder;->w:[Lretrofit2/ParameterHandler;

    .line 387
    .line 388
    add-int/lit8 v8, v6, -0x1

    .line 389
    .line 390
    move v12, v5

    .line 391
    :goto_5
    if-ge v12, v6, :cond_69

    .line 392
    .line 393
    iget-object v10, v2, Lretrofit2/RequestFactory$Builder;->w:[Lretrofit2/ParameterHandler;

    .line 394
    .line 395
    iget-object v11, v2, Lretrofit2/RequestFactory$Builder;->f:[Ljava/lang/reflect/Type;

    .line 396
    .line 397
    aget-object v11, v11, v12

    .line 398
    .line 399
    aget-object v13, v4, v12

    .line 400
    .line 401
    if-ne v12, v8, :cond_16

    .line 402
    .line 403
    const/16 v16, 0x1

    .line 404
    .line 405
    goto :goto_6

    .line 406
    :cond_16
    move/from16 v16, v5

    .line 407
    .line 408
    :goto_6
    if-eqz v13, :cond_66

    .line 409
    .line 410
    array-length v14, v13

    .line 411
    move v15, v5

    .line 412
    move-object/from16 v17, v9

    .line 413
    .line 414
    :goto_7
    if-ge v15, v14, :cond_65

    .line 415
    .line 416
    aget-object v9, v13, v15

    .line 417
    .line 418
    instance-of v5, v9, Lretrofit2/http/Url;

    .line 419
    .line 420
    move-object/from16 v18, v4

    .line 421
    .line 422
    const-string v4, "@Path parameters may not be used with @Url."

    .line 423
    .line 424
    move/from16 v19, v5

    .line 425
    .line 426
    const-class v5, Ljava/lang/String;

    .line 427
    .line 428
    if-eqz v19, :cond_1f

    .line 429
    .line 430
    invoke-virtual {v2, v12, v11}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 431
    .line 432
    .line 433
    iget-boolean v9, v2, Lretrofit2/RequestFactory$Builder;->n:Z

    .line 434
    .line 435
    if-nez v9, :cond_1e

    .line 436
    .line 437
    iget-boolean v9, v2, Lretrofit2/RequestFactory$Builder;->j:Z

    .line 438
    .line 439
    if-nez v9, :cond_1d

    .line 440
    .line 441
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->k:Z

    .line 442
    .line 443
    if-nez v4, :cond_1c

    .line 444
    .line 445
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->l:Z

    .line 446
    .line 447
    if-nez v4, :cond_1b

    .line 448
    .line 449
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->m:Z

    .line 450
    .line 451
    if-nez v4, :cond_1a

    .line 452
    .line 453
    iget-object v4, v2, Lretrofit2/RequestFactory$Builder;->s:Ljava/lang/String;

    .line 454
    .line 455
    if-nez v4, :cond_19

    .line 456
    .line 457
    const/4 v4, 0x1

    .line 458
    iput-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->n:Z

    .line 459
    .line 460
    const-class v4, Ld01/a0;

    .line 461
    .line 462
    if-eq v11, v4, :cond_18

    .line 463
    .line 464
    if-eq v11, v5, :cond_18

    .line 465
    .line 466
    const-class v4, Ljava/net/URI;

    .line 467
    .line 468
    if-eq v11, v4, :cond_18

    .line 469
    .line 470
    instance-of v4, v11, Ljava/lang/Class;

    .line 471
    .line 472
    if-eqz v4, :cond_17

    .line 473
    .line 474
    move-object v4, v11

    .line 475
    check-cast v4, Ljava/lang/Class;

    .line 476
    .line 477
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 478
    .line 479
    .line 480
    move-result-object v4

    .line 481
    const-string v5, "android.net.Uri"

    .line 482
    .line 483
    invoke-virtual {v5, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 484
    .line 485
    .line 486
    move-result v4

    .line 487
    if-eqz v4, :cond_17

    .line 488
    .line 489
    goto :goto_8

    .line 490
    :cond_17
    const-string v0, "@Url must be okhttp3.HttpUrl, String, java.net.URI, or android.net.Uri type."

    .line 491
    .line 492
    const/4 v2, 0x0

    .line 493
    new-array v2, v2, [Ljava/lang/Object;

    .line 494
    .line 495
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    throw v0

    .line 500
    :cond_18
    :goto_8
    new-instance v4, Lretrofit2/ParameterHandler$RelativeUrl;

    .line 501
    .line 502
    invoke-direct {v4, v12, v1}, Lretrofit2/ParameterHandler$RelativeUrl;-><init>(ILjava/lang/reflect/Method;)V

    .line 503
    .line 504
    .line 505
    move/from16 v19, v6

    .line 506
    .line 507
    move-object/from16 v24, v7

    .line 508
    .line 509
    move/from16 v23, v8

    .line 510
    .line 511
    move-object/from16 v20, v10

    .line 512
    .line 513
    move-object v10, v11

    .line 514
    move-object v11, v13

    .line 515
    move/from16 v21, v14

    .line 516
    .line 517
    move/from16 v22, v15

    .line 518
    .line 519
    goto/16 :goto_10

    .line 520
    .line 521
    :cond_19
    iget-object v0, v2, Lretrofit2/RequestFactory$Builder;->o:Ljava/lang/String;

    .line 522
    .line 523
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    move-result-object v0

    .line 527
    const-string v2, "@Url cannot be used with @%s URL"

    .line 528
    .line 529
    invoke-static {v1, v12, v2, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 530
    .line 531
    .line 532
    move-result-object v0

    .line 533
    throw v0

    .line 534
    :cond_1a
    const-string v0, "A @Url parameter must not come after a @QueryMap."

    .line 535
    .line 536
    const/4 v2, 0x0

    .line 537
    new-array v2, v2, [Ljava/lang/Object;

    .line 538
    .line 539
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    throw v0

    .line 544
    :cond_1b
    const/4 v2, 0x0

    .line 545
    const-string v0, "A @Url parameter must not come after a @QueryName."

    .line 546
    .line 547
    new-array v2, v2, [Ljava/lang/Object;

    .line 548
    .line 549
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 550
    .line 551
    .line 552
    move-result-object v0

    .line 553
    throw v0

    .line 554
    :cond_1c
    const/4 v2, 0x0

    .line 555
    const-string v0, "A @Url parameter must not come after a @Query."

    .line 556
    .line 557
    new-array v2, v2, [Ljava/lang/Object;

    .line 558
    .line 559
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 560
    .line 561
    .line 562
    move-result-object v0

    .line 563
    throw v0

    .line 564
    :cond_1d
    const/4 v2, 0x0

    .line 565
    new-array v0, v2, [Ljava/lang/Object;

    .line 566
    .line 567
    invoke-static {v1, v12, v4, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 568
    .line 569
    .line 570
    move-result-object v0

    .line 571
    throw v0

    .line 572
    :cond_1e
    const/4 v2, 0x0

    .line 573
    const-string v0, "Multiple @Url method annotations found."

    .line 574
    .line 575
    new-array v2, v2, [Ljava/lang/Object;

    .line 576
    .line 577
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    throw v0

    .line 582
    :cond_1f
    move/from16 v19, v6

    .line 583
    .line 584
    instance-of v6, v9, Lretrofit2/http/Path;

    .line 585
    .line 586
    move/from16 v20, v6

    .line 587
    .line 588
    iget-object v6, v2, Lretrofit2/RequestFactory$Builder;->a:Lretrofit2/Retrofit;

    .line 589
    .line 590
    if-eqz v20, :cond_27

    .line 591
    .line 592
    invoke-virtual {v2, v12, v11}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 593
    .line 594
    .line 595
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->k:Z

    .line 596
    .line 597
    if-nez v5, :cond_26

    .line 598
    .line 599
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->l:Z

    .line 600
    .line 601
    if-nez v5, :cond_25

    .line 602
    .line 603
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->m:Z

    .line 604
    .line 605
    if-nez v5, :cond_24

    .line 606
    .line 607
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->n:Z

    .line 608
    .line 609
    if-nez v5, :cond_23

    .line 610
    .line 611
    iget-object v4, v2, Lretrofit2/RequestFactory$Builder;->s:Ljava/lang/String;

    .line 612
    .line 613
    if-eqz v4, :cond_22

    .line 614
    .line 615
    const/4 v4, 0x1

    .line 616
    iput-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->j:Z

    .line 617
    .line 618
    check-cast v9, Lretrofit2/http/Path;

    .line 619
    .line 620
    invoke-interface {v9}, Lretrofit2/http/Path;->value()Ljava/lang/String;

    .line 621
    .line 622
    .line 623
    move-result-object v4

    .line 624
    sget-object v5, Lretrofit2/RequestFactory$Builder;->z:Ljava/util/regex/Pattern;

    .line 625
    .line 626
    invoke-virtual {v5, v4}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 627
    .line 628
    .line 629
    move-result-object v5

    .line 630
    invoke-virtual {v5}, Ljava/util/regex/Matcher;->matches()Z

    .line 631
    .line 632
    .line 633
    move-result v5

    .line 634
    if-eqz v5, :cond_21

    .line 635
    .line 636
    iget-object v5, v2, Lretrofit2/RequestFactory$Builder;->v:Ljava/util/LinkedHashSet;

    .line 637
    .line 638
    invoke-interface {v5, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    move-result v5

    .line 642
    if-eqz v5, :cond_20

    .line 643
    .line 644
    move v5, v14

    .line 645
    invoke-virtual {v6, v11, v13}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 646
    .line 647
    .line 648
    move-result-object v14

    .line 649
    move-object v6, v10

    .line 650
    new-instance v10, Lretrofit2/ParameterHandler$Path;

    .line 651
    .line 652
    move-object/from16 v20, v11

    .line 653
    .line 654
    iget-object v11, v2, Lretrofit2/RequestFactory$Builder;->c:Ljava/lang/reflect/Method;

    .line 655
    .line 656
    invoke-interface {v9}, Lretrofit2/http/Path;->encoded()Z

    .line 657
    .line 658
    .line 659
    move-result v9

    .line 660
    move/from16 v21, v5

    .line 661
    .line 662
    move-object v5, v13

    .line 663
    move/from16 v22, v15

    .line 664
    .line 665
    move-object v13, v4

    .line 666
    move-object v4, v6

    .line 667
    move v15, v9

    .line 668
    invoke-direct/range {v10 .. v15}, Lretrofit2/ParameterHandler$Path;-><init>(Ljava/lang/reflect/Method;ILjava/lang/String;Lretrofit2/Converter;Z)V

    .line 669
    .line 670
    .line 671
    move-object/from16 v11, v20

    .line 672
    .line 673
    move-object/from16 v20, v4

    .line 674
    .line 675
    move-object v4, v10

    .line 676
    move-object v10, v11

    .line 677
    move-object v11, v5

    .line 678
    move-object/from16 v24, v7

    .line 679
    .line 680
    move/from16 v23, v8

    .line 681
    .line 682
    goto/16 :goto_10

    .line 683
    .line 684
    :cond_20
    move-object v13, v4

    .line 685
    iget-object v0, v2, Lretrofit2/RequestFactory$Builder;->s:Ljava/lang/String;

    .line 686
    .line 687
    filled-new-array {v0, v13}, [Ljava/lang/Object;

    .line 688
    .line 689
    .line 690
    move-result-object v0

    .line 691
    const-string v2, "URL \"%s\" does not contain \"{%s}\"."

    .line 692
    .line 693
    invoke-static {v1, v12, v2, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 694
    .line 695
    .line 696
    move-result-object v0

    .line 697
    throw v0

    .line 698
    :cond_21
    move-object v13, v4

    .line 699
    sget-object v0, Lretrofit2/RequestFactory$Builder;->y:Ljava/util/regex/Pattern;

    .line 700
    .line 701
    invoke-virtual {v0}, Ljava/util/regex/Pattern;->pattern()Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v0

    .line 705
    filled-new-array {v0, v13}, [Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object v0

    .line 709
    const-string v2, "@Path parameter name must match %s. Found: %s"

    .line 710
    .line 711
    invoke-static {v1, v12, v2, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 712
    .line 713
    .line 714
    move-result-object v0

    .line 715
    throw v0

    .line 716
    :cond_22
    iget-object v0, v2, Lretrofit2/RequestFactory$Builder;->o:Ljava/lang/String;

    .line 717
    .line 718
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 719
    .line 720
    .line 721
    move-result-object v0

    .line 722
    const-string v2, "@Path can only be used with relative url on @%s"

    .line 723
    .line 724
    invoke-static {v1, v12, v2, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 725
    .line 726
    .line 727
    move-result-object v0

    .line 728
    throw v0

    .line 729
    :cond_23
    const/4 v2, 0x0

    .line 730
    new-array v0, v2, [Ljava/lang/Object;

    .line 731
    .line 732
    invoke-static {v1, v12, v4, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 733
    .line 734
    .line 735
    move-result-object v0

    .line 736
    throw v0

    .line 737
    :cond_24
    const/4 v2, 0x0

    .line 738
    const-string v0, "A @Path parameter must not come after a @QueryMap."

    .line 739
    .line 740
    new-array v2, v2, [Ljava/lang/Object;

    .line 741
    .line 742
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 743
    .line 744
    .line 745
    move-result-object v0

    .line 746
    throw v0

    .line 747
    :cond_25
    const/4 v2, 0x0

    .line 748
    const-string v0, "A @Path parameter must not come after a @QueryName."

    .line 749
    .line 750
    new-array v2, v2, [Ljava/lang/Object;

    .line 751
    .line 752
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 753
    .line 754
    .line 755
    move-result-object v0

    .line 756
    throw v0

    .line 757
    :cond_26
    const/4 v2, 0x0

    .line 758
    const-string v0, "A @Path parameter must not come after a @Query."

    .line 759
    .line 760
    new-array v2, v2, [Ljava/lang/Object;

    .line 761
    .line 762
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 763
    .line 764
    .line 765
    move-result-object v0

    .line 766
    throw v0

    .line 767
    :cond_27
    move-object v4, v10

    .line 768
    move-object v10, v11

    .line 769
    move-object v11, v13

    .line 770
    move/from16 v21, v14

    .line 771
    .line 772
    move/from16 v22, v15

    .line 773
    .line 774
    instance-of v13, v9, Lretrofit2/http/Query;

    .line 775
    .line 776
    const-string v14, "<String>)"

    .line 777
    .line 778
    const-string v15, " must include generic type (e.g., "

    .line 779
    .line 780
    move-object/from16 v20, v4

    .line 781
    .line 782
    const-class v4, Ljava/lang/Iterable;

    .line 783
    .line 784
    if-eqz v13, :cond_2b

    .line 785
    .line 786
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 787
    .line 788
    .line 789
    check-cast v9, Lretrofit2/http/Query;

    .line 790
    .line 791
    invoke-interface {v9}, Lretrofit2/http/Query;->value()Ljava/lang/String;

    .line 792
    .line 793
    .line 794
    move-result-object v5

    .line 795
    invoke-interface {v9}, Lretrofit2/http/Query;->encoded()Z

    .line 796
    .line 797
    .line 798
    move-result v9

    .line 799
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 800
    .line 801
    .line 802
    move-result-object v13

    .line 803
    move/from16 v23, v8

    .line 804
    .line 805
    const/4 v8, 0x1

    .line 806
    iput-boolean v8, v2, Lretrofit2/RequestFactory$Builder;->k:Z

    .line 807
    .line 808
    invoke-virtual {v4, v13}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 809
    .line 810
    .line 811
    move-result v4

    .line 812
    if-eqz v4, :cond_29

    .line 813
    .line 814
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 815
    .line 816
    if-eqz v4, :cond_28

    .line 817
    .line 818
    move-object v4, v10

    .line 819
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 820
    .line 821
    const/4 v8, 0x0

    .line 822
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 823
    .line 824
    .line 825
    move-result-object v4

    .line 826
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 827
    .line 828
    .line 829
    move-result-object v4

    .line 830
    new-instance v6, Lretrofit2/ParameterHandler$Query;

    .line 831
    .line 832
    invoke-direct {v6, v5, v4, v9}, Lretrofit2/ParameterHandler$Query;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 833
    .line 834
    .line 835
    new-instance v4, Lretrofit2/ParameterHandler$1;

    .line 836
    .line 837
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 838
    .line 839
    .line 840
    :goto_9
    move-object/from16 v24, v7

    .line 841
    .line 842
    goto/16 :goto_10

    .line 843
    .line 844
    :cond_28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 845
    .line 846
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 847
    .line 848
    .line 849
    invoke-virtual {v13}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 850
    .line 851
    .line 852
    move-result-object v2

    .line 853
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 854
    .line 855
    .line 856
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 857
    .line 858
    .line 859
    invoke-virtual {v13}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 860
    .line 861
    .line 862
    move-result-object v2

    .line 863
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 864
    .line 865
    .line 866
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 867
    .line 868
    .line 869
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 870
    .line 871
    .line 872
    move-result-object v0

    .line 873
    const/4 v2, 0x0

    .line 874
    new-array v2, v2, [Ljava/lang/Object;

    .line 875
    .line 876
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 877
    .line 878
    .line 879
    move-result-object v0

    .line 880
    throw v0

    .line 881
    :cond_29
    invoke-virtual {v13}, Ljava/lang/Class;->isArray()Z

    .line 882
    .line 883
    .line 884
    move-result v4

    .line 885
    if-eqz v4, :cond_2a

    .line 886
    .line 887
    invoke-virtual {v13}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 888
    .line 889
    .line 890
    move-result-object v4

    .line 891
    invoke-static {v4}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 892
    .line 893
    .line 894
    move-result-object v4

    .line 895
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 896
    .line 897
    .line 898
    move-result-object v4

    .line 899
    new-instance v6, Lretrofit2/ParameterHandler$Query;

    .line 900
    .line 901
    invoke-direct {v6, v5, v4, v9}, Lretrofit2/ParameterHandler$Query;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 902
    .line 903
    .line 904
    new-instance v4, Lretrofit2/ParameterHandler$2;

    .line 905
    .line 906
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 907
    .line 908
    .line 909
    goto :goto_9

    .line 910
    :cond_2a
    invoke-virtual {v6, v10, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 911
    .line 912
    .line 913
    move-result-object v4

    .line 914
    new-instance v6, Lretrofit2/ParameterHandler$Query;

    .line 915
    .line 916
    invoke-direct {v6, v5, v4, v9}, Lretrofit2/ParameterHandler$Query;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 917
    .line 918
    .line 919
    :goto_a
    move-object v4, v6

    .line 920
    goto :goto_9

    .line 921
    :cond_2b
    move/from16 v23, v8

    .line 922
    .line 923
    instance-of v8, v9, Lretrofit2/http/QueryName;

    .line 924
    .line 925
    if-eqz v8, :cond_2f

    .line 926
    .line 927
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 928
    .line 929
    .line 930
    check-cast v9, Lretrofit2/http/QueryName;

    .line 931
    .line 932
    invoke-interface {v9}, Lretrofit2/http/QueryName;->encoded()Z

    .line 933
    .line 934
    .line 935
    move-result v5

    .line 936
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 937
    .line 938
    .line 939
    move-result-object v8

    .line 940
    const/4 v9, 0x1

    .line 941
    iput-boolean v9, v2, Lretrofit2/RequestFactory$Builder;->l:Z

    .line 942
    .line 943
    invoke-virtual {v4, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 944
    .line 945
    .line 946
    move-result v4

    .line 947
    if-eqz v4, :cond_2d

    .line 948
    .line 949
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 950
    .line 951
    if-eqz v4, :cond_2c

    .line 952
    .line 953
    move-object v4, v10

    .line 954
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 955
    .line 956
    const/4 v8, 0x0

    .line 957
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 958
    .line 959
    .line 960
    move-result-object v4

    .line 961
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 962
    .line 963
    .line 964
    move-result-object v4

    .line 965
    new-instance v6, Lretrofit2/ParameterHandler$QueryName;

    .line 966
    .line 967
    invoke-direct {v6, v4, v5}, Lretrofit2/ParameterHandler$QueryName;-><init>(Lretrofit2/Converter;Z)V

    .line 968
    .line 969
    .line 970
    new-instance v4, Lretrofit2/ParameterHandler$1;

    .line 971
    .line 972
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 973
    .line 974
    .line 975
    goto/16 :goto_9

    .line 976
    .line 977
    :cond_2c
    new-instance v0, Ljava/lang/StringBuilder;

    .line 978
    .line 979
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 980
    .line 981
    .line 982
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 983
    .line 984
    .line 985
    move-result-object v2

    .line 986
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 987
    .line 988
    .line 989
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 990
    .line 991
    .line 992
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 993
    .line 994
    .line 995
    move-result-object v2

    .line 996
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 997
    .line 998
    .line 999
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1000
    .line 1001
    .line 1002
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1003
    .line 1004
    .line 1005
    move-result-object v0

    .line 1006
    const/4 v2, 0x0

    .line 1007
    new-array v2, v2, [Ljava/lang/Object;

    .line 1008
    .line 1009
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v0

    .line 1013
    throw v0

    .line 1014
    :cond_2d
    invoke-virtual {v8}, Ljava/lang/Class;->isArray()Z

    .line 1015
    .line 1016
    .line 1017
    move-result v4

    .line 1018
    if-eqz v4, :cond_2e

    .line 1019
    .line 1020
    invoke-virtual {v8}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 1021
    .line 1022
    .line 1023
    move-result-object v4

    .line 1024
    invoke-static {v4}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v4

    .line 1028
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v4

    .line 1032
    new-instance v6, Lretrofit2/ParameterHandler$QueryName;

    .line 1033
    .line 1034
    invoke-direct {v6, v4, v5}, Lretrofit2/ParameterHandler$QueryName;-><init>(Lretrofit2/Converter;Z)V

    .line 1035
    .line 1036
    .line 1037
    new-instance v4, Lretrofit2/ParameterHandler$2;

    .line 1038
    .line 1039
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1040
    .line 1041
    .line 1042
    goto/16 :goto_9

    .line 1043
    .line 1044
    :cond_2e
    invoke-virtual {v6, v10, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v4

    .line 1048
    new-instance v6, Lretrofit2/ParameterHandler$QueryName;

    .line 1049
    .line 1050
    invoke-direct {v6, v4, v5}, Lretrofit2/ParameterHandler$QueryName;-><init>(Lretrofit2/Converter;Z)V

    .line 1051
    .line 1052
    .line 1053
    goto/16 :goto_a

    .line 1054
    .line 1055
    :cond_2f
    instance-of v8, v9, Lretrofit2/http/QueryMap;

    .line 1056
    .line 1057
    const-string v13, "Map must include generic types (e.g., Map<String, String>)"

    .line 1058
    .line 1059
    move/from16 v24, v8

    .line 1060
    .line 1061
    const-class v8, Ljava/util/Map;

    .line 1062
    .line 1063
    if-eqz v24, :cond_33

    .line 1064
    .line 1065
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1066
    .line 1067
    .line 1068
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v4

    .line 1072
    const/4 v14, 0x1

    .line 1073
    iput-boolean v14, v2, Lretrofit2/RequestFactory$Builder;->m:Z

    .line 1074
    .line 1075
    invoke-virtual {v8, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1076
    .line 1077
    .line 1078
    move-result v8

    .line 1079
    if-eqz v8, :cond_32

    .line 1080
    .line 1081
    invoke-static {v10, v4}, Lretrofit2/Utils;->f(Ljava/lang/reflect/Type;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v4

    .line 1085
    instance-of v8, v4, Ljava/lang/reflect/ParameterizedType;

    .line 1086
    .line 1087
    if-eqz v8, :cond_31

    .line 1088
    .line 1089
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1090
    .line 1091
    const/4 v8, 0x0

    .line 1092
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v13

    .line 1096
    if-ne v5, v13, :cond_30

    .line 1097
    .line 1098
    invoke-static {v14, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v4

    .line 1102
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v4

    .line 1106
    new-instance v5, Lretrofit2/ParameterHandler$QueryMap;

    .line 1107
    .line 1108
    check-cast v9, Lretrofit2/http/QueryMap;

    .line 1109
    .line 1110
    invoke-interface {v9}, Lretrofit2/http/QueryMap;->encoded()Z

    .line 1111
    .line 1112
    .line 1113
    move-result v6

    .line 1114
    invoke-direct {v5, v1, v12, v4, v6}, Lretrofit2/ParameterHandler$QueryMap;-><init>(Ljava/lang/reflect/Method;ILretrofit2/Converter;Z)V

    .line 1115
    .line 1116
    .line 1117
    move-object v4, v5

    .line 1118
    goto/16 :goto_9

    .line 1119
    .line 1120
    :cond_30
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1121
    .line 1122
    const-string v2, "@QueryMap keys must be of type String: "

    .line 1123
    .line 1124
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1125
    .line 1126
    .line 1127
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1128
    .line 1129
    .line 1130
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v0

    .line 1134
    const/4 v2, 0x0

    .line 1135
    new-array v2, v2, [Ljava/lang/Object;

    .line 1136
    .line 1137
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v0

    .line 1141
    throw v0

    .line 1142
    :cond_31
    const/4 v2, 0x0

    .line 1143
    new-array v0, v2, [Ljava/lang/Object;

    .line 1144
    .line 1145
    invoke-static {v1, v12, v13, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1146
    .line 1147
    .line 1148
    move-result-object v0

    .line 1149
    throw v0

    .line 1150
    :cond_32
    const/4 v2, 0x0

    .line 1151
    const-string v0, "@QueryMap parameter type must be Map."

    .line 1152
    .line 1153
    new-array v2, v2, [Ljava/lang/Object;

    .line 1154
    .line 1155
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v0

    .line 1159
    throw v0

    .line 1160
    :cond_33
    move-object/from16 v24, v7

    .line 1161
    .line 1162
    instance-of v7, v9, Lretrofit2/http/Header;

    .line 1163
    .line 1164
    if-eqz v7, :cond_37

    .line 1165
    .line 1166
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1167
    .line 1168
    .line 1169
    check-cast v9, Lretrofit2/http/Header;

    .line 1170
    .line 1171
    invoke-interface {v9}, Lretrofit2/http/Header;->value()Ljava/lang/String;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v5

    .line 1175
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v7

    .line 1179
    invoke-virtual {v4, v7}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1180
    .line 1181
    .line 1182
    move-result v4

    .line 1183
    if-eqz v4, :cond_35

    .line 1184
    .line 1185
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 1186
    .line 1187
    if-eqz v4, :cond_34

    .line 1188
    .line 1189
    move-object v4, v10

    .line 1190
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1191
    .line 1192
    const/4 v8, 0x0

    .line 1193
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1194
    .line 1195
    .line 1196
    move-result-object v4

    .line 1197
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v4

    .line 1201
    new-instance v6, Lretrofit2/ParameterHandler$Header;

    .line 1202
    .line 1203
    invoke-interface {v9}, Lretrofit2/http/Header;->allowUnsafeNonAsciiValues()Z

    .line 1204
    .line 1205
    .line 1206
    move-result v7

    .line 1207
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Header;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1208
    .line 1209
    .line 1210
    new-instance v4, Lretrofit2/ParameterHandler$1;

    .line 1211
    .line 1212
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1213
    .line 1214
    .line 1215
    goto/16 :goto_10

    .line 1216
    .line 1217
    :cond_34
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1218
    .line 1219
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1220
    .line 1221
    .line 1222
    invoke-virtual {v7}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v2

    .line 1226
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1227
    .line 1228
    .line 1229
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1230
    .line 1231
    .line 1232
    invoke-virtual {v7}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v2

    .line 1236
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1237
    .line 1238
    .line 1239
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1240
    .line 1241
    .line 1242
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v0

    .line 1246
    const/4 v2, 0x0

    .line 1247
    new-array v2, v2, [Ljava/lang/Object;

    .line 1248
    .line 1249
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1250
    .line 1251
    .line 1252
    move-result-object v0

    .line 1253
    throw v0

    .line 1254
    :cond_35
    invoke-virtual {v7}, Ljava/lang/Class;->isArray()Z

    .line 1255
    .line 1256
    .line 1257
    move-result v4

    .line 1258
    if-eqz v4, :cond_36

    .line 1259
    .line 1260
    invoke-virtual {v7}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v4

    .line 1264
    invoke-static {v4}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v4

    .line 1268
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1269
    .line 1270
    .line 1271
    move-result-object v4

    .line 1272
    new-instance v6, Lretrofit2/ParameterHandler$Header;

    .line 1273
    .line 1274
    invoke-interface {v9}, Lretrofit2/http/Header;->allowUnsafeNonAsciiValues()Z

    .line 1275
    .line 1276
    .line 1277
    move-result v7

    .line 1278
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Header;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1279
    .line 1280
    .line 1281
    new-instance v4, Lretrofit2/ParameterHandler$2;

    .line 1282
    .line 1283
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1284
    .line 1285
    .line 1286
    goto/16 :goto_10

    .line 1287
    .line 1288
    :cond_36
    invoke-virtual {v6, v10, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v4

    .line 1292
    new-instance v6, Lretrofit2/ParameterHandler$Header;

    .line 1293
    .line 1294
    invoke-interface {v9}, Lretrofit2/http/Header;->allowUnsafeNonAsciiValues()Z

    .line 1295
    .line 1296
    .line 1297
    move-result v7

    .line 1298
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Header;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1299
    .line 1300
    .line 1301
    :goto_b
    move-object v4, v6

    .line 1302
    goto/16 :goto_10

    .line 1303
    .line 1304
    :cond_37
    instance-of v7, v9, Lretrofit2/http/HeaderMap;

    .line 1305
    .line 1306
    if-eqz v7, :cond_3c

    .line 1307
    .line 1308
    const-class v4, Ld01/y;

    .line 1309
    .line 1310
    if-ne v10, v4, :cond_38

    .line 1311
    .line 1312
    new-instance v4, Lretrofit2/ParameterHandler$Headers;

    .line 1313
    .line 1314
    invoke-direct {v4, v12, v1}, Lretrofit2/ParameterHandler$Headers;-><init>(ILjava/lang/reflect/Method;)V

    .line 1315
    .line 1316
    .line 1317
    goto/16 :goto_10

    .line 1318
    .line 1319
    :cond_38
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1320
    .line 1321
    .line 1322
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v4

    .line 1326
    invoke-virtual {v8, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1327
    .line 1328
    .line 1329
    move-result v7

    .line 1330
    if-eqz v7, :cond_3b

    .line 1331
    .line 1332
    invoke-static {v10, v4}, Lretrofit2/Utils;->f(Ljava/lang/reflect/Type;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v4

    .line 1336
    instance-of v7, v4, Ljava/lang/reflect/ParameterizedType;

    .line 1337
    .line 1338
    if-eqz v7, :cond_3a

    .line 1339
    .line 1340
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1341
    .line 1342
    const/4 v8, 0x0

    .line 1343
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v7

    .line 1347
    if-ne v5, v7, :cond_39

    .line 1348
    .line 1349
    const/4 v14, 0x1

    .line 1350
    invoke-static {v14, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v4

    .line 1354
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v4

    .line 1358
    new-instance v5, Lretrofit2/ParameterHandler$HeaderMap;

    .line 1359
    .line 1360
    check-cast v9, Lretrofit2/http/HeaderMap;

    .line 1361
    .line 1362
    invoke-interface {v9}, Lretrofit2/http/HeaderMap;->allowUnsafeNonAsciiValues()Z

    .line 1363
    .line 1364
    .line 1365
    move-result v6

    .line 1366
    invoke-direct {v5, v1, v12, v4, v6}, Lretrofit2/ParameterHandler$HeaderMap;-><init>(Ljava/lang/reflect/Method;ILretrofit2/Converter;Z)V

    .line 1367
    .line 1368
    .line 1369
    :goto_c
    move-object v4, v5

    .line 1370
    goto/16 :goto_10

    .line 1371
    .line 1372
    :cond_39
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1373
    .line 1374
    const-string v2, "@HeaderMap keys must be of type String: "

    .line 1375
    .line 1376
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1377
    .line 1378
    .line 1379
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1380
    .line 1381
    .line 1382
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1383
    .line 1384
    .line 1385
    move-result-object v0

    .line 1386
    const/4 v2, 0x0

    .line 1387
    new-array v2, v2, [Ljava/lang/Object;

    .line 1388
    .line 1389
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v0

    .line 1393
    throw v0

    .line 1394
    :cond_3a
    const/4 v2, 0x0

    .line 1395
    new-array v0, v2, [Ljava/lang/Object;

    .line 1396
    .line 1397
    invoke-static {v1, v12, v13, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1398
    .line 1399
    .line 1400
    move-result-object v0

    .line 1401
    throw v0

    .line 1402
    :cond_3b
    const/4 v2, 0x0

    .line 1403
    const-string v0, "@HeaderMap parameter type must be Map or Headers."

    .line 1404
    .line 1405
    new-array v2, v2, [Ljava/lang/Object;

    .line 1406
    .line 1407
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v0

    .line 1411
    throw v0

    .line 1412
    :cond_3c
    instance-of v7, v9, Lretrofit2/http/Field;

    .line 1413
    .line 1414
    if-eqz v7, :cond_41

    .line 1415
    .line 1416
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1417
    .line 1418
    .line 1419
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 1420
    .line 1421
    if-eqz v5, :cond_40

    .line 1422
    .line 1423
    check-cast v9, Lretrofit2/http/Field;

    .line 1424
    .line 1425
    invoke-interface {v9}, Lretrofit2/http/Field;->value()Ljava/lang/String;

    .line 1426
    .line 1427
    .line 1428
    move-result-object v5

    .line 1429
    invoke-interface {v9}, Lretrofit2/http/Field;->encoded()Z

    .line 1430
    .line 1431
    .line 1432
    move-result v7

    .line 1433
    const/4 v8, 0x1

    .line 1434
    iput-boolean v8, v2, Lretrofit2/RequestFactory$Builder;->g:Z

    .line 1435
    .line 1436
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v8

    .line 1440
    invoke-virtual {v4, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1441
    .line 1442
    .line 1443
    move-result v4

    .line 1444
    if-eqz v4, :cond_3e

    .line 1445
    .line 1446
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 1447
    .line 1448
    if-eqz v4, :cond_3d

    .line 1449
    .line 1450
    move-object v4, v10

    .line 1451
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1452
    .line 1453
    const/4 v8, 0x0

    .line 1454
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1455
    .line 1456
    .line 1457
    move-result-object v4

    .line 1458
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1459
    .line 1460
    .line 1461
    move-result-object v4

    .line 1462
    new-instance v6, Lretrofit2/ParameterHandler$Field;

    .line 1463
    .line 1464
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Field;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1465
    .line 1466
    .line 1467
    new-instance v4, Lretrofit2/ParameterHandler$1;

    .line 1468
    .line 1469
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1470
    .line 1471
    .line 1472
    goto/16 :goto_10

    .line 1473
    .line 1474
    :cond_3d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1475
    .line 1476
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1477
    .line 1478
    .line 1479
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1480
    .line 1481
    .line 1482
    move-result-object v2

    .line 1483
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1484
    .line 1485
    .line 1486
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1487
    .line 1488
    .line 1489
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v2

    .line 1493
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1494
    .line 1495
    .line 1496
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1497
    .line 1498
    .line 1499
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v0

    .line 1503
    const/4 v2, 0x0

    .line 1504
    new-array v2, v2, [Ljava/lang/Object;

    .line 1505
    .line 1506
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v0

    .line 1510
    throw v0

    .line 1511
    :cond_3e
    invoke-virtual {v8}, Ljava/lang/Class;->isArray()Z

    .line 1512
    .line 1513
    .line 1514
    move-result v4

    .line 1515
    if-eqz v4, :cond_3f

    .line 1516
    .line 1517
    invoke-virtual {v8}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v4

    .line 1521
    invoke-static {v4}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v4

    .line 1525
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v4

    .line 1529
    new-instance v6, Lretrofit2/ParameterHandler$Field;

    .line 1530
    .line 1531
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Field;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1532
    .line 1533
    .line 1534
    new-instance v4, Lretrofit2/ParameterHandler$2;

    .line 1535
    .line 1536
    invoke-direct {v4, v6}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1537
    .line 1538
    .line 1539
    goto/16 :goto_10

    .line 1540
    .line 1541
    :cond_3f
    invoke-virtual {v6, v10, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1542
    .line 1543
    .line 1544
    move-result-object v4

    .line 1545
    new-instance v6, Lretrofit2/ParameterHandler$Field;

    .line 1546
    .line 1547
    invoke-direct {v6, v5, v4, v7}, Lretrofit2/ParameterHandler$Field;-><init>(Ljava/lang/String;Lretrofit2/Converter;Z)V

    .line 1548
    .line 1549
    .line 1550
    goto/16 :goto_b

    .line 1551
    .line 1552
    :cond_40
    const-string v0, "@Field parameters can only be used with form encoding."

    .line 1553
    .line 1554
    const/4 v2, 0x0

    .line 1555
    new-array v2, v2, [Ljava/lang/Object;

    .line 1556
    .line 1557
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1558
    .line 1559
    .line 1560
    move-result-object v0

    .line 1561
    throw v0

    .line 1562
    :cond_41
    instance-of v7, v9, Lretrofit2/http/FieldMap;

    .line 1563
    .line 1564
    if-eqz v7, :cond_46

    .line 1565
    .line 1566
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1567
    .line 1568
    .line 1569
    iget-boolean v4, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 1570
    .line 1571
    if-eqz v4, :cond_45

    .line 1572
    .line 1573
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1574
    .line 1575
    .line 1576
    move-result-object v4

    .line 1577
    invoke-virtual {v8, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1578
    .line 1579
    .line 1580
    move-result v7

    .line 1581
    if-eqz v7, :cond_44

    .line 1582
    .line 1583
    invoke-static {v10, v4}, Lretrofit2/Utils;->f(Ljava/lang/reflect/Type;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 1584
    .line 1585
    .line 1586
    move-result-object v4

    .line 1587
    instance-of v7, v4, Ljava/lang/reflect/ParameterizedType;

    .line 1588
    .line 1589
    if-eqz v7, :cond_43

    .line 1590
    .line 1591
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1592
    .line 1593
    const/4 v8, 0x0

    .line 1594
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v7

    .line 1598
    if-ne v5, v7, :cond_42

    .line 1599
    .line 1600
    const/4 v14, 0x1

    .line 1601
    invoke-static {v14, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v4

    .line 1605
    invoke-virtual {v6, v4, v11}, Lretrofit2/Retrofit;->e(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1606
    .line 1607
    .line 1608
    move-result-object v4

    .line 1609
    iput-boolean v14, v2, Lretrofit2/RequestFactory$Builder;->g:Z

    .line 1610
    .line 1611
    new-instance v5, Lretrofit2/ParameterHandler$FieldMap;

    .line 1612
    .line 1613
    check-cast v9, Lretrofit2/http/FieldMap;

    .line 1614
    .line 1615
    invoke-interface {v9}, Lretrofit2/http/FieldMap;->encoded()Z

    .line 1616
    .line 1617
    .line 1618
    move-result v6

    .line 1619
    invoke-direct {v5, v1, v12, v4, v6}, Lretrofit2/ParameterHandler$FieldMap;-><init>(Ljava/lang/reflect/Method;ILretrofit2/Converter;Z)V

    .line 1620
    .line 1621
    .line 1622
    goto/16 :goto_c

    .line 1623
    .line 1624
    :cond_42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1625
    .line 1626
    const-string v2, "@FieldMap keys must be of type String: "

    .line 1627
    .line 1628
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1629
    .line 1630
    .line 1631
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1632
    .line 1633
    .line 1634
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1635
    .line 1636
    .line 1637
    move-result-object v0

    .line 1638
    const/4 v2, 0x0

    .line 1639
    new-array v2, v2, [Ljava/lang/Object;

    .line 1640
    .line 1641
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1642
    .line 1643
    .line 1644
    move-result-object v0

    .line 1645
    throw v0

    .line 1646
    :cond_43
    const/4 v2, 0x0

    .line 1647
    new-array v0, v2, [Ljava/lang/Object;

    .line 1648
    .line 1649
    invoke-static {v1, v12, v13, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v0

    .line 1653
    throw v0

    .line 1654
    :cond_44
    const/4 v2, 0x0

    .line 1655
    const-string v0, "@FieldMap parameter type must be Map."

    .line 1656
    .line 1657
    new-array v2, v2, [Ljava/lang/Object;

    .line 1658
    .line 1659
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1660
    .line 1661
    .line 1662
    move-result-object v0

    .line 1663
    throw v0

    .line 1664
    :cond_45
    const/4 v2, 0x0

    .line 1665
    const-string v0, "@FieldMap parameters can only be used with form encoding."

    .line 1666
    .line 1667
    new-array v2, v2, [Ljava/lang/Object;

    .line 1668
    .line 1669
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1670
    .line 1671
    .line 1672
    move-result-object v0

    .line 1673
    throw v0

    .line 1674
    :cond_46
    instance-of v7, v9, Lretrofit2/http/Part;

    .line 1675
    .line 1676
    move/from16 v25, v7

    .line 1677
    .line 1678
    const-class v7, Ld01/e0;

    .line 1679
    .line 1680
    if-eqz v25, :cond_55

    .line 1681
    .line 1682
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 1683
    .line 1684
    .line 1685
    iget-boolean v5, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 1686
    .line 1687
    if-eqz v5, :cond_54

    .line 1688
    .line 1689
    check-cast v9, Lretrofit2/http/Part;

    .line 1690
    .line 1691
    const/4 v8, 0x1

    .line 1692
    iput-boolean v8, v2, Lretrofit2/RequestFactory$Builder;->h:Z

    .line 1693
    .line 1694
    invoke-interface {v9}, Lretrofit2/http/Part;->value()Ljava/lang/String;

    .line 1695
    .line 1696
    .line 1697
    move-result-object v5

    .line 1698
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v8

    .line 1702
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    .line 1703
    .line 1704
    .line 1705
    move-result v13

    .line 1706
    if-eqz v13, :cond_4d

    .line 1707
    .line 1708
    invoke-virtual {v4, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1709
    .line 1710
    .line 1711
    move-result v4

    .line 1712
    const-string v5, "@Part annotation must supply a name or use MultipartBody.Part parameter type."

    .line 1713
    .line 1714
    if-eqz v4, :cond_49

    .line 1715
    .line 1716
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 1717
    .line 1718
    if-eqz v4, :cond_48

    .line 1719
    .line 1720
    move-object v4, v10

    .line 1721
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1722
    .line 1723
    const/4 v8, 0x0

    .line 1724
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1725
    .line 1726
    .line 1727
    move-result-object v4

    .line 1728
    invoke-static {v4}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1729
    .line 1730
    .line 1731
    move-result-object v4

    .line 1732
    invoke-virtual {v7, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1733
    .line 1734
    .line 1735
    move-result v4

    .line 1736
    if-eqz v4, :cond_47

    .line 1737
    .line 1738
    sget-object v4, Lretrofit2/ParameterHandler$RawPart;->a:Lretrofit2/ParameterHandler$RawPart;

    .line 1739
    .line 1740
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1741
    .line 1742
    .line 1743
    new-instance v5, Lretrofit2/ParameterHandler$1;

    .line 1744
    .line 1745
    invoke-direct {v5, v4}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1746
    .line 1747
    .line 1748
    goto/16 :goto_c

    .line 1749
    .line 1750
    :cond_47
    new-array v0, v8, [Ljava/lang/Object;

    .line 1751
    .line 1752
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1753
    .line 1754
    .line 1755
    move-result-object v0

    .line 1756
    throw v0

    .line 1757
    :cond_48
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1758
    .line 1759
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1760
    .line 1761
    .line 1762
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1763
    .line 1764
    .line 1765
    move-result-object v2

    .line 1766
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1767
    .line 1768
    .line 1769
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1770
    .line 1771
    .line 1772
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1773
    .line 1774
    .line 1775
    move-result-object v2

    .line 1776
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1777
    .line 1778
    .line 1779
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1780
    .line 1781
    .line 1782
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1783
    .line 1784
    .line 1785
    move-result-object v0

    .line 1786
    const/4 v2, 0x0

    .line 1787
    new-array v2, v2, [Ljava/lang/Object;

    .line 1788
    .line 1789
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1790
    .line 1791
    .line 1792
    move-result-object v0

    .line 1793
    throw v0

    .line 1794
    :cond_49
    invoke-virtual {v8}, Ljava/lang/Class;->isArray()Z

    .line 1795
    .line 1796
    .line 1797
    move-result v4

    .line 1798
    if-eqz v4, :cond_4b

    .line 1799
    .line 1800
    invoke-virtual {v8}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 1801
    .line 1802
    .line 1803
    move-result-object v4

    .line 1804
    invoke-virtual {v7, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1805
    .line 1806
    .line 1807
    move-result v4

    .line 1808
    if-eqz v4, :cond_4a

    .line 1809
    .line 1810
    sget-object v4, Lretrofit2/ParameterHandler$RawPart;->a:Lretrofit2/ParameterHandler$RawPart;

    .line 1811
    .line 1812
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1813
    .line 1814
    .line 1815
    new-instance v5, Lretrofit2/ParameterHandler$2;

    .line 1816
    .line 1817
    invoke-direct {v5, v4}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1818
    .line 1819
    .line 1820
    goto/16 :goto_c

    .line 1821
    .line 1822
    :cond_4a
    const/4 v4, 0x0

    .line 1823
    new-array v0, v4, [Ljava/lang/Object;

    .line 1824
    .line 1825
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1826
    .line 1827
    .line 1828
    move-result-object v0

    .line 1829
    throw v0

    .line 1830
    :cond_4b
    const/4 v4, 0x0

    .line 1831
    invoke-virtual {v7, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1832
    .line 1833
    .line 1834
    move-result v6

    .line 1835
    if-eqz v6, :cond_4c

    .line 1836
    .line 1837
    sget-object v5, Lretrofit2/ParameterHandler$RawPart;->a:Lretrofit2/ParameterHandler$RawPart;

    .line 1838
    .line 1839
    goto/16 :goto_c

    .line 1840
    .line 1841
    :cond_4c
    new-array v0, v4, [Ljava/lang/Object;

    .line 1842
    .line 1843
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1844
    .line 1845
    .line 1846
    move-result-object v0

    .line 1847
    throw v0

    .line 1848
    :cond_4d
    const-string v13, "form-data; name=\""

    .line 1849
    .line 1850
    move-object/from16 v25, v9

    .line 1851
    .line 1852
    const-string v9, "\""

    .line 1853
    .line 1854
    invoke-static {v13, v5, v9}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1855
    .line 1856
    .line 1857
    move-result-object v5

    .line 1858
    const-string v9, "Content-Transfer-Encoding"

    .line 1859
    .line 1860
    invoke-interface/range {v25 .. v25}, Lretrofit2/http/Part;->encoding()Ljava/lang/String;

    .line 1861
    .line 1862
    .line 1863
    move-result-object v13

    .line 1864
    const-string v0, "Content-Disposition"

    .line 1865
    .line 1866
    filled-new-array {v0, v5, v9, v13}, [Ljava/lang/String;

    .line 1867
    .line 1868
    .line 1869
    move-result-object v0

    .line 1870
    sget-object v5, Ld01/y;->e:Ld01/y;

    .line 1871
    .line 1872
    invoke-static {v0}, Ljp/te;->b([Ljava/lang/String;)Ld01/y;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v0

    .line 1876
    invoke-virtual {v4, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1877
    .line 1878
    .line 1879
    move-result v4

    .line 1880
    const-string v5, "@Part parameters using the MultipartBody.Part must not include a part name in the annotation."

    .line 1881
    .line 1882
    if-eqz v4, :cond_50

    .line 1883
    .line 1884
    instance-of v4, v10, Ljava/lang/reflect/ParameterizedType;

    .line 1885
    .line 1886
    if-eqz v4, :cond_4f

    .line 1887
    .line 1888
    move-object v4, v10

    .line 1889
    check-cast v4, Ljava/lang/reflect/ParameterizedType;

    .line 1890
    .line 1891
    const/4 v8, 0x0

    .line 1892
    invoke-static {v8, v4}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 1893
    .line 1894
    .line 1895
    move-result-object v4

    .line 1896
    invoke-static {v4}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 1897
    .line 1898
    .line 1899
    move-result-object v9

    .line 1900
    invoke-virtual {v7, v9}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1901
    .line 1902
    .line 1903
    move-result v7

    .line 1904
    if-nez v7, :cond_4e

    .line 1905
    .line 1906
    invoke-virtual {v6, v4, v11, v3}, Lretrofit2/Retrofit;->c(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1907
    .line 1908
    .line 1909
    move-result-object v4

    .line 1910
    new-instance v5, Lretrofit2/ParameterHandler$Part;

    .line 1911
    .line 1912
    invoke-direct {v5, v1, v12, v0, v4}, Lretrofit2/ParameterHandler$Part;-><init>(Ljava/lang/reflect/Method;ILd01/y;Lretrofit2/Converter;)V

    .line 1913
    .line 1914
    .line 1915
    new-instance v0, Lretrofit2/ParameterHandler$1;

    .line 1916
    .line 1917
    invoke-direct {v0, v5}, Lretrofit2/ParameterHandler$1;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1918
    .line 1919
    .line 1920
    :goto_d
    move-object v4, v0

    .line 1921
    goto/16 :goto_10

    .line 1922
    .line 1923
    :cond_4e
    new-array v0, v8, [Ljava/lang/Object;

    .line 1924
    .line 1925
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1926
    .line 1927
    .line 1928
    move-result-object v0

    .line 1929
    throw v0

    .line 1930
    :cond_4f
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1931
    .line 1932
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 1933
    .line 1934
    .line 1935
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1936
    .line 1937
    .line 1938
    move-result-object v2

    .line 1939
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1940
    .line 1941
    .line 1942
    invoke-virtual {v0, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1943
    .line 1944
    .line 1945
    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 1946
    .line 1947
    .line 1948
    move-result-object v2

    .line 1949
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1950
    .line 1951
    .line 1952
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1953
    .line 1954
    .line 1955
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1956
    .line 1957
    .line 1958
    move-result-object v0

    .line 1959
    const/4 v2, 0x0

    .line 1960
    new-array v2, v2, [Ljava/lang/Object;

    .line 1961
    .line 1962
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 1963
    .line 1964
    .line 1965
    move-result-object v0

    .line 1966
    throw v0

    .line 1967
    :cond_50
    invoke-virtual {v8}, Ljava/lang/Class;->isArray()Z

    .line 1968
    .line 1969
    .line 1970
    move-result v4

    .line 1971
    if-eqz v4, :cond_52

    .line 1972
    .line 1973
    invoke-virtual {v8}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 1974
    .line 1975
    .line 1976
    move-result-object v4

    .line 1977
    invoke-static {v4}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v4

    .line 1981
    invoke-virtual {v7, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 1982
    .line 1983
    .line 1984
    move-result v7

    .line 1985
    if-nez v7, :cond_51

    .line 1986
    .line 1987
    invoke-virtual {v6, v4, v11, v3}, Lretrofit2/Retrofit;->c(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 1988
    .line 1989
    .line 1990
    move-result-object v4

    .line 1991
    new-instance v5, Lretrofit2/ParameterHandler$Part;

    .line 1992
    .line 1993
    invoke-direct {v5, v1, v12, v0, v4}, Lretrofit2/ParameterHandler$Part;-><init>(Ljava/lang/reflect/Method;ILd01/y;Lretrofit2/Converter;)V

    .line 1994
    .line 1995
    .line 1996
    new-instance v0, Lretrofit2/ParameterHandler$2;

    .line 1997
    .line 1998
    invoke-direct {v0, v5}, Lretrofit2/ParameterHandler$2;-><init>(Lretrofit2/ParameterHandler;)V

    .line 1999
    .line 2000
    .line 2001
    goto :goto_d

    .line 2002
    :cond_51
    const/4 v4, 0x0

    .line 2003
    new-array v0, v4, [Ljava/lang/Object;

    .line 2004
    .line 2005
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2006
    .line 2007
    .line 2008
    move-result-object v0

    .line 2009
    throw v0

    .line 2010
    :cond_52
    const/4 v4, 0x0

    .line 2011
    invoke-virtual {v7, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 2012
    .line 2013
    .line 2014
    move-result v7

    .line 2015
    if-nez v7, :cond_53

    .line 2016
    .line 2017
    invoke-virtual {v6, v10, v11, v3}, Lretrofit2/Retrofit;->c(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 2018
    .line 2019
    .line 2020
    move-result-object v5

    .line 2021
    new-instance v6, Lretrofit2/ParameterHandler$Part;

    .line 2022
    .line 2023
    invoke-direct {v6, v1, v12, v0, v5}, Lretrofit2/ParameterHandler$Part;-><init>(Ljava/lang/reflect/Method;ILd01/y;Lretrofit2/Converter;)V

    .line 2024
    .line 2025
    .line 2026
    goto/16 :goto_b

    .line 2027
    .line 2028
    :cond_53
    new-array v0, v4, [Ljava/lang/Object;

    .line 2029
    .line 2030
    invoke-static {v1, v12, v5, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2031
    .line 2032
    .line 2033
    move-result-object v0

    .line 2034
    throw v0

    .line 2035
    :cond_54
    const/4 v4, 0x0

    .line 2036
    const-string v0, "@Part parameters can only be used with multipart encoding."

    .line 2037
    .line 2038
    new-array v2, v4, [Ljava/lang/Object;

    .line 2039
    .line 2040
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2041
    .line 2042
    .line 2043
    move-result-object v0

    .line 2044
    throw v0

    .line 2045
    :cond_55
    instance-of v0, v9, Lretrofit2/http/PartMap;

    .line 2046
    .line 2047
    if-eqz v0, :cond_5b

    .line 2048
    .line 2049
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 2050
    .line 2051
    .line 2052
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 2053
    .line 2054
    if-eqz v0, :cond_5a

    .line 2055
    .line 2056
    const/4 v14, 0x1

    .line 2057
    iput-boolean v14, v2, Lretrofit2/RequestFactory$Builder;->h:Z

    .line 2058
    .line 2059
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2060
    .line 2061
    .line 2062
    move-result-object v0

    .line 2063
    invoke-virtual {v8, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 2064
    .line 2065
    .line 2066
    move-result v4

    .line 2067
    if-eqz v4, :cond_59

    .line 2068
    .line 2069
    invoke-static {v10, v0}, Lretrofit2/Utils;->f(Ljava/lang/reflect/Type;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 2070
    .line 2071
    .line 2072
    move-result-object v0

    .line 2073
    instance-of v4, v0, Ljava/lang/reflect/ParameterizedType;

    .line 2074
    .line 2075
    if-eqz v4, :cond_58

    .line 2076
    .line 2077
    check-cast v0, Ljava/lang/reflect/ParameterizedType;

    .line 2078
    .line 2079
    const/4 v8, 0x0

    .line 2080
    invoke-static {v8, v0}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 2081
    .line 2082
    .line 2083
    move-result-object v4

    .line 2084
    if-ne v5, v4, :cond_57

    .line 2085
    .line 2086
    invoke-static {v14, v0}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 2087
    .line 2088
    .line 2089
    move-result-object v0

    .line 2090
    invoke-static {v0}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2091
    .line 2092
    .line 2093
    move-result-object v4

    .line 2094
    invoke-virtual {v7, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 2095
    .line 2096
    .line 2097
    move-result v4

    .line 2098
    if-nez v4, :cond_56

    .line 2099
    .line 2100
    invoke-virtual {v6, v0, v11, v3}, Lretrofit2/Retrofit;->c(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 2101
    .line 2102
    .line 2103
    move-result-object v0

    .line 2104
    check-cast v9, Lretrofit2/http/PartMap;

    .line 2105
    .line 2106
    new-instance v4, Lretrofit2/ParameterHandler$PartMap;

    .line 2107
    .line 2108
    invoke-interface {v9}, Lretrofit2/http/PartMap;->encoding()Ljava/lang/String;

    .line 2109
    .line 2110
    .line 2111
    move-result-object v5

    .line 2112
    invoke-direct {v4, v1, v12, v0, v5}, Lretrofit2/ParameterHandler$PartMap;-><init>(Ljava/lang/reflect/Method;ILretrofit2/Converter;Ljava/lang/String;)V

    .line 2113
    .line 2114
    .line 2115
    goto/16 :goto_10

    .line 2116
    .line 2117
    :cond_56
    const-string v0, "@PartMap values cannot be MultipartBody.Part. Use @Part List<Part> or a different value type instead."

    .line 2118
    .line 2119
    const/4 v2, 0x0

    .line 2120
    new-array v2, v2, [Ljava/lang/Object;

    .line 2121
    .line 2122
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2123
    .line 2124
    .line 2125
    move-result-object v0

    .line 2126
    throw v0

    .line 2127
    :cond_57
    const/4 v2, 0x0

    .line 2128
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2129
    .line 2130
    const-string v3, "@PartMap keys must be of type String: "

    .line 2131
    .line 2132
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2133
    .line 2134
    .line 2135
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 2136
    .line 2137
    .line 2138
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 2139
    .line 2140
    .line 2141
    move-result-object v0

    .line 2142
    new-array v2, v2, [Ljava/lang/Object;

    .line 2143
    .line 2144
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2145
    .line 2146
    .line 2147
    move-result-object v0

    .line 2148
    throw v0

    .line 2149
    :cond_58
    const/4 v2, 0x0

    .line 2150
    new-array v0, v2, [Ljava/lang/Object;

    .line 2151
    .line 2152
    invoke-static {v1, v12, v13, v0}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2153
    .line 2154
    .line 2155
    move-result-object v0

    .line 2156
    throw v0

    .line 2157
    :cond_59
    const/4 v2, 0x0

    .line 2158
    const-string v0, "@PartMap parameter type must be Map."

    .line 2159
    .line 2160
    new-array v2, v2, [Ljava/lang/Object;

    .line 2161
    .line 2162
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2163
    .line 2164
    .line 2165
    move-result-object v0

    .line 2166
    throw v0

    .line 2167
    :cond_5a
    const/4 v2, 0x0

    .line 2168
    const-string v0, "@PartMap parameters can only be used with multipart encoding."

    .line 2169
    .line 2170
    new-array v2, v2, [Ljava/lang/Object;

    .line 2171
    .line 2172
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2173
    .line 2174
    .line 2175
    move-result-object v0

    .line 2176
    throw v0

    .line 2177
    :cond_5b
    instance-of v0, v9, Lretrofit2/http/Body;

    .line 2178
    .line 2179
    if-eqz v0, :cond_5e

    .line 2180
    .line 2181
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 2182
    .line 2183
    .line 2184
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 2185
    .line 2186
    if-nez v0, :cond_5d

    .line 2187
    .line 2188
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 2189
    .line 2190
    if-nez v0, :cond_5d

    .line 2191
    .line 2192
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->i:Z

    .line 2193
    .line 2194
    if-nez v0, :cond_5c

    .line 2195
    .line 2196
    :try_start_1
    invoke-virtual {v6, v10, v11, v3}, Lretrofit2/Retrofit;->c(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 2197
    .line 2198
    .line 2199
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 2200
    const/4 v14, 0x1

    .line 2201
    iput-boolean v14, v2, Lretrofit2/RequestFactory$Builder;->i:Z

    .line 2202
    .line 2203
    new-instance v4, Lretrofit2/ParameterHandler$Body;

    .line 2204
    .line 2205
    invoke-direct {v4, v1, v12, v0}, Lretrofit2/ParameterHandler$Body;-><init>(Ljava/lang/reflect/Method;ILretrofit2/Converter;)V

    .line 2206
    .line 2207
    .line 2208
    goto/16 :goto_10

    .line 2209
    .line 2210
    :catch_1
    move-exception v0

    .line 2211
    const-string v2, "Unable to create @Body converter for %s"

    .line 2212
    .line 2213
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 2214
    .line 2215
    .line 2216
    move-result-object v3

    .line 2217
    invoke-static {v1, v0, v12, v2, v3}, Lretrofit2/Utils;->k(Ljava/lang/reflect/Method;Ljava/lang/Exception;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2218
    .line 2219
    .line 2220
    move-result-object v0

    .line 2221
    throw v0

    .line 2222
    :cond_5c
    const-string v0, "Multiple @Body method annotations found."

    .line 2223
    .line 2224
    const/4 v2, 0x0

    .line 2225
    new-array v2, v2, [Ljava/lang/Object;

    .line 2226
    .line 2227
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2228
    .line 2229
    .line 2230
    move-result-object v0

    .line 2231
    throw v0

    .line 2232
    :cond_5d
    const/4 v2, 0x0

    .line 2233
    const-string v0, "@Body parameters cannot be used with form or multi-part encoding."

    .line 2234
    .line 2235
    new-array v2, v2, [Ljava/lang/Object;

    .line 2236
    .line 2237
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2238
    .line 2239
    .line 2240
    move-result-object v0

    .line 2241
    throw v0

    .line 2242
    :cond_5e
    instance-of v0, v9, Lretrofit2/http/Tag;

    .line 2243
    .line 2244
    if-eqz v0, :cond_62

    .line 2245
    .line 2246
    invoke-virtual {v2, v12, v10}, Lretrofit2/RequestFactory$Builder;->c(ILjava/lang/reflect/Type;)V

    .line 2247
    .line 2248
    .line 2249
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2250
    .line 2251
    .line 2252
    move-result-object v0

    .line 2253
    invoke-static {v0}, Lretrofit2/RequestFactory$Builder;->a(Ljava/lang/Class;)Ljava/lang/Class;

    .line 2254
    .line 2255
    .line 2256
    move-result-object v0

    .line 2257
    add-int/lit8 v4, v12, -0x1

    .line 2258
    .line 2259
    :goto_e
    if-ltz v4, :cond_61

    .line 2260
    .line 2261
    iget-object v5, v2, Lretrofit2/RequestFactory$Builder;->w:[Lretrofit2/ParameterHandler;

    .line 2262
    .line 2263
    aget-object v5, v5, v4

    .line 2264
    .line 2265
    instance-of v6, v5, Lretrofit2/ParameterHandler$Tag;

    .line 2266
    .line 2267
    if-eqz v6, :cond_60

    .line 2268
    .line 2269
    check-cast v5, Lretrofit2/ParameterHandler$Tag;

    .line 2270
    .line 2271
    iget-object v5, v5, Lretrofit2/ParameterHandler$Tag;->a:Ljava/lang/Class;

    .line 2272
    .line 2273
    invoke-virtual {v5, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 2274
    .line 2275
    .line 2276
    move-result v5

    .line 2277
    if-nez v5, :cond_5f

    .line 2278
    .line 2279
    goto :goto_f

    .line 2280
    :cond_5f
    new-instance v2, Ljava/lang/StringBuilder;

    .line 2281
    .line 2282
    const-string v3, "@Tag type "

    .line 2283
    .line 2284
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2285
    .line 2286
    .line 2287
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 2288
    .line 2289
    .line 2290
    move-result-object v0

    .line 2291
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2292
    .line 2293
    .line 2294
    const-string v0, " is duplicate of "

    .line 2295
    .line 2296
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2297
    .line 2298
    .line 2299
    sget-object v0, Lretrofit2/Platform;->b:Lretrofit2/Reflection;

    .line 2300
    .line 2301
    invoke-virtual {v0, v4, v1}, Lretrofit2/Reflection;->a(ILjava/lang/reflect/Method;)Ljava/lang/String;

    .line 2302
    .line 2303
    .line 2304
    move-result-object v0

    .line 2305
    const-string v3, " and would always overwrite its value."

    .line 2306
    .line 2307
    invoke-static {v2, v0, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 2308
    .line 2309
    .line 2310
    move-result-object v0

    .line 2311
    const/4 v2, 0x0

    .line 2312
    new-array v2, v2, [Ljava/lang/Object;

    .line 2313
    .line 2314
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2315
    .line 2316
    .line 2317
    move-result-object v0

    .line 2318
    throw v0

    .line 2319
    :cond_60
    :goto_f
    add-int/lit8 v4, v4, -0x1

    .line 2320
    .line 2321
    goto :goto_e

    .line 2322
    :cond_61
    new-instance v4, Lretrofit2/ParameterHandler$Tag;

    .line 2323
    .line 2324
    invoke-direct {v4, v0}, Lretrofit2/ParameterHandler$Tag;-><init>(Ljava/lang/Class;)V

    .line 2325
    .line 2326
    .line 2327
    goto :goto_10

    .line 2328
    :cond_62
    const/4 v4, 0x0

    .line 2329
    :goto_10
    if-nez v4, :cond_63

    .line 2330
    .line 2331
    goto :goto_11

    .line 2332
    :cond_63
    if-nez v17, :cond_64

    .line 2333
    .line 2334
    move-object/from16 v17, v4

    .line 2335
    .line 2336
    :goto_11
    add-int/lit8 v15, v22, 0x1

    .line 2337
    .line 2338
    move-object/from16 v0, p0

    .line 2339
    .line 2340
    move-object v13, v11

    .line 2341
    move-object/from16 v4, v18

    .line 2342
    .line 2343
    move/from16 v6, v19

    .line 2344
    .line 2345
    move/from16 v14, v21

    .line 2346
    .line 2347
    move/from16 v8, v23

    .line 2348
    .line 2349
    move-object/from16 v7, v24

    .line 2350
    .line 2351
    const/4 v5, 0x0

    .line 2352
    const/4 v9, 0x0

    .line 2353
    move-object v11, v10

    .line 2354
    move-object/from16 v10, v20

    .line 2355
    .line 2356
    goto/16 :goto_7

    .line 2357
    .line 2358
    :cond_64
    const-string v0, "Multiple Retrofit annotations found, only one allowed."

    .line 2359
    .line 2360
    const/4 v2, 0x0

    .line 2361
    new-array v2, v2, [Ljava/lang/Object;

    .line 2362
    .line 2363
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2364
    .line 2365
    .line 2366
    move-result-object v0

    .line 2367
    throw v0

    .line 2368
    :cond_65
    :goto_12
    move-object/from16 v18, v4

    .line 2369
    .line 2370
    move/from16 v19, v6

    .line 2371
    .line 2372
    move-object/from16 v24, v7

    .line 2373
    .line 2374
    move/from16 v23, v8

    .line 2375
    .line 2376
    move-object/from16 v20, v10

    .line 2377
    .line 2378
    move-object v10, v11

    .line 2379
    goto :goto_13

    .line 2380
    :cond_66
    const/16 v17, 0x0

    .line 2381
    .line 2382
    goto :goto_12

    .line 2383
    :goto_13
    if-nez v17, :cond_68

    .line 2384
    .line 2385
    if-eqz v16, :cond_67

    .line 2386
    .line 2387
    :try_start_2
    invoke-static {v10}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2388
    .line 2389
    .line 2390
    move-result-object v0

    .line 2391
    const-class v4, Lkotlin/coroutines/Continuation;

    .line 2392
    .line 2393
    if-ne v0, v4, :cond_67

    .line 2394
    .line 2395
    const/4 v14, 0x1

    .line 2396
    iput-boolean v14, v2, Lretrofit2/RequestFactory$Builder;->x:Z
    :try_end_2
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_2 .. :try_end_2} :catch_2

    .line 2397
    .line 2398
    const/16 v17, 0x0

    .line 2399
    .line 2400
    goto :goto_14

    .line 2401
    :catch_2
    :cond_67
    const-string v0, "No Retrofit annotation found."

    .line 2402
    .line 2403
    const/4 v2, 0x0

    .line 2404
    new-array v2, v2, [Ljava/lang/Object;

    .line 2405
    .line 2406
    invoke-static {v1, v12, v0, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2407
    .line 2408
    .line 2409
    move-result-object v0

    .line 2410
    throw v0

    .line 2411
    :cond_68
    :goto_14
    aput-object v17, v20, v12

    .line 2412
    .line 2413
    add-int/lit8 v12, v12, 0x1

    .line 2414
    .line 2415
    move-object/from16 v0, p0

    .line 2416
    .line 2417
    move-object/from16 v4, v18

    .line 2418
    .line 2419
    move/from16 v6, v19

    .line 2420
    .line 2421
    move/from16 v8, v23

    .line 2422
    .line 2423
    move-object/from16 v7, v24

    .line 2424
    .line 2425
    const/4 v5, 0x0

    .line 2426
    const/4 v9, 0x0

    .line 2427
    goto/16 :goto_5

    .line 2428
    .line 2429
    :cond_69
    move-object/from16 v24, v7

    .line 2430
    .line 2431
    iget-object v0, v2, Lretrofit2/RequestFactory$Builder;->s:Ljava/lang/String;

    .line 2432
    .line 2433
    if-nez v0, :cond_6b

    .line 2434
    .line 2435
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->n:Z

    .line 2436
    .line 2437
    if-eqz v0, :cond_6a

    .line 2438
    .line 2439
    goto :goto_15

    .line 2440
    :cond_6a
    iget-object v0, v2, Lretrofit2/RequestFactory$Builder;->o:Ljava/lang/String;

    .line 2441
    .line 2442
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 2443
    .line 2444
    .line 2445
    move-result-object v0

    .line 2446
    const-string v2, "Missing either @%s URL or @Url parameter."

    .line 2447
    .line 2448
    const/4 v3, 0x0

    .line 2449
    invoke-static {v1, v3, v2, v0}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2450
    .line 2451
    .line 2452
    move-result-object v0

    .line 2453
    throw v0

    .line 2454
    :cond_6b
    :goto_15
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 2455
    .line 2456
    if-nez v0, :cond_6c

    .line 2457
    .line 2458
    iget-boolean v3, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 2459
    .line 2460
    if-nez v3, :cond_6c

    .line 2461
    .line 2462
    iget-boolean v3, v2, Lretrofit2/RequestFactory$Builder;->p:Z

    .line 2463
    .line 2464
    if-nez v3, :cond_6c

    .line 2465
    .line 2466
    iget-boolean v3, v2, Lretrofit2/RequestFactory$Builder;->i:Z

    .line 2467
    .line 2468
    if-nez v3, :cond_6d

    .line 2469
    .line 2470
    :cond_6c
    const/4 v3, 0x0

    .line 2471
    const/4 v8, 0x0

    .line 2472
    goto :goto_16

    .line 2473
    :cond_6d
    const-string v0, "Non-body HTTP method cannot contain @Body."

    .line 2474
    .line 2475
    const/4 v8, 0x0

    .line 2476
    new-array v2, v8, [Ljava/lang/Object;

    .line 2477
    .line 2478
    const/4 v3, 0x0

    .line 2479
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2480
    .line 2481
    .line 2482
    move-result-object v0

    .line 2483
    throw v0

    .line 2484
    :goto_16
    if-eqz v0, :cond_6f

    .line 2485
    .line 2486
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->g:Z

    .line 2487
    .line 2488
    if-eqz v0, :cond_6e

    .line 2489
    .line 2490
    goto :goto_17

    .line 2491
    :cond_6e
    const-string v0, "Form-encoded method must contain at least one @Field."

    .line 2492
    .line 2493
    new-array v2, v8, [Ljava/lang/Object;

    .line 2494
    .line 2495
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2496
    .line 2497
    .line 2498
    move-result-object v0

    .line 2499
    throw v0

    .line 2500
    :cond_6f
    :goto_17
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 2501
    .line 2502
    if-eqz v0, :cond_71

    .line 2503
    .line 2504
    iget-boolean v0, v2, Lretrofit2/RequestFactory$Builder;->h:Z

    .line 2505
    .line 2506
    if-eqz v0, :cond_70

    .line 2507
    .line 2508
    goto :goto_18

    .line 2509
    :cond_70
    const-string v0, "Multipart method must contain at least one @Part."

    .line 2510
    .line 2511
    new-array v2, v8, [Ljava/lang/Object;

    .line 2512
    .line 2513
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2514
    .line 2515
    .line 2516
    move-result-object v0

    .line 2517
    throw v0

    .line 2518
    :cond_71
    :goto_18
    new-instance v0, Lretrofit2/RequestFactory;

    .line 2519
    .line 2520
    invoke-direct {v0, v2}, Lretrofit2/RequestFactory;-><init>(Lretrofit2/RequestFactory$Builder;)V

    .line 2521
    .line 2522
    .line 2523
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getGenericReturnType()Ljava/lang/reflect/Type;

    .line 2524
    .line 2525
    .line 2526
    move-result-object v2

    .line 2527
    invoke-static {v2}, Lretrofit2/Utils;->g(Ljava/lang/reflect/Type;)Z

    .line 2528
    .line 2529
    .line 2530
    move-result v3

    .line 2531
    if-nez v3, :cond_7f

    .line 2532
    .line 2533
    sget-object v3, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    .line 2534
    .line 2535
    if-eq v2, v3, :cond_7e

    .line 2536
    .line 2537
    invoke-virtual {v1}, Ljava/lang/reflect/AccessibleObject;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 2538
    .line 2539
    .line 2540
    move-result-object v2

    .line 2541
    const-class v3, Llx0/b0;

    .line 2542
    .line 2543
    const-class v4, Lretrofit2/Response;

    .line 2544
    .line 2545
    iget-boolean v5, v0, Lretrofit2/RequestFactory;->l:Z

    .line 2546
    .line 2547
    if-eqz v5, :cond_77

    .line 2548
    .line 2549
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    .line 2550
    .line 2551
    .line 2552
    move-result-object v6

    .line 2553
    array-length v7, v6

    .line 2554
    const/4 v14, 0x1

    .line 2555
    sub-int/2addr v7, v14

    .line 2556
    aget-object v6, v6, v7

    .line 2557
    .line 2558
    check-cast v6, Ljava/lang/reflect/ParameterizedType;

    .line 2559
    .line 2560
    invoke-interface {v6}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 2561
    .line 2562
    .line 2563
    move-result-object v6

    .line 2564
    const/4 v8, 0x0

    .line 2565
    aget-object v6, v6, v8

    .line 2566
    .line 2567
    instance-of v7, v6, Ljava/lang/reflect/WildcardType;

    .line 2568
    .line 2569
    if-eqz v7, :cond_72

    .line 2570
    .line 2571
    check-cast v6, Ljava/lang/reflect/WildcardType;

    .line 2572
    .line 2573
    invoke-interface {v6}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    .line 2574
    .line 2575
    .line 2576
    move-result-object v6

    .line 2577
    aget-object v6, v6, v8

    .line 2578
    .line 2579
    :cond_72
    invoke-static {v6}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2580
    .line 2581
    .line 2582
    move-result-object v7

    .line 2583
    const-class v9, Lretrofit2/Call;

    .line 2584
    .line 2585
    if-ne v7, v4, :cond_73

    .line 2586
    .line 2587
    instance-of v7, v6, Ljava/lang/reflect/ParameterizedType;

    .line 2588
    .line 2589
    if-eqz v7, :cond_73

    .line 2590
    .line 2591
    check-cast v6, Ljava/lang/reflect/ParameterizedType;

    .line 2592
    .line 2593
    invoke-static {v8, v6}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 2594
    .line 2595
    .line 2596
    move-result-object v6

    .line 2597
    const/4 v7, 0x1

    .line 2598
    const/4 v8, 0x0

    .line 2599
    goto :goto_1a

    .line 2600
    :cond_73
    invoke-static {v6}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2601
    .line 2602
    .line 2603
    move-result-object v7

    .line 2604
    if-eq v7, v9, :cond_76

    .line 2605
    .line 2606
    sget-boolean v7, Lretrofit2/Utils;->b:Z

    .line 2607
    .line 2608
    if-eqz v7, :cond_74

    .line 2609
    .line 2610
    if-ne v6, v3, :cond_74

    .line 2611
    .line 2612
    const/4 v7, 0x1

    .line 2613
    goto :goto_19

    .line 2614
    :cond_74
    const/4 v7, 0x0

    .line 2615
    :goto_19
    move v8, v7

    .line 2616
    const/4 v7, 0x0

    .line 2617
    :goto_1a
    new-instance v10, Lretrofit2/Utils$ParameterizedTypeImpl;

    .line 2618
    .line 2619
    const/4 v14, 0x1

    .line 2620
    new-array v11, v14, [Ljava/lang/reflect/Type;

    .line 2621
    .line 2622
    const/4 v12, 0x0

    .line 2623
    aput-object v6, v11, v12

    .line 2624
    .line 2625
    const/4 v6, 0x0

    .line 2626
    invoke-direct {v10, v6, v9, v11}, Lretrofit2/Utils$ParameterizedTypeImpl;-><init>(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V

    .line 2627
    .line 2628
    .line 2629
    sget-object v6, Lretrofit2/SkipCallbackExecutorImpl;->a:Lretrofit2/SkipCallbackExecutor;

    .line 2630
    .line 2631
    const-class v6, Lretrofit2/SkipCallbackExecutor;

    .line 2632
    .line 2633
    invoke-static {v2, v6}, Lretrofit2/Utils;->h([Ljava/lang/annotation/Annotation;Ljava/lang/Class;)Z

    .line 2634
    .line 2635
    .line 2636
    move-result v6

    .line 2637
    if-eqz v6, :cond_75

    .line 2638
    .line 2639
    goto :goto_1b

    .line 2640
    :cond_75
    array-length v6, v2

    .line 2641
    add-int/2addr v6, v14

    .line 2642
    new-array v6, v6, [Ljava/lang/annotation/Annotation;

    .line 2643
    .line 2644
    sget-object v9, Lretrofit2/SkipCallbackExecutorImpl;->a:Lretrofit2/SkipCallbackExecutor;

    .line 2645
    .line 2646
    aput-object v9, v6, v12

    .line 2647
    .line 2648
    array-length v9, v2

    .line 2649
    invoke-static {v2, v12, v6, v14, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 2650
    .line 2651
    .line 2652
    move-object v2, v6

    .line 2653
    :goto_1b
    move v6, v8

    .line 2654
    :goto_1c
    move-object/from16 v8, p0

    .line 2655
    .line 2656
    goto :goto_1d

    .line 2657
    :cond_76
    const/4 v12, 0x0

    .line 2658
    check-cast v6, Ljava/lang/reflect/ParameterizedType;

    .line 2659
    .line 2660
    invoke-static {v12, v6}, Lretrofit2/Utils;->d(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 2661
    .line 2662
    .line 2663
    move-result-object v0

    .line 2664
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 2665
    .line 2666
    .line 2667
    move-result-object v0

    .line 2668
    const-string v2, "Suspend functions should not return Call, as they already execute asynchronously.\nChange its return type to %s"

    .line 2669
    .line 2670
    const/4 v3, 0x0

    .line 2671
    invoke-static {v1, v3, v2, v0}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2672
    .line 2673
    .line 2674
    move-result-object v0

    .line 2675
    throw v0

    .line 2676
    :cond_77
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getGenericReturnType()Ljava/lang/reflect/Type;

    .line 2677
    .line 2678
    .line 2679
    move-result-object v10

    .line 2680
    const/4 v6, 0x0

    .line 2681
    const/4 v7, 0x0

    .line 2682
    goto :goto_1c

    .line 2683
    :goto_1d
    :try_start_3
    invoke-virtual {v8, v10, v2}, Lretrofit2/Retrofit;->a(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/CallAdapter;

    .line 2684
    .line 2685
    .line 2686
    move-result-object v2
    :try_end_3
    .catch Ljava/lang/RuntimeException; {:try_start_3 .. :try_end_3} :catch_4

    .line 2687
    invoke-interface {v2}, Lretrofit2/CallAdapter;->d()Ljava/lang/reflect/Type;

    .line 2688
    .line 2689
    .line 2690
    move-result-object v9

    .line 2691
    const-class v10, Ld01/t0;

    .line 2692
    .line 2693
    if-eq v9, v10, :cond_7d

    .line 2694
    .line 2695
    if-eq v9, v4, :cond_7c

    .line 2696
    .line 2697
    iget-object v4, v0, Lretrofit2/RequestFactory;->d:Ljava/lang/String;

    .line 2698
    .line 2699
    move-object/from16 v10, v24

    .line 2700
    .line 2701
    invoke-virtual {v4, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2702
    .line 2703
    .line 2704
    move-result v4

    .line 2705
    if-eqz v4, :cond_79

    .line 2706
    .line 2707
    const-class v4, Ljava/lang/Void;

    .line 2708
    .line 2709
    invoke-virtual {v4, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 2710
    .line 2711
    .line 2712
    move-result v4

    .line 2713
    if-nez v4, :cond_79

    .line 2714
    .line 2715
    sget-boolean v4, Lretrofit2/Utils;->b:Z

    .line 2716
    .line 2717
    if-eqz v4, :cond_78

    .line 2718
    .line 2719
    if-ne v9, v3, :cond_78

    .line 2720
    .line 2721
    goto :goto_1e

    .line 2722
    :cond_78
    const-string v0, "HEAD method must use Void or Unit as response type."

    .line 2723
    .line 2724
    const/4 v2, 0x0

    .line 2725
    new-array v2, v2, [Ljava/lang/Object;

    .line 2726
    .line 2727
    const/4 v3, 0x0

    .line 2728
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2729
    .line 2730
    .line 2731
    move-result-object v0

    .line 2732
    throw v0

    .line 2733
    :cond_79
    :goto_1e
    invoke-virtual {v1}, Ljava/lang/reflect/AccessibleObject;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 2734
    .line 2735
    .line 2736
    move-result-object v3

    .line 2737
    :try_start_4
    invoke-virtual {v8, v9, v3}, Lretrofit2/Retrofit;->d(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 2738
    .line 2739
    .line 2740
    move-result-object v4
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_3

    .line 2741
    iget-object v3, v8, Lretrofit2/Retrofit;->b:Ld01/i;

    .line 2742
    .line 2743
    if-nez v5, :cond_7a

    .line 2744
    .line 2745
    new-instance v1, Lretrofit2/HttpServiceMethod$CallAdapted;

    .line 2746
    .line 2747
    invoke-direct {v1, v0, v3, v4, v2}, Lretrofit2/HttpServiceMethod$CallAdapted;-><init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;Lretrofit2/CallAdapter;)V

    .line 2748
    .line 2749
    .line 2750
    return-object v1

    .line 2751
    :cond_7a
    if-eqz v7, :cond_7b

    .line 2752
    .line 2753
    new-instance v1, Lretrofit2/HttpServiceMethod$SuspendForResponse;

    .line 2754
    .line 2755
    invoke-direct {v1, v0, v3, v4, v2}, Lretrofit2/HttpServiceMethod$SuspendForResponse;-><init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;Lretrofit2/CallAdapter;)V

    .line 2756
    .line 2757
    .line 2758
    return-object v1

    .line 2759
    :cond_7b
    new-instance v1, Lretrofit2/HttpServiceMethod$SuspendForBody;

    .line 2760
    .line 2761
    move-object v5, v2

    .line 2762
    move-object v2, v0

    .line 2763
    invoke-direct/range {v1 .. v6}, Lretrofit2/HttpServiceMethod$SuspendForBody;-><init>(Lretrofit2/RequestFactory;Ld01/i;Lretrofit2/Converter;Lretrofit2/CallAdapter;Z)V

    .line 2764
    .line 2765
    .line 2766
    return-object v1

    .line 2767
    :catch_3
    move-exception v0

    .line 2768
    const-string v2, "Unable to create converter for %s"

    .line 2769
    .line 2770
    filled-new-array {v9}, [Ljava/lang/Object;

    .line 2771
    .line 2772
    .line 2773
    move-result-object v3

    .line 2774
    invoke-static {v1, v0, v2, v3}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2775
    .line 2776
    .line 2777
    move-result-object v0

    .line 2778
    throw v0

    .line 2779
    :cond_7c
    const-string v0, "Response must include generic type (e.g., Response<String>)"

    .line 2780
    .line 2781
    const/4 v2, 0x0

    .line 2782
    new-array v2, v2, [Ljava/lang/Object;

    .line 2783
    .line 2784
    const/4 v3, 0x0

    .line 2785
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2786
    .line 2787
    .line 2788
    move-result-object v0

    .line 2789
    throw v0

    .line 2790
    :cond_7d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2791
    .line 2792
    const-string v2, "\'"

    .line 2793
    .line 2794
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2795
    .line 2796
    .line 2797
    invoke-static {v9}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2798
    .line 2799
    .line 2800
    move-result-object v2

    .line 2801
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 2802
    .line 2803
    .line 2804
    move-result-object v2

    .line 2805
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2806
    .line 2807
    .line 2808
    const-string v2, "\' is not a valid response body type. Did you mean ResponseBody?"

    .line 2809
    .line 2810
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2811
    .line 2812
    .line 2813
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 2814
    .line 2815
    .line 2816
    move-result-object v0

    .line 2817
    const/4 v2, 0x0

    .line 2818
    new-array v2, v2, [Ljava/lang/Object;

    .line 2819
    .line 2820
    const/4 v3, 0x0

    .line 2821
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2822
    .line 2823
    .line 2824
    move-result-object v0

    .line 2825
    throw v0

    .line 2826
    :catch_4
    move-exception v0

    .line 2827
    const-string v2, "Unable to create call adapter for %s"

    .line 2828
    .line 2829
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 2830
    .line 2831
    .line 2832
    move-result-object v3

    .line 2833
    invoke-static {v1, v0, v2, v3}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2834
    .line 2835
    .line 2836
    move-result-object v0

    .line 2837
    throw v0

    .line 2838
    :cond_7e
    const/4 v2, 0x0

    .line 2839
    const/4 v3, 0x0

    .line 2840
    const-string v0, "Service methods cannot return void."

    .line 2841
    .line 2842
    new-array v2, v2, [Ljava/lang/Object;

    .line 2843
    .line 2844
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2845
    .line 2846
    .line 2847
    move-result-object v0

    .line 2848
    throw v0

    .line 2849
    :cond_7f
    const/4 v3, 0x0

    .line 2850
    const-string v0, "Method return type must not include a type variable or wildcard: %s"

    .line 2851
    .line 2852
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 2853
    .line 2854
    .line 2855
    move-result-object v2

    .line 2856
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2857
    .line 2858
    .line 2859
    move-result-object v0

    .line 2860
    throw v0

    .line 2861
    :cond_80
    move v2, v5

    .line 2862
    move-object v3, v9

    .line 2863
    const-string v0, "HTTP method annotation is required (e.g., @GET, @POST, etc.)."

    .line 2864
    .line 2865
    new-array v2, v2, [Ljava/lang/Object;

    .line 2866
    .line 2867
    invoke-static {v1, v3, v0, v2}, Lretrofit2/Utils;->i(Ljava/lang/reflect/Method;Ljava/lang/Exception;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 2868
    .line 2869
    .line 2870
    move-result-object v0

    .line 2871
    throw v0
.end method


# virtual methods
.method public abstract a(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
.end method
