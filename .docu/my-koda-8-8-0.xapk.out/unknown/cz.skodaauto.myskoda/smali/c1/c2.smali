.class public final synthetic Lc1/c2;
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
    iput p1, p0, Lc1/c2;->d:I

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lc1/c2;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Lhi/a;

    .line 11
    .line 12
    const-string v1, "$this$single"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Ldg/f;

    .line 18
    .line 19
    new-instance v2, Lag/c;

    .line 20
    .line 21
    const-class v3, Lretrofit2/Retrofit;

    .line 22
    .line 23
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 24
    .line 25
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v0, Lii/a;

    .line 30
    .line 31
    invoke-virtual {v0, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lretrofit2/Retrofit;

    .line 36
    .line 37
    const-class v3, Lfg/d;

    .line 38
    .line 39
    invoke-virtual {v0, v3}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    const-string v0, "create(...)"

    .line 44
    .line 45
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const/4 v8, 0x0

    .line 49
    const/4 v9, 0x6

    .line 50
    const/4 v3, 0x2

    .line 51
    const-class v5, Lfg/d;

    .line 52
    .line 53
    const-string v6, "postEvseIdLookup"

    .line 54
    .line 55
    const-string v7, "postEvseIdLookup(Lcariad/charging/multicharge/kitten/remoteauthorization/models/HeadlessEvseIdLookupRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 56
    .line 57
    invoke-direct/range {v2 .. v9}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 58
    .line 59
    .line 60
    invoke-direct {v1, v2}, Ldg/f;-><init>(Lag/c;)V

    .line 61
    .line 62
    .line 63
    return-object v1

    .line 64
    :pswitch_0
    move-object/from16 v0, p1

    .line 65
    .line 66
    check-cast v0, Lhi/a;

    .line 67
    .line 68
    const-string v1, "$this$single"

    .line 69
    .line 70
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-class v1, Lretrofit2/Retrofit;

    .line 74
    .line 75
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 76
    .line 77
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    check-cast v0, Lii/a;

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    check-cast v0, Lretrofit2/Retrofit;

    .line 88
    .line 89
    const-class v1, Lfg/d;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    check-cast v0, Lfg/d;

    .line 96
    .line 97
    new-instance v1, Lfg/c;

    .line 98
    .line 99
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    invoke-direct {v1, v0}, Lfg/c;-><init>(Lfg/d;)V

    .line 103
    .line 104
    .line 105
    return-object v1

    .line 106
    :pswitch_1
    move-object/from16 v0, p1

    .line 107
    .line 108
    check-cast v0, Lhi/c;

    .line 109
    .line 110
    const-string v1, "$this$module"

    .line 111
    .line 112
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    new-instance v1, Lc1/c2;

    .line 116
    .line 117
    const/16 v2, 0x1c

    .line 118
    .line 119
    invoke-direct {v1, v2}, Lc1/c2;-><init>(I)V

    .line 120
    .line 121
    .line 122
    new-instance v2, Lii/b;

    .line 123
    .line 124
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 125
    .line 126
    const-class v4, Lfg/c;

    .line 127
    .line 128
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    const/4 v5, 0x0

    .line 133
    invoke-direct {v2, v5, v1, v4}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 134
    .line 135
    .line 136
    iget-object v0, v0, Lhi/c;->a:Ljava/util/ArrayList;

    .line 137
    .line 138
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    new-instance v1, Lc1/c2;

    .line 142
    .line 143
    const/16 v2, 0x1d

    .line 144
    .line 145
    invoke-direct {v1, v2}, Lc1/c2;-><init>(I)V

    .line 146
    .line 147
    .line 148
    new-instance v2, Lii/b;

    .line 149
    .line 150
    const-class v4, Lkj/c;

    .line 151
    .line 152
    invoke-virtual {v3, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-direct {v2, v5, v1, v3}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    return-object v0

    .line 165
    :pswitch_2
    move-object/from16 v0, p1

    .line 166
    .line 167
    check-cast v0, Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;

    .line 168
    .line 169
    const-string v1, "$this$request"

    .line 170
    .line 171
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;->getTitle()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;->getText()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    invoke-virtual {v0}, Lcz/myskoda/api/bff_consents/v2/LoyaltyProgramConsentDto;->getConsented()Z

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    new-instance v3, Lfe0/a;

    .line 187
    .line 188
    invoke-direct {v3, v0, v1, v2}, Lfe0/a;-><init>(ZLjava/lang/String;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    return-object v3

    .line 192
    :pswitch_3
    move-object/from16 v0, p1

    .line 193
    .line 194
    check-cast v0, Llx0/l;

    .line 195
    .line 196
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v0, Ljava/lang/Boolean;

    .line 199
    .line 200
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 201
    .line 202
    .line 203
    return-object v0

    .line 204
    :pswitch_4
    move-object/from16 v0, p1

    .line 205
    .line 206
    check-cast v0, Llx0/l;

    .line 207
    .line 208
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast v1, Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 213
    .line 214
    .line 215
    move-result v1

    .line 216
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v0, Ljava/lang/Boolean;

    .line 219
    .line 220
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    if-eqz v1, :cond_0

    .line 225
    .line 226
    if-nez v0, :cond_0

    .line 227
    .line 228
    const/4 v0, 0x1

    .line 229
    goto :goto_0

    .line 230
    :cond_0
    const/4 v0, 0x0

    .line 231
    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    return-object v0

    .line 236
    :pswitch_5
    move-object/from16 v0, p1

    .line 237
    .line 238
    check-cast v0, Lz9/u;

    .line 239
    .line 240
    const-string v1, "it"

    .line 241
    .line 242
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 246
    .line 247
    iget v0, v0, Lca/j;->a:I

    .line 248
    .line 249
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    return-object v0

    .line 254
    :pswitch_6
    move-object/from16 v0, p1

    .line 255
    .line 256
    check-cast v0, Lz9/u;

    .line 257
    .line 258
    const-string v1, "destination"

    .line 259
    .line 260
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    iget-object v1, v0, Lz9/u;->f:Lz9/v;

    .line 264
    .line 265
    if-eqz v1, :cond_1

    .line 266
    .line 267
    iget-object v2, v1, Lz9/v;->i:Lca/m;

    .line 268
    .line 269
    iget v2, v2, Lca/m;->d:I

    .line 270
    .line 271
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 272
    .line 273
    iget v0, v0, Lca/j;->a:I

    .line 274
    .line 275
    if-ne v2, v0, :cond_1

    .line 276
    .line 277
    goto :goto_1

    .line 278
    :cond_1
    const/4 v1, 0x0

    .line 279
    :goto_1
    return-object v1

    .line 280
    :pswitch_7
    move-object/from16 v0, p1

    .line 281
    .line 282
    check-cast v0, Lz9/u;

    .line 283
    .line 284
    const-string v1, "destination"

    .line 285
    .line 286
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    iget-object v1, v0, Lz9/u;->f:Lz9/v;

    .line 290
    .line 291
    if-eqz v1, :cond_2

    .line 292
    .line 293
    iget-object v2, v1, Lz9/v;->i:Lca/m;

    .line 294
    .line 295
    iget v2, v2, Lca/m;->d:I

    .line 296
    .line 297
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 298
    .line 299
    iget v0, v0, Lca/j;->a:I

    .line 300
    .line 301
    if-ne v2, v0, :cond_2

    .line 302
    .line 303
    goto :goto_2

    .line 304
    :cond_2
    const/4 v1, 0x0

    .line 305
    :goto_2
    return-object v1

    .line 306
    :pswitch_8
    move-object/from16 v0, p1

    .line 307
    .line 308
    check-cast v0, Lz9/c0;

    .line 309
    .line 310
    const-string v1, "$this$navOptions"

    .line 311
    .line 312
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    const/4 v1, 0x1

    .line 316
    iput-boolean v1, v0, Lz9/c0;->c:Z

    .line 317
    .line 318
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 319
    .line 320
    return-object v0

    .line 321
    :pswitch_9
    move-object/from16 v0, p1

    .line 322
    .line 323
    check-cast v0, Lp7/c;

    .line 324
    .line 325
    const-string v1, "$this$initializer"

    .line 326
    .line 327
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    new-instance v1, Lca/b;

    .line 331
    .line 332
    invoke-static {v0}, Landroidx/lifecycle/v0;->b(Lp7/c;)Landroidx/lifecycle/s0;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    invoke-direct {v1, v0}, Lca/b;-><init>(Landroidx/lifecycle/s0;)V

    .line 337
    .line 338
    .line 339
    return-object v1

    .line 340
    :pswitch_a
    move-object/from16 v0, p1

    .line 341
    .line 342
    check-cast v0, Lp31/c;

    .line 343
    .line 344
    const-string v1, "it"

    .line 345
    .line 346
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    iget-object v0, v0, Lp31/c;->a:Ljava/lang/String;

    .line 350
    .line 351
    return-object v0

    .line 352
    :pswitch_b
    move-object/from16 v0, p1

    .line 353
    .line 354
    check-cast v0, Ll4/i;

    .line 355
    .line 356
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 357
    .line 358
    return-object v0

    .line 359
    :pswitch_c
    move-object/from16 v0, p1

    .line 360
    .line 361
    check-cast v0, Ljava/util/List;

    .line 362
    .line 363
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 364
    .line 365
    return-object v0

    .line 366
    :pswitch_d
    move-object/from16 v0, p1

    .line 367
    .line 368
    check-cast v0, Lcz/myskoda/api/bff_dealers/v2/DealerDto;

    .line 369
    .line 370
    const-string v1, "$this$request"

    .line 371
    .line 372
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getId()Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v3

    .line 379
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getName()Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v4

    .line 383
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getLocation()Lcz/myskoda/api/bff_dealers/v2/DealerGpsCoordinatesDto;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    new-instance v5, Lcq0/t;

    .line 388
    .line 389
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerGpsCoordinatesDto;->getLatitude()D

    .line 390
    .line 391
    .line 392
    move-result-wide v6

    .line 393
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerGpsCoordinatesDto;->getLongitude()D

    .line 394
    .line 395
    .line 396
    move-result-wide v1

    .line 397
    invoke-direct {v5, v6, v7, v1, v2}, Lcq0/t;-><init>(DD)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getContact()Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;

    .line 401
    .line 402
    .line 403
    move-result-object v1

    .line 404
    const/4 v2, 0x0

    .line 405
    if-eqz v1, :cond_3

    .line 406
    .line 407
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;->getPhone()Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    move-object v7, v1

    .line 412
    goto :goto_3

    .line 413
    :cond_3
    move-object v7, v2

    .line 414
    :goto_3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getContact()Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;

    .line 415
    .line 416
    .line 417
    move-result-object v1

    .line 418
    if-eqz v1, :cond_4

    .line 419
    .line 420
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;->getUrl()Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v1

    .line 424
    move-object v8, v1

    .line 425
    goto :goto_4

    .line 426
    :cond_4
    move-object v8, v2

    .line 427
    :goto_4
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getContact()Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    if-eqz v1, :cond_5

    .line 432
    .line 433
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerContactDto;->getEmail()Ljava/lang/String;

    .line 434
    .line 435
    .line 436
    move-result-object v2

    .line 437
    :cond_5
    move-object v9, v2

    .line 438
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getAddress()Lcz/myskoda/api/bff_dealers/v2/DealerAddressDto;

    .line 439
    .line 440
    .line 441
    move-result-object v1

    .line 442
    new-instance v6, Lcq0/h;

    .line 443
    .line 444
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerAddressDto;->getStreet()Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerAddressDto;->getCity()Ljava/lang/String;

    .line 449
    .line 450
    .line 451
    move-result-object v10

    .line 452
    invoke-virtual {v1}, Lcz/myskoda/api/bff_dealers/v2/DealerAddressDto;->getZipCode()Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v1

    .line 456
    invoke-direct {v6, v2, v10, v1}, Lcq0/h;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {v0}, Lcz/myskoda/api/bff_dealers/v2/DealerDto;->getOpeningHours()Ljava/util/List;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    if-eqz v0, :cond_8

    .line 464
    .line 465
    check-cast v0, Ljava/lang/Iterable;

    .line 466
    .line 467
    new-instance v1, Ljava/util/ArrayList;

    .line 468
    .line 469
    const/16 v2, 0xa

    .line 470
    .line 471
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 472
    .line 473
    .line 474
    move-result v10

    .line 475
    invoke-direct {v1, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 476
    .line 477
    .line 478
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 479
    .line 480
    .line 481
    move-result-object v0

    .line 482
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 483
    .line 484
    .line 485
    move-result v10

    .line 486
    if-eqz v10, :cond_7

    .line 487
    .line 488
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v10

    .line 492
    check-cast v10, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningHoursDto;

    .line 493
    .line 494
    invoke-virtual {v10}, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningHoursDto;->getPeriodStart()Ljava/lang/String;

    .line 495
    .line 496
    .line 497
    move-result-object v11

    .line 498
    invoke-static {v11}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 499
    .line 500
    .line 501
    move-result-object v11

    .line 502
    invoke-virtual {v10}, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningHoursDto;->getPeriodEnd()Ljava/lang/String;

    .line 503
    .line 504
    .line 505
    move-result-object v12

    .line 506
    invoke-static {v12}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 507
    .line 508
    .line 509
    move-result-object v12

    .line 510
    invoke-virtual {v10}, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningHoursDto;->getOpeningTimes()Ljava/util/List;

    .line 511
    .line 512
    .line 513
    move-result-object v10

    .line 514
    check-cast v10, Ljava/lang/Iterable;

    .line 515
    .line 516
    new-instance v13, Ljava/util/ArrayList;

    .line 517
    .line 518
    invoke-static {v10, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 519
    .line 520
    .line 521
    move-result v14

    .line 522
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 523
    .line 524
    .line 525
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 526
    .line 527
    .line 528
    move-result-object v10

    .line 529
    :goto_6
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 530
    .line 531
    .line 532
    move-result v14

    .line 533
    if-eqz v14, :cond_6

    .line 534
    .line 535
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 536
    .line 537
    .line 538
    move-result-object v14

    .line 539
    check-cast v14, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningTimesDto;

    .line 540
    .line 541
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 542
    .line 543
    .line 544
    move-result-object v15

    .line 545
    invoke-virtual {v15}, Ljava/time/OffsetDateTime;->getOffset()Ljava/time/ZoneOffset;

    .line 546
    .line 547
    .line 548
    move-result-object v15

    .line 549
    const-string v2, "getOffset(...)"

    .line 550
    .line 551
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    new-instance v2, Lcq0/v;

    .line 555
    .line 556
    invoke-virtual {v14}, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningTimesDto;->getFrom()Ljava/lang/String;

    .line 557
    .line 558
    .line 559
    move-result-object v16

    .line 560
    move-object/from16 p1, v0

    .line 561
    .line 562
    invoke-static/range {v16 .. v16}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    invoke-static {v0, v15}, Ljava/time/OffsetTime;->of(Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetTime;

    .line 567
    .line 568
    .line 569
    move-result-object v0

    .line 570
    move-object/from16 v16, v3

    .line 571
    .line 572
    const-string v3, "of(...)"

    .line 573
    .line 574
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 575
    .line 576
    .line 577
    invoke-virtual {v14}, Lcz/myskoda/api/bff_dealers/v2/DealerOpeningTimesDto;->getTo()Ljava/lang/String;

    .line 578
    .line 579
    .line 580
    move-result-object v14

    .line 581
    invoke-static {v14}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 582
    .line 583
    .line 584
    move-result-object v14

    .line 585
    invoke-static {v14, v15}, Ljava/time/OffsetTime;->of(Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetTime;

    .line 586
    .line 587
    .line 588
    move-result-object v14

    .line 589
    invoke-static {v14, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 590
    .line 591
    .line 592
    invoke-direct {v2, v0, v14}, Lcq0/v;-><init>(Ljava/time/OffsetTime;Ljava/time/OffsetTime;)V

    .line 593
    .line 594
    .line 595
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 596
    .line 597
    .line 598
    move-object/from16 v0, p1

    .line 599
    .line 600
    move-object/from16 v3, v16

    .line 601
    .line 602
    const/16 v2, 0xa

    .line 603
    .line 604
    goto :goto_6

    .line 605
    :cond_6
    move-object/from16 p1, v0

    .line 606
    .line 607
    move-object/from16 v16, v3

    .line 608
    .line 609
    new-instance v0, Lcq0/u;

    .line 610
    .line 611
    invoke-direct {v0, v11, v12, v13}, Lcq0/u;-><init>(Ljava/time/DayOfWeek;Ljava/time/DayOfWeek;Ljava/util/ArrayList;)V

    .line 612
    .line 613
    .line 614
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 615
    .line 616
    .line 617
    move-object/from16 v0, p1

    .line 618
    .line 619
    const/16 v2, 0xa

    .line 620
    .line 621
    goto/16 :goto_5

    .line 622
    .line 623
    :cond_7
    move-object/from16 v16, v3

    .line 624
    .line 625
    :goto_7
    move-object v10, v1

    .line 626
    goto :goto_8

    .line 627
    :cond_8
    move-object/from16 v16, v3

    .line 628
    .line 629
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 630
    .line 631
    goto :goto_7

    .line 632
    :goto_8
    new-instance v2, Lf10/a;

    .line 633
    .line 634
    move-object/from16 v3, v16

    .line 635
    .line 636
    invoke-direct/range {v2 .. v10}, Lf10/a;-><init>(Ljava/lang/String;Ljava/lang/String;Lcq0/t;Lcq0/h;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 637
    .line 638
    .line 639
    return-object v2

    .line 640
    :pswitch_e
    move-object/from16 v0, p1

    .line 641
    .line 642
    check-cast v0, Lc1/l;

    .line 643
    .line 644
    iget v0, v0, Lc1/l;->a:F

    .line 645
    .line 646
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 647
    .line 648
    .line 649
    move-result-object v0

    .line 650
    return-object v0

    .line 651
    :pswitch_f
    move-object/from16 v0, p1

    .line 652
    .line 653
    check-cast v0, Lc1/o;

    .line 654
    .line 655
    new-instance v1, Ld3/c;

    .line 656
    .line 657
    iget v2, v0, Lc1/o;->a:F

    .line 658
    .line 659
    iget v3, v0, Lc1/o;->b:F

    .line 660
    .line 661
    iget v4, v0, Lc1/o;->c:F

    .line 662
    .line 663
    iget v0, v0, Lc1/o;->d:F

    .line 664
    .line 665
    invoke-direct {v1, v2, v3, v4, v0}, Ld3/c;-><init>(FFFF)V

    .line 666
    .line 667
    .line 668
    return-object v1

    .line 669
    :pswitch_10
    move-object/from16 v0, p1

    .line 670
    .line 671
    check-cast v0, Ld3/c;

    .line 672
    .line 673
    new-instance v1, Lc1/o;

    .line 674
    .line 675
    iget v2, v0, Ld3/c;->a:F

    .line 676
    .line 677
    iget v3, v0, Ld3/c;->b:F

    .line 678
    .line 679
    iget v4, v0, Ld3/c;->c:F

    .line 680
    .line 681
    iget v0, v0, Ld3/c;->d:F

    .line 682
    .line 683
    invoke-direct {v1, v2, v3, v4, v0}, Lc1/o;-><init>(FFFF)V

    .line 684
    .line 685
    .line 686
    return-object v1

    .line 687
    :pswitch_11
    move-object/from16 v0, p1

    .line 688
    .line 689
    check-cast v0, Lc1/m;

    .line 690
    .line 691
    iget v1, v0, Lc1/m;->a:F

    .line 692
    .line 693
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 694
    .line 695
    .line 696
    move-result v1

    .line 697
    const/4 v2, 0x0

    .line 698
    if-gez v1, :cond_9

    .line 699
    .line 700
    move v1, v2

    .line 701
    :cond_9
    iget v0, v0, Lc1/m;->b:F

    .line 702
    .line 703
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 704
    .line 705
    .line 706
    move-result v0

    .line 707
    if-gez v0, :cond_a

    .line 708
    .line 709
    goto :goto_9

    .line 710
    :cond_a
    move v2, v0

    .line 711
    :goto_9
    int-to-long v0, v1

    .line 712
    const/16 v3, 0x20

    .line 713
    .line 714
    shl-long/2addr v0, v3

    .line 715
    int-to-long v2, v2

    .line 716
    const-wide v4, 0xffffffffL

    .line 717
    .line 718
    .line 719
    .line 720
    .line 721
    and-long/2addr v2, v4

    .line 722
    or-long/2addr v0, v2

    .line 723
    new-instance v2, Lt4/l;

    .line 724
    .line 725
    invoke-direct {v2, v0, v1}, Lt4/l;-><init>(J)V

    .line 726
    .line 727
    .line 728
    return-object v2

    .line 729
    :pswitch_12
    move-object/from16 v0, p1

    .line 730
    .line 731
    check-cast v0, Lt4/l;

    .line 732
    .line 733
    new-instance v1, Lc1/m;

    .line 734
    .line 735
    iget-wide v2, v0, Lt4/l;->a:J

    .line 736
    .line 737
    const/16 v0, 0x20

    .line 738
    .line 739
    shr-long v4, v2, v0

    .line 740
    .line 741
    long-to-int v0, v4

    .line 742
    int-to-float v0, v0

    .line 743
    const-wide v4, 0xffffffffL

    .line 744
    .line 745
    .line 746
    .line 747
    .line 748
    and-long/2addr v2, v4

    .line 749
    long-to-int v2, v2

    .line 750
    int-to-float v2, v2

    .line 751
    invoke-direct {v1, v0, v2}, Lc1/m;-><init>(FF)V

    .line 752
    .line 753
    .line 754
    return-object v1

    .line 755
    :pswitch_13
    move-object/from16 v0, p1

    .line 756
    .line 757
    check-cast v0, Lc1/m;

    .line 758
    .line 759
    iget v1, v0, Lc1/m;->a:F

    .line 760
    .line 761
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 762
    .line 763
    .line 764
    move-result v1

    .line 765
    iget v0, v0, Lc1/m;->b:F

    .line 766
    .line 767
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 768
    .line 769
    .line 770
    move-result v0

    .line 771
    int-to-long v1, v1

    .line 772
    const/16 v3, 0x20

    .line 773
    .line 774
    shl-long/2addr v1, v3

    .line 775
    int-to-long v3, v0

    .line 776
    const-wide v5, 0xffffffffL

    .line 777
    .line 778
    .line 779
    .line 780
    .line 781
    and-long/2addr v3, v5

    .line 782
    or-long v0, v1, v3

    .line 783
    .line 784
    new-instance v2, Lt4/j;

    .line 785
    .line 786
    invoke-direct {v2, v0, v1}, Lt4/j;-><init>(J)V

    .line 787
    .line 788
    .line 789
    return-object v2

    .line 790
    :pswitch_14
    move-object/from16 v0, p1

    .line 791
    .line 792
    check-cast v0, Lt4/j;

    .line 793
    .line 794
    new-instance v1, Lc1/m;

    .line 795
    .line 796
    iget-wide v2, v0, Lt4/j;->a:J

    .line 797
    .line 798
    const/16 v0, 0x20

    .line 799
    .line 800
    shr-long v4, v2, v0

    .line 801
    .line 802
    long-to-int v0, v4

    .line 803
    int-to-float v0, v0

    .line 804
    const-wide v4, 0xffffffffL

    .line 805
    .line 806
    .line 807
    .line 808
    .line 809
    and-long/2addr v2, v4

    .line 810
    long-to-int v2, v2

    .line 811
    int-to-float v2, v2

    .line 812
    invoke-direct {v1, v0, v2}, Lc1/m;-><init>(FF)V

    .line 813
    .line 814
    .line 815
    return-object v1

    .line 816
    :pswitch_15
    move-object/from16 v0, p1

    .line 817
    .line 818
    check-cast v0, Lc1/m;

    .line 819
    .line 820
    iget v1, v0, Lc1/m;->a:F

    .line 821
    .line 822
    iget v0, v0, Lc1/m;->b:F

    .line 823
    .line 824
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 825
    .line 826
    .line 827
    move-result v1

    .line 828
    int-to-long v1, v1

    .line 829
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 830
    .line 831
    .line 832
    move-result v0

    .line 833
    int-to-long v3, v0

    .line 834
    const/16 v0, 0x20

    .line 835
    .line 836
    shl-long v0, v1, v0

    .line 837
    .line 838
    const-wide v5, 0xffffffffL

    .line 839
    .line 840
    .line 841
    .line 842
    .line 843
    and-long v2, v3, v5

    .line 844
    .line 845
    or-long/2addr v0, v2

    .line 846
    new-instance v2, Ld3/b;

    .line 847
    .line 848
    invoke-direct {v2, v0, v1}, Ld3/b;-><init>(J)V

    .line 849
    .line 850
    .line 851
    return-object v2

    .line 852
    :pswitch_16
    move-object/from16 v0, p1

    .line 853
    .line 854
    check-cast v0, Ld3/b;

    .line 855
    .line 856
    new-instance v1, Lc1/m;

    .line 857
    .line 858
    iget-wide v2, v0, Ld3/b;->a:J

    .line 859
    .line 860
    const/16 v4, 0x20

    .line 861
    .line 862
    shr-long/2addr v2, v4

    .line 863
    long-to-int v2, v2

    .line 864
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 865
    .line 866
    .line 867
    move-result v2

    .line 868
    iget-wide v3, v0, Ld3/b;->a:J

    .line 869
    .line 870
    const-wide v5, 0xffffffffL

    .line 871
    .line 872
    .line 873
    .line 874
    .line 875
    and-long/2addr v3, v5

    .line 876
    long-to-int v0, v3

    .line 877
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 878
    .line 879
    .line 880
    move-result v0

    .line 881
    invoke-direct {v1, v2, v0}, Lc1/m;-><init>(FF)V

    .line 882
    .line 883
    .line 884
    return-object v1

    .line 885
    :pswitch_17
    move-object/from16 v0, p1

    .line 886
    .line 887
    check-cast v0, Lc1/m;

    .line 888
    .line 889
    iget v1, v0, Lc1/m;->a:F

    .line 890
    .line 891
    iget v0, v0, Lc1/m;->b:F

    .line 892
    .line 893
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 894
    .line 895
    .line 896
    move-result v1

    .line 897
    int-to-long v1, v1

    .line 898
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 899
    .line 900
    .line 901
    move-result v0

    .line 902
    int-to-long v3, v0

    .line 903
    const/16 v0, 0x20

    .line 904
    .line 905
    shl-long v0, v1, v0

    .line 906
    .line 907
    const-wide v5, 0xffffffffL

    .line 908
    .line 909
    .line 910
    .line 911
    .line 912
    and-long v2, v3, v5

    .line 913
    .line 914
    or-long/2addr v0, v2

    .line 915
    new-instance v2, Ld3/e;

    .line 916
    .line 917
    invoke-direct {v2, v0, v1}, Ld3/e;-><init>(J)V

    .line 918
    .line 919
    .line 920
    return-object v2

    .line 921
    :pswitch_18
    move-object/from16 v0, p1

    .line 922
    .line 923
    check-cast v0, Ld3/e;

    .line 924
    .line 925
    new-instance v1, Lc1/m;

    .line 926
    .line 927
    iget-wide v2, v0, Ld3/e;->a:J

    .line 928
    .line 929
    const/16 v4, 0x20

    .line 930
    .line 931
    shr-long/2addr v2, v4

    .line 932
    long-to-int v2, v2

    .line 933
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 934
    .line 935
    .line 936
    move-result v2

    .line 937
    iget-wide v3, v0, Ld3/e;->a:J

    .line 938
    .line 939
    const-wide v5, 0xffffffffL

    .line 940
    .line 941
    .line 942
    .line 943
    .line 944
    and-long/2addr v3, v5

    .line 945
    long-to-int v0, v3

    .line 946
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 947
    .line 948
    .line 949
    move-result v0

    .line 950
    invoke-direct {v1, v2, v0}, Lc1/m;-><init>(FF)V

    .line 951
    .line 952
    .line 953
    return-object v1

    .line 954
    :pswitch_19
    move-object/from16 v0, p1

    .line 955
    .line 956
    check-cast v0, Lc1/m;

    .line 957
    .line 958
    iget v1, v0, Lc1/m;->a:F

    .line 959
    .line 960
    iget v0, v0, Lc1/m;->b:F

    .line 961
    .line 962
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 963
    .line 964
    .line 965
    move-result v1

    .line 966
    int-to-long v1, v1

    .line 967
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 968
    .line 969
    .line 970
    move-result v0

    .line 971
    int-to-long v3, v0

    .line 972
    const/16 v0, 0x20

    .line 973
    .line 974
    shl-long v0, v1, v0

    .line 975
    .line 976
    const-wide v5, 0xffffffffL

    .line 977
    .line 978
    .line 979
    .line 980
    .line 981
    and-long v2, v3, v5

    .line 982
    .line 983
    or-long/2addr v0, v2

    .line 984
    new-instance v2, Lt4/g;

    .line 985
    .line 986
    invoke-direct {v2, v0, v1}, Lt4/g;-><init>(J)V

    .line 987
    .line 988
    .line 989
    return-object v2

    .line 990
    :pswitch_1a
    move-object/from16 v0, p1

    .line 991
    .line 992
    check-cast v0, Lt4/g;

    .line 993
    .line 994
    new-instance v1, Lc1/m;

    .line 995
    .line 996
    iget-wide v2, v0, Lt4/g;->a:J

    .line 997
    .line 998
    const/16 v4, 0x20

    .line 999
    .line 1000
    shr-long/2addr v2, v4

    .line 1001
    long-to-int v2, v2

    .line 1002
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1003
    .line 1004
    .line 1005
    move-result v2

    .line 1006
    iget-wide v3, v0, Lt4/g;->a:J

    .line 1007
    .line 1008
    const-wide v5, 0xffffffffL

    .line 1009
    .line 1010
    .line 1011
    .line 1012
    .line 1013
    and-long/2addr v3, v5

    .line 1014
    long-to-int v0, v3

    .line 1015
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1016
    .line 1017
    .line 1018
    move-result v0

    .line 1019
    invoke-direct {v1, v2, v0}, Lc1/m;-><init>(FF)V

    .line 1020
    .line 1021
    .line 1022
    return-object v1

    .line 1023
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1024
    .line 1025
    check-cast v0, Lc1/l;

    .line 1026
    .line 1027
    iget v0, v0, Lc1/l;->a:F

    .line 1028
    .line 1029
    new-instance v1, Lt4/f;

    .line 1030
    .line 1031
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 1032
    .line 1033
    .line 1034
    return-object v1

    .line 1035
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1036
    .line 1037
    check-cast v0, Lt4/f;

    .line 1038
    .line 1039
    new-instance v1, Lc1/l;

    .line 1040
    .line 1041
    iget v0, v0, Lt4/f;->d:F

    .line 1042
    .line 1043
    invoke-direct {v1, v0}, Lc1/l;-><init>(F)V

    .line 1044
    .line 1045
    .line 1046
    return-object v1

    .line 1047
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
.end method
