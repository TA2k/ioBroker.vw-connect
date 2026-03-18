.class public abstract Lkp/e8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;)Lvk0/d;
    .locals 30

    .line 1
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getId()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v1

    .line 5
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getDescription()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getAddress()Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const/4 v4, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-static {v0}, Lb0/c;->d(Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;)Lbl0/a;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    move-object v5, v4

    .line 25
    move-object v4, v0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move-object v5, v4

    .line 28
    :goto_0
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getAddress()Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/MapPositionAddressDto;->getFormattedAddress()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    move-object v6, v5

    .line 39
    move-object v5, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move-object v6, v5

    .line 42
    :goto_1
    const-string v0, "Required value was null."

    .line 43
    .line 44
    if-eqz v5, :cond_17

    .line 45
    .line 46
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getLocation()Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    invoke-static {v7}, Lb0/c;->f(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)Lxj0/f;

    .line 51
    .line 52
    .line 53
    move-result-object v7

    .line 54
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getPhotos()Ljava/util/List;

    .line 55
    .line 56
    .line 57
    move-result-object v8

    .line 58
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    .line 59
    .line 60
    const/16 v10, 0xa

    .line 61
    .line 62
    if-eqz v8, :cond_2

    .line 63
    .line 64
    check-cast v8, Ljava/lang/Iterable;

    .line 65
    .line 66
    new-instance v11, Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-static {v8, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 69
    .line 70
    .line 71
    move-result v12

    .line 72
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    :goto_2
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v12

    .line 83
    if-eqz v12, :cond_3

    .line 84
    .line 85
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v12

    .line 89
    check-cast v12, Ljava/lang/String;

    .line 90
    .line 91
    new-instance v13, Ljava/net/URL;

    .line 92
    .line 93
    invoke-direct {v13, v12}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_2
    move-object v11, v9

    .line 101
    :cond_3
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getContact()Lcz/myskoda/api/bff_maps/v3/ContactDto;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    if-eqz v8, :cond_7

    .line 106
    .line 107
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ContactDto;->getInternationalPhoneNumber()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v12

    .line 111
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ContactDto;->getWebsite()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v13

    .line 115
    if-eqz v13, :cond_5

    .line 116
    .line 117
    invoke-static {v13}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 118
    .line 119
    .line 120
    move-result v13

    .line 121
    if-eqz v13, :cond_4

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_4
    new-instance v13, Ljava/net/URL;

    .line 125
    .line 126
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ContactDto;->getWebsite()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v14

    .line 130
    invoke-direct {v13, v14}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_5
    :goto_3
    move-object v13, v6

    .line 135
    :goto_4
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ContactDto;->getGooglePage()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    if-eqz v8, :cond_6

    .line 140
    .line 141
    new-instance v14, Ljava/net/URL;

    .line 142
    .line 143
    invoke-direct {v14, v8}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_6
    move-object v14, v6

    .line 148
    :goto_5
    new-instance v8, Lvk0/l;

    .line 149
    .line 150
    invoke-direct {v8, v12, v13, v14}, Lvk0/l;-><init>(Ljava/lang/String;Ljava/net/URL;Ljava/net/URL;)V

    .line 151
    .line 152
    .line 153
    :goto_6
    move-object v12, v9

    .line 154
    goto :goto_7

    .line 155
    :cond_7
    move-object v8, v6

    .line 156
    goto :goto_6

    .line 157
    :goto_7
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getOpenNow()Ljava/lang/Boolean;

    .line 158
    .line 159
    .line 160
    move-result-object v9

    .line 161
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getOpeningHours()Ljava/util/List;

    .line 162
    .line 163
    .line 164
    move-result-object v13

    .line 165
    if-eqz v13, :cond_8

    .line 166
    .line 167
    const/4 v14, 0x0

    .line 168
    invoke-static {v13, v14}, Lkp/e8;->b(Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 169
    .line 170
    .line 171
    move-result-object v13

    .line 172
    goto :goto_8

    .line 173
    :cond_8
    move-object v13, v6

    .line 174
    :goto_8
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getPlaceReview()Lcz/myskoda/api/bff_maps/v3/PlaceReviewDto;

    .line 175
    .line 176
    .line 177
    move-result-object v14

    .line 178
    if-eqz v14, :cond_b

    .line 179
    .line 180
    new-instance v15, Lvk0/i0;

    .line 181
    .line 182
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/PlaceReviewDto;->getAverageRating()Ljava/lang/Float;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/PlaceReviewDto;->getNumberOfReviews()Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v10

    .line 190
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/PlaceReviewDto;->getVisitorReviews()Ljava/util/List;

    .line 191
    .line 192
    .line 193
    move-result-object v14

    .line 194
    if-eqz v14, :cond_a

    .line 195
    .line 196
    check-cast v14, Ljava/lang/Iterable;

    .line 197
    .line 198
    new-instance v12, Ljava/util/ArrayList;

    .line 199
    .line 200
    move-object/from16 v18, v1

    .line 201
    .line 202
    const/16 v1, 0xa

    .line 203
    .line 204
    invoke-static {v14, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 205
    .line 206
    .line 207
    move-result v1

    .line 208
    invoke-direct {v12, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 209
    .line 210
    .line 211
    invoke-interface {v14}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 216
    .line 217
    .line 218
    move-result v14

    .line 219
    if-eqz v14, :cond_9

    .line 220
    .line 221
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v14

    .line 225
    check-cast v14, Lcz/myskoda/api/bff_maps/v3/VisitorReviewDto;

    .line 226
    .line 227
    move-object/from16 v17, v1

    .line 228
    .line 229
    new-instance v1, Lvk0/u0;

    .line 230
    .line 231
    move-object/from16 v19, v2

    .line 232
    .line 233
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/VisitorReviewDto;->getAuthorName()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    move-object/from16 v20, v3

    .line 238
    .line 239
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/VisitorReviewDto;->getRating()I

    .line 240
    .line 241
    .line 242
    move-result v3

    .line 243
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/VisitorReviewDto;->getText()Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v14

    .line 247
    invoke-direct {v1, v2, v3, v14}, Lvk0/u0;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v12, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-object/from16 v1, v17

    .line 254
    .line 255
    move-object/from16 v2, v19

    .line 256
    .line 257
    move-object/from16 v3, v20

    .line 258
    .line 259
    goto :goto_9

    .line 260
    :cond_9
    :goto_a
    move-object/from16 v19, v2

    .line 261
    .line 262
    move-object/from16 v20, v3

    .line 263
    .line 264
    goto :goto_b

    .line 265
    :cond_a
    move-object/from16 v18, v1

    .line 266
    .line 267
    goto :goto_a

    .line 268
    :goto_b
    invoke-direct {v15, v6, v10, v12}, Lvk0/i0;-><init>(Ljava/lang/Float;Ljava/lang/Integer;Ljava/util/List;)V

    .line 269
    .line 270
    .line 271
    goto :goto_c

    .line 272
    :cond_b
    move-object/from16 v18, v1

    .line 273
    .line 274
    move-object/from16 v19, v2

    .line 275
    .line 276
    move-object/from16 v20, v3

    .line 277
    .line 278
    const/4 v15, 0x0

    .line 279
    :goto_c
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getTravelData()Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    if-eqz v1, :cond_c

    .line 284
    .line 285
    invoke-static {v1}, Llp/zf;->d(Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)Loo0/b;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    move-object v12, v1

    .line 290
    :goto_d
    move-object v10, v13

    .line 291
    goto :goto_e

    .line 292
    :cond_c
    const/4 v12, 0x0

    .line 293
    goto :goto_d

    .line 294
    :goto_e
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getFavouritePlaceId()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v13

    .line 298
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getOffer()Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    if-eqz v1, :cond_16

    .line 303
    .line 304
    const-string v2, "<this>"

    .line 305
    .line 306
    :try_start_0
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getId()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v22

    .line 310
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getType()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 318
    .line 319
    .line 320
    move-result v6

    .line 321
    const v14, -0x4de4161b

    .line 322
    .line 323
    .line 324
    if-eq v6, v14, :cond_11

    .line 325
    .line 326
    const v14, 0x3eee6541

    .line 327
    .line 328
    .line 329
    if-eq v6, v14, :cond_f

    .line 330
    .line 331
    const v14, 0x76750c83

    .line 332
    .line 333
    .line 334
    if-eq v6, v14, :cond_d

    .line 335
    .line 336
    goto :goto_10

    .line 337
    :cond_d
    const-string v6, "PROMOTION"

    .line 338
    .line 339
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    move-result v3

    .line 343
    if-nez v3, :cond_e

    .line 344
    .line 345
    goto :goto_10

    .line 346
    :cond_e
    sget-object v3, Lvk0/x;->e:Lvk0/x;

    .line 347
    .line 348
    :goto_f
    move-object/from16 v23, v3

    .line 349
    .line 350
    goto :goto_11

    .line 351
    :cond_f
    const-string v6, "DISCOUNT"

    .line 352
    .line 353
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result v3

    .line 357
    if-nez v3, :cond_10

    .line 358
    .line 359
    goto :goto_10

    .line 360
    :cond_10
    sget-object v3, Lvk0/x;->f:Lvk0/x;

    .line 361
    .line 362
    goto :goto_f

    .line 363
    :cond_11
    const-string v6, "ADVERTISEMENT"

    .line 364
    .line 365
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 366
    .line 367
    .line 368
    move-result v3

    .line 369
    if-nez v3, :cond_12

    .line 370
    .line 371
    :goto_10
    const/16 v23, 0x0

    .line 372
    .line 373
    goto :goto_11

    .line 374
    :cond_12
    sget-object v3, Lvk0/x;->d:Lvk0/x;

    .line 375
    .line 376
    goto :goto_f

    .line 377
    :goto_11
    if-eqz v23, :cond_14

    .line 378
    .line 379
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getTitle()Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v24

    .line 383
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getDescription()Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v25

    .line 387
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getExpiration()Ljava/time/OffsetDateTime;

    .line 388
    .line 389
    .line 390
    move-result-object v26

    .line 391
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getPartner()Lcz/myskoda/api/bff_maps/v3/OfferPartnerDto;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    new-instance v2, Lvk0/w;

    .line 399
    .line 400
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/OfferPartnerDto;->getId()Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v3

    .line 404
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/OfferPartnerDto;->getName()Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v6

    .line 408
    new-instance v14, Ljava/net/URL;

    .line 409
    .line 410
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/OfferPartnerDto;->getLogo()Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    invoke-direct {v14, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    invoke-direct {v2, v3, v6, v14}, Lvk0/w;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/net/URL;)V

    .line 418
    .line 419
    .line 420
    new-instance v0, Ljava/net/URL;

    .line 421
    .line 422
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getImage()Ljava/lang/String;

    .line 423
    .line 424
    .line 425
    move-result-object v3

    .line 426
    invoke-direct {v0, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getPromotionDetail()Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v3

    .line 433
    if-eqz v3, :cond_13

    .line 434
    .line 435
    new-instance v3, Ljava/net/URL;

    .line 436
    .line 437
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/OfferDetailDto;->getPromotionDetail()Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    invoke-direct {v3, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v29, v3

    .line 445
    .line 446
    goto :goto_12

    .line 447
    :catchall_0
    move-exception v0

    .line 448
    goto :goto_14

    .line 449
    :cond_13
    const/16 v29, 0x0

    .line 450
    .line 451
    :goto_12
    new-instance v21, Lvk0/y;

    .line 452
    .line 453
    move-object/from16 v28, v0

    .line 454
    .line 455
    move-object/from16 v27, v2

    .line 456
    .line 457
    invoke-direct/range {v21 .. v29}, Lvk0/y;-><init>(Ljava/lang/String;Lvk0/x;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Lvk0/w;Ljava/net/URL;Ljava/net/URL;)V

    .line 458
    .line 459
    .line 460
    :goto_13
    move-object/from16 v0, v21

    .line 461
    .line 462
    goto :goto_15

    .line 463
    :cond_14
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 464
    .line 465
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    throw v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 469
    :goto_14
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 470
    .line 471
    .line 472
    move-result-object v21

    .line 473
    goto :goto_13

    .line 474
    :goto_15
    instance-of v1, v0, Llx0/n;

    .line 475
    .line 476
    if-eqz v1, :cond_15

    .line 477
    .line 478
    const/16 v16, 0x0

    .line 479
    .line 480
    goto :goto_16

    .line 481
    :cond_15
    move-object/from16 v16, v0

    .line 482
    .line 483
    :goto_16
    move-object/from16 v0, v16

    .line 484
    .line 485
    check-cast v0, Lvk0/y;

    .line 486
    .line 487
    move-object v14, v0

    .line 488
    goto :goto_17

    .line 489
    :cond_16
    const/4 v14, 0x0

    .line 490
    :goto_17
    new-instance v0, Lvk0/d;

    .line 491
    .line 492
    move-object v6, v7

    .line 493
    move-object v7, v11

    .line 494
    move-object v11, v15

    .line 495
    move-object/from16 v1, v18

    .line 496
    .line 497
    move-object/from16 v2, v19

    .line 498
    .line 499
    move-object/from16 v3, v20

    .line 500
    .line 501
    invoke-direct/range {v0 .. v14}, Lvk0/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/util/List;Lvk0/l;Ljava/lang/Boolean;Ljava/util/List;Lvk0/i0;Loo0/b;Ljava/lang/String;Lvk0/y;)V

    .line 502
    .line 503
    .line 504
    return-object v0

    .line 505
    :cond_17
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 506
    .line 507
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 508
    .line 509
    .line 510
    throw v1
.end method

.method public static final b(Ljava/util/List;Z)Ljava/util/ArrayList;
    .locals 11

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Lcz/myskoda/api/bff_maps/v3/OpeningHoursDto;

    .line 29
    .line 30
    new-instance v3, Lvk0/a0;

    .line 31
    .line 32
    invoke-virtual {v2}, Lcz/myskoda/api/bff_maps/v3/OpeningHoursDto;->getPeriodStart()Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    invoke-virtual {v4}, Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;->getValue()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-static {v4}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {v2}, Lcz/myskoda/api/bff_maps/v3/OpeningHoursDto;->getPeriodEnd()Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-virtual {v5}, Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;->getValue()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    invoke-static {v5}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-virtual {v2}, Lcz/myskoda/api/bff_maps/v3/OpeningHoursDto;->getOpeningTimes()Ljava/util/List;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    check-cast v2, Ljava/lang/Iterable;

    .line 61
    .line 62
    new-instance v6, Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-static {v2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 65
    .line 66
    .line 67
    move-result v7

    .line 68
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v7

    .line 79
    if-eqz v7, :cond_0

    .line 80
    .line 81
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lcz/myskoda/api/bff_maps/v3/OpeningTimesDto;

    .line 86
    .line 87
    new-instance v8, Lvk0/b0;

    .line 88
    .line 89
    invoke-virtual {v7}, Lcz/myskoda/api/bff_maps/v3/OpeningTimesDto;->getFrom()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v9

    .line 93
    invoke-static {v9}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    const-string v10, "parse(...)"

    .line 98
    .line 99
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v7}, Lcz/myskoda/api/bff_maps/v3/OpeningTimesDto;->getTo()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    invoke-static {v7}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-direct {v8, v9, v7}, Lvk0/b0;-><init>(Ljava/time/LocalTime;Ljava/time/LocalTime;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_0
    invoke-direct {v3, v4, v5, v6, p1}, Lvk0/a0;-><init>(Ljava/time/DayOfWeek;Ljava/time/DayOfWeek;Ljava/util/ArrayList;Z)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_1
    return-object v0
.end method

.method public static final c(Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;Z)Lvk0/d0;
    .locals 36

    .line 1
    invoke-static/range {p0 .. p0}, Lkp/e8;->a(Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;)Lvk0/d;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getOpeningHours()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const/4 v3, 0x0

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-static {v2, v3}, Lkp/e8;->b(Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    if-eqz v5, :cond_0

    .line 25
    .line 26
    invoke-virtual {v5}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->isOpen24h()Ljava/lang/Boolean;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v5, v3

    .line 38
    :goto_0
    if-nez v5, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/4 v2, 0x0

    .line 42
    :goto_1
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    const/4 v6, 0x1

    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    invoke-virtual {v5}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getRestrictions()Lcz/myskoda/api/bff_maps/v3/RestrictionsDto;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    if-eqz v5, :cond_2

    .line 54
    .line 55
    invoke-virtual {v5}, Lcz/myskoda/api/bff_maps/v3/RestrictionsDto;->getRestrictedHours()Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    if-eqz v5, :cond_2

    .line 60
    .line 61
    invoke-static {v5, v6}, Lkp/e8;->b(Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    goto :goto_2

    .line 66
    :cond_2
    const/4 v5, 0x0

    .line 67
    :goto_2
    if-eqz v2, :cond_3

    .line 68
    .line 69
    invoke-virtual {v1, v2}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 70
    .line 71
    .line 72
    :cond_3
    if-eqz v5, :cond_4

    .line 73
    .line 74
    invoke-virtual {v1, v5}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 75
    .line 76
    .line 77
    :cond_4
    invoke-static {v1}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 78
    .line 79
    .line 80
    move-result-object v17

    .line 81
    iget-object v8, v0, Lvk0/d;->a:Ljava/lang/String;

    .line 82
    .line 83
    iget-object v9, v0, Lvk0/d;->b:Ljava/lang/String;

    .line 84
    .line 85
    iget-object v10, v0, Lvk0/d;->c:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v11, v0, Lvk0/d;->d:Lbl0/a;

    .line 88
    .line 89
    iget-object v12, v0, Lvk0/d;->e:Ljava/lang/String;

    .line 90
    .line 91
    iget-object v13, v0, Lvk0/d;->f:Lxj0/f;

    .line 92
    .line 93
    iget-object v14, v0, Lvk0/d;->g:Ljava/util/List;

    .line 94
    .line 95
    iget-object v15, v0, Lvk0/d;->h:Lvk0/l;

    .line 96
    .line 97
    iget-object v1, v0, Lvk0/d;->i:Ljava/lang/Boolean;

    .line 98
    .line 99
    iget-object v2, v0, Lvk0/d;->k:Lvk0/i0;

    .line 100
    .line 101
    iget-object v5, v0, Lvk0/d;->l:Loo0/b;

    .line 102
    .line 103
    iget-object v7, v0, Lvk0/d;->m:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v0, v0, Lvk0/d;->n:Lvk0/y;

    .line 106
    .line 107
    const-string v3, "id"

    .line 108
    .line 109
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    new-instance v23, Lvk0/d;

    .line 113
    .line 114
    move-object/from16 v21, v0

    .line 115
    .line 116
    move-object/from16 v16, v1

    .line 117
    .line 118
    move-object/from16 v18, v2

    .line 119
    .line 120
    move-object/from16 v19, v5

    .line 121
    .line 122
    move-object/from16 v20, v7

    .line 123
    .line 124
    move-object/from16 v7, v23

    .line 125
    .line 126
    invoke-direct/range {v7 .. v21}, Lvk0/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Ljava/util/List;Lvk0/l;Ljava/lang/Boolean;Ljava/util/List;Lvk0/i0;Loo0/b;Ljava/lang/String;Lvk0/y;)V

    .line 127
    .line 128
    .line 129
    new-instance v0, Ljava/net/URL;

    .line 130
    .line 131
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    if-eqz v1, :cond_5

    .line 136
    .line 137
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getTermsUrl()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    goto :goto_3

    .line 142
    :cond_5
    const/4 v1, 0x0

    .line 143
    :goto_3
    const-string v2, "Required value was null."

    .line 144
    .line 145
    if-eqz v1, :cond_37

    .line 146
    .line 147
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    if-eqz v1, :cond_6

    .line 155
    .line 156
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getPricePerHour()Ljava/lang/Float;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    if-eqz v1, :cond_6

    .line 161
    .line 162
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    float-to-double v8, v1

    .line 167
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    move-object/from16 v25, v1

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_6
    const/16 v25, 0x0

    .line 175
    .line 176
    :goto_4
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    if-eqz v1, :cond_7

    .line 181
    .line 182
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getCurrencyCode()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    move-object/from16 v26, v1

    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_7
    const/16 v26, 0x0

    .line 190
    .line 191
    :goto_5
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    if-eqz v1, :cond_8

    .line 196
    .line 197
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getProviderName()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    move-object/from16 v27, v1

    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_8
    const/16 v27, 0x0

    .line 205
    .line 206
    :goto_6
    if-eqz v27, :cond_36

    .line 207
    .line 208
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    if-eqz v1, :cond_9

    .line 213
    .line 214
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getAdditionalInfo()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    move-object/from16 v28, v1

    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_9
    const/16 v28, 0x0

    .line 222
    .line 223
    :goto_7
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    if-eqz v1, :cond_a

    .line 228
    .line 229
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getCapacity()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    move-object/from16 v29, v1

    .line 234
    .line 235
    goto :goto_8

    .line 236
    :cond_a
    const/16 v29, 0x0

    .line 237
    .line 238
    :goto_8
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    const-string v2, "<this>"

    .line 243
    .line 244
    const/16 v3, 0xa

    .line 245
    .line 246
    if-eqz v1, :cond_e

    .line 247
    .line 248
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getProviderInfo()Lcz/myskoda/api/bff_maps/v3/ProviderInfoDto;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    if-eqz v1, :cond_e

    .line 253
    .line 254
    new-instance v5, Lon0/s;

    .line 255
    .line 256
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoDto;->getParkingSpaceSelection()Lcz/myskoda/api/bff_maps/v3/ProviderInfoParkingSpaceSelectionDto;

    .line 257
    .line 258
    .line 259
    move-result-object v8

    .line 260
    if-eqz v8, :cond_c

    .line 261
    .line 262
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoParkingSpaceSelectionDto;->getTitle()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v9

    .line 266
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoParkingSpaceSelectionDto;->getSubtitle()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v10

    .line 270
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoParkingSpaceSelectionDto;->getOptions()Ljava/util/List;

    .line 271
    .line 272
    .line 273
    move-result-object v8

    .line 274
    check-cast v8, Ljava/lang/Iterable;

    .line 275
    .line 276
    new-instance v11, Ljava/util/ArrayList;

    .line 277
    .line 278
    invoke-static {v8, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 279
    .line 280
    .line 281
    move-result v12

    .line 282
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 283
    .line 284
    .line 285
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 286
    .line 287
    .line 288
    move-result-object v8

    .line 289
    :goto_9
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 290
    .line 291
    .line 292
    move-result v12

    .line 293
    if-eqz v12, :cond_b

    .line 294
    .line 295
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v12

    .line 299
    check-cast v12, Lcz/myskoda/api/bff_maps/v3/ParkingSpaceOptionDto;

    .line 300
    .line 301
    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    new-instance v13, Lon0/u;

    .line 305
    .line 306
    invoke-virtual {v12}, Lcz/myskoda/api/bff_maps/v3/ParkingSpaceOptionDto;->getId()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v14

    .line 310
    invoke-virtual {v12}, Lcz/myskoda/api/bff_maps/v3/ParkingSpaceOptionDto;->getValue()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v12

    .line 314
    invoke-direct {v13, v14, v12}, Lon0/u;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 318
    .line 319
    .line 320
    goto :goto_9

    .line 321
    :cond_b
    new-instance v8, Lon0/v;

    .line 322
    .line 323
    invoke-direct {v8, v9, v10, v11}, Lon0/v;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 324
    .line 325
    .line 326
    goto :goto_a

    .line 327
    :cond_c
    const/4 v8, 0x0

    .line 328
    :goto_a
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoDto;->getAreaSpecificMessage()Lcz/myskoda/api/bff_maps/v3/ProviderInfoAreaSpecificMessageDto;

    .line 329
    .line 330
    .line 331
    move-result-object v1

    .line 332
    if-eqz v1, :cond_d

    .line 333
    .line 334
    new-instance v9, Lon0/a;

    .line 335
    .line 336
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoAreaSpecificMessageDto;->getTitle()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v10

    .line 340
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ProviderInfoAreaSpecificMessageDto;->getSubtitle()Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    invoke-direct {v9, v10, v1}, Lon0/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    goto :goto_b

    .line 348
    :cond_d
    const/4 v9, 0x0

    .line 349
    :goto_b
    invoke-direct {v5, v8, v9}, Lon0/s;-><init>(Lon0/v;Lon0/a;)V

    .line 350
    .line 351
    .line 352
    move-object/from16 v30, v5

    .line 353
    .line 354
    goto :goto_c

    .line 355
    :cond_e
    const/16 v30, 0x0

    .line 356
    .line 357
    :goto_c
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 358
    .line 359
    .line 360
    move-result-object v1

    .line 361
    if-eqz v1, :cond_33

    .line 362
    .line 363
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getRateTables()Ljava/util/List;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    if-eqz v1, :cond_33

    .line 368
    .line 369
    check-cast v1, Ljava/lang/Iterable;

    .line 370
    .line 371
    new-instance v5, Ljava/util/ArrayList;

    .line 372
    .line 373
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 374
    .line 375
    .line 376
    move-result v8

    .line 377
    invoke-direct {v5, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 378
    .line 379
    .line 380
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 385
    .line 386
    .line 387
    move-result v8

    .line 388
    if-eqz v8, :cond_32

    .line 389
    .line 390
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v8

    .line 394
    check-cast v8, Lcz/myskoda/api/bff_maps/v3/RateTableDto;

    .line 395
    .line 396
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/RateTableDto;->getEligibility()Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object v9

    .line 400
    if-eqz v9, :cond_26

    .line 401
    .line 402
    invoke-virtual {v9}, Ljava/lang/String;->hashCode()I

    .line 403
    .line 404
    .line 405
    move-result v10

    .line 406
    sparse-switch v10, :sswitch_data_0

    .line 407
    .line 408
    .line 409
    goto/16 :goto_e

    .line 410
    .line 411
    :sswitch_0
    const-string v10, "PATIENTS"

    .line 412
    .line 413
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 414
    .line 415
    .line 416
    move-result v9

    .line 417
    if-nez v9, :cond_f

    .line 418
    .line 419
    goto/16 :goto_e

    .line 420
    .line 421
    :cond_f
    sget-object v9, Lvk0/r0;->r:Lvk0/r0;

    .line 422
    .line 423
    goto/16 :goto_f

    .line 424
    .line 425
    :sswitch_1
    const-string v10, "LARGE VEHICLE"

    .line 426
    .line 427
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 428
    .line 429
    .line 430
    move-result v9

    .line 431
    if-nez v9, :cond_10

    .line 432
    .line 433
    goto/16 :goto_e

    .line 434
    .line 435
    :cond_10
    sget-object v9, Lvk0/r0;->j:Lvk0/r0;

    .line 436
    .line 437
    goto/16 :goto_f

    .line 438
    .line 439
    :sswitch_2
    const-string v10, "PAY-BY-MOBILE"

    .line 440
    .line 441
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 442
    .line 443
    .line 444
    move-result v9

    .line 445
    if-nez v9, :cond_11

    .line 446
    .line 447
    goto/16 :goto_e

    .line 448
    .line 449
    :cond_11
    sget-object v9, Lvk0/r0;->m:Lvk0/r0;

    .line 450
    .line 451
    goto/16 :goto_f

    .line 452
    .line 453
    :sswitch_3
    const-string v10, "CUSTOMER"

    .line 454
    .line 455
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    move-result v9

    .line 459
    if-nez v9, :cond_12

    .line 460
    .line 461
    goto/16 :goto_e

    .line 462
    .line 463
    :cond_12
    sget-object v9, Lvk0/r0;->h:Lvk0/r0;

    .line 464
    .line 465
    goto/16 :goto_f

    .line 466
    .line 467
    :sswitch_4
    const-string v10, "IMPORTED VEHICLE"

    .line 468
    .line 469
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 470
    .line 471
    .line 472
    move-result v9

    .line 473
    if-nez v9, :cond_13

    .line 474
    .line 475
    goto/16 :goto_e

    .line 476
    .line 477
    :cond_13
    sget-object v9, Lvk0/r0;->y:Lvk0/r0;

    .line 478
    .line 479
    goto/16 :goto_f

    .line 480
    .line 481
    :sswitch_5
    const-string v10, "CONTIPARK_PCARD"

    .line 482
    .line 483
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 484
    .line 485
    .line 486
    move-result v9

    .line 487
    if-nez v9, :cond_14

    .line 488
    .line 489
    goto/16 :goto_e

    .line 490
    .line 491
    :cond_14
    sget-object v9, Lvk0/r0;->v:Lvk0/r0;

    .line 492
    .line 493
    goto/16 :goto_f

    .line 494
    .line 495
    :sswitch_6
    const-string v10, "PARK AND RIDE"

    .line 496
    .line 497
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 498
    .line 499
    .line 500
    move-result v9

    .line 501
    if-nez v9, :cond_15

    .line 502
    .line 503
    goto/16 :goto_e

    .line 504
    .line 505
    :cond_15
    sget-object v9, Lvk0/r0;->u:Lvk0/r0;

    .line 506
    .line 507
    goto/16 :goto_f

    .line 508
    .line 509
    :sswitch_7
    const-string v10, "SMALL VEHICLE"

    .line 510
    .line 511
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result v9

    .line 515
    if-nez v9, :cond_16

    .line 516
    .line 517
    goto/16 :goto_e

    .line 518
    .line 519
    :cond_16
    sget-object v9, Lvk0/r0;->n:Lvk0/r0;

    .line 520
    .line 521
    goto/16 :goto_f

    .line 522
    .line 523
    :sswitch_8
    const-string v10, "OUTDOORS"

    .line 524
    .line 525
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    move-result v9

    .line 529
    if-nez v9, :cond_17

    .line 530
    .line 531
    goto/16 :goto_e

    .line 532
    .line 533
    :cond_17
    sget-object v9, Lvk0/r0;->l:Lvk0/r0;

    .line 534
    .line 535
    goto/16 :goto_f

    .line 536
    .line 537
    :sswitch_9
    const-string v10, "SHORTSTAY"

    .line 538
    .line 539
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 540
    .line 541
    .line 542
    move-result v9

    .line 543
    if-nez v9, :cond_18

    .line 544
    .line 545
    goto/16 :goto_e

    .line 546
    .line 547
    :cond_18
    sget-object v9, Lvk0/r0;->t:Lvk0/r0;

    .line 548
    .line 549
    goto/16 :goto_f

    .line 550
    .line 551
    :sswitch_a
    const-string v10, "MIDDLESIZED VEHICLE"

    .line 552
    .line 553
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 554
    .line 555
    .line 556
    move-result v9

    .line 557
    if-nez v9, :cond_19

    .line 558
    .line 559
    goto/16 :goto_e

    .line 560
    .line 561
    :cond_19
    sget-object v9, Lvk0/r0;->q:Lvk0/r0;

    .line 562
    .line 563
    goto/16 :goto_f

    .line 564
    .line 565
    :sswitch_b
    const-string v10, "VALIDATION"

    .line 566
    .line 567
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 568
    .line 569
    .line 570
    move-result v9

    .line 571
    if-nez v9, :cond_1a

    .line 572
    .line 573
    goto/16 :goto_e

    .line 574
    .line 575
    :cond_1a
    sget-object v9, Lvk0/r0;->i:Lvk0/r0;

    .line 576
    .line 577
    goto/16 :goto_f

    .line 578
    .line 579
    :sswitch_c
    const-string v10, "UNKNOWN"

    .line 580
    .line 581
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 582
    .line 583
    .line 584
    move-result v9

    .line 585
    if-nez v9, :cond_1b

    .line 586
    .line 587
    goto/16 :goto_e

    .line 588
    .line 589
    :cond_1b
    sget-object v9, Lvk0/r0;->z:Lvk0/r0;

    .line 590
    .line 591
    goto/16 :goto_f

    .line 592
    .line 593
    :sswitch_d
    const-string v10, "VALET"

    .line 594
    .line 595
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 596
    .line 597
    .line 598
    move-result v9

    .line 599
    if-nez v9, :cond_1c

    .line 600
    .line 601
    goto/16 :goto_e

    .line 602
    .line 603
    :cond_1c
    sget-object v9, Lvk0/r0;->g:Lvk0/r0;

    .line 604
    .line 605
    goto/16 :goto_f

    .line 606
    .line 607
    :sswitch_e
    const-string v10, "EVENT"

    .line 608
    .line 609
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 610
    .line 611
    .line 612
    move-result v9

    .line 613
    if-nez v9, :cond_1d

    .line 614
    .line 615
    goto/16 :goto_e

    .line 616
    .line 617
    :cond_1d
    sget-object v9, Lvk0/r0;->w:Lvk0/r0;

    .line 618
    .line 619
    goto/16 :goto_f

    .line 620
    .line 621
    :sswitch_f
    const-string v10, "LONGSTAY"

    .line 622
    .line 623
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 624
    .line 625
    .line 626
    move-result v9

    .line 627
    if-nez v9, :cond_1e

    .line 628
    .line 629
    goto :goto_e

    .line 630
    :cond_1e
    sget-object v9, Lvk0/r0;->o:Lvk0/r0;

    .line 631
    .line 632
    goto :goto_f

    .line 633
    :sswitch_10
    const-string v10, "ELECTRIC VEHICLE"

    .line 634
    .line 635
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    move-result v9

    .line 639
    if-nez v9, :cond_1f

    .line 640
    .line 641
    goto :goto_e

    .line 642
    :cond_1f
    sget-object v9, Lvk0/r0;->x:Lvk0/r0;

    .line 643
    .line 644
    goto :goto_f

    .line 645
    :sswitch_11
    const-string v10, "BOOKABLE"

    .line 646
    .line 647
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 648
    .line 649
    .line 650
    move-result v9

    .line 651
    if-nez v9, :cond_20

    .line 652
    .line 653
    goto :goto_e

    .line 654
    :cond_20
    sget-object v9, Lvk0/r0;->p:Lvk0/r0;

    .line 655
    .line 656
    goto :goto_f

    .line 657
    :sswitch_12
    const-string v10, "INDOORS"

    .line 658
    .line 659
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 660
    .line 661
    .line 662
    move-result v9

    .line 663
    if-nez v9, :cond_21

    .line 664
    .line 665
    goto :goto_e

    .line 666
    :cond_21
    sget-object v9, Lvk0/r0;->k:Lvk0/r0;

    .line 667
    .line 668
    goto :goto_f

    .line 669
    :sswitch_13
    const-string v10, "WINTER"

    .line 670
    .line 671
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 672
    .line 673
    .line 674
    move-result v9

    .line 675
    if-nez v9, :cond_22

    .line 676
    .line 677
    goto :goto_e

    .line 678
    :cond_22
    sget-object v9, Lvk0/r0;->f:Lvk0/r0;

    .line 679
    .line 680
    goto :goto_f

    .line 681
    :sswitch_14
    const-string v10, "SUMMER"

    .line 682
    .line 683
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 684
    .line 685
    .line 686
    move-result v9

    .line 687
    if-nez v9, :cond_23

    .line 688
    .line 689
    goto :goto_e

    .line 690
    :cond_23
    sget-object v9, Lvk0/r0;->e:Lvk0/r0;

    .line 691
    .line 692
    goto :goto_f

    .line 693
    :sswitch_15
    const-string v10, "VISITORS"

    .line 694
    .line 695
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 696
    .line 697
    .line 698
    move-result v9

    .line 699
    if-nez v9, :cond_24

    .line 700
    .line 701
    goto :goto_e

    .line 702
    :cond_24
    sget-object v9, Lvk0/r0;->s:Lvk0/r0;

    .line 703
    .line 704
    goto :goto_f

    .line 705
    :sswitch_16
    const-string v10, "DEFAULT"

    .line 706
    .line 707
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 708
    .line 709
    .line 710
    move-result v9

    .line 711
    if-nez v9, :cond_25

    .line 712
    .line 713
    goto :goto_e

    .line 714
    :cond_25
    sget-object v9, Lvk0/r0;->d:Lvk0/r0;

    .line 715
    .line 716
    goto :goto_f

    .line 717
    :cond_26
    :goto_e
    sget-object v9, Lvk0/r0;->z:Lvk0/r0;

    .line 718
    .line 719
    :goto_f
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/RateTableDto;->getMaxStay()Ljava/lang/String;

    .line 720
    .line 721
    .line 722
    move-result-object v10

    .line 723
    if-eqz v10, :cond_27

    .line 724
    .line 725
    sget v11, Lmy0/c;->g:I

    .line 726
    .line 727
    invoke-static {v10}, Lmy0/h;->o(Ljava/lang/String;)J

    .line 728
    .line 729
    .line 730
    move-result-wide v10

    .line 731
    new-instance v12, Lmy0/c;

    .line 732
    .line 733
    invoke-direct {v12, v10, v11}, Lmy0/c;-><init>(J)V

    .line 734
    .line 735
    .line 736
    goto :goto_10

    .line 737
    :cond_27
    const/4 v12, 0x0

    .line 738
    :goto_10
    invoke-virtual {v8}, Lcz/myskoda/api/bff_maps/v3/RateTableDto;->getOpeningHoursRates()Ljava/util/List;

    .line 739
    .line 740
    .line 741
    move-result-object v8

    .line 742
    check-cast v8, Ljava/lang/Iterable;

    .line 743
    .line 744
    new-instance v10, Ljava/util/ArrayList;

    .line 745
    .line 746
    invoke-static {v8, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 747
    .line 748
    .line 749
    move-result v11

    .line 750
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 751
    .line 752
    .line 753
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 754
    .line 755
    .line 756
    move-result-object v8

    .line 757
    :goto_11
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 758
    .line 759
    .line 760
    move-result v11

    .line 761
    if-eqz v11, :cond_31

    .line 762
    .line 763
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 764
    .line 765
    .line 766
    move-result-object v11

    .line 767
    check-cast v11, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningHoursRatesDto;

    .line 768
    .line 769
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningHoursRatesDto;->getPeriodStart()Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;

    .line 770
    .line 771
    .line 772
    move-result-object v13

    .line 773
    invoke-virtual {v13}, Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;->getValue()Ljava/lang/String;

    .line 774
    .line 775
    .line 776
    move-result-object v13

    .line 777
    invoke-static {v13}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 778
    .line 779
    .line 780
    move-result-object v13

    .line 781
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningHoursRatesDto;->getPeriodEnd()Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;

    .line 782
    .line 783
    .line 784
    move-result-object v14

    .line 785
    invoke-virtual {v14}, Lcz/myskoda/api/bff_maps/v3/DayOfWeekDto;->getValue()Ljava/lang/String;

    .line 786
    .line 787
    .line 788
    move-result-object v14

    .line 789
    invoke-static {v14}, Ljava/time/DayOfWeek;->valueOf(Ljava/lang/String;)Ljava/time/DayOfWeek;

    .line 790
    .line 791
    .line 792
    move-result-object v14

    .line 793
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningHoursRatesDto;->getOpeningTimesRates()Ljava/util/List;

    .line 794
    .line 795
    .line 796
    move-result-object v11

    .line 797
    check-cast v11, Ljava/lang/Iterable;

    .line 798
    .line 799
    new-instance v15, Ljava/util/ArrayList;

    .line 800
    .line 801
    invoke-static {v11, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 802
    .line 803
    .line 804
    move-result v4

    .line 805
    invoke-direct {v15, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 806
    .line 807
    .line 808
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 809
    .line 810
    .line 811
    move-result-object v4

    .line 812
    :goto_12
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 813
    .line 814
    .line 815
    move-result v11

    .line 816
    if-eqz v11, :cond_30

    .line 817
    .line 818
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 819
    .line 820
    .line 821
    move-result-object v11

    .line 822
    check-cast v11, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningTimeRatesDto;

    .line 823
    .line 824
    invoke-static {v11, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 825
    .line 826
    .line 827
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningTimeRatesDto;->getFrom()Ljava/lang/String;

    .line 828
    .line 829
    .line 830
    move-result-object v17

    .line 831
    invoke-static/range {v17 .. v17}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 832
    .line 833
    .line 834
    move-result-object v3

    .line 835
    const-string v6, "parse(...)"

    .line 836
    .line 837
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 838
    .line 839
    .line 840
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningTimeRatesDto;->getTo()Ljava/lang/String;

    .line 841
    .line 842
    .line 843
    move-result-object v19

    .line 844
    move-object/from16 v24, v0

    .line 845
    .line 846
    invoke-static/range {v19 .. v19}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 847
    .line 848
    .line 849
    move-result-object v0

    .line 850
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 851
    .line 852
    .line 853
    invoke-virtual {v11}, Lcz/myskoda/api/bff_maps/v3/ParkingOpeningTimeRatesDto;->getRates()Ljava/util/List;

    .line 854
    .line 855
    .line 856
    move-result-object v6

    .line 857
    check-cast v6, Ljava/lang/Iterable;

    .line 858
    .line 859
    new-instance v11, Ljava/util/ArrayList;

    .line 860
    .line 861
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 862
    .line 863
    .line 864
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 865
    .line 866
    .line 867
    move-result-object v6

    .line 868
    :goto_13
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 869
    .line 870
    .line 871
    move-result v19

    .line 872
    if-eqz v19, :cond_2f

    .line 873
    .line 874
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 875
    .line 876
    .line 877
    move-result-object v19

    .line 878
    move-object/from16 v20, v1

    .line 879
    .line 880
    move-object/from16 v1, v19

    .line 881
    .line 882
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/RateDto;

    .line 883
    .line 884
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 885
    .line 886
    .line 887
    move-object/from16 v19, v1

    .line 888
    .line 889
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getType()Ljava/lang/String;

    .line 890
    .line 891
    .line 892
    move-result-object v1

    .line 893
    move-object/from16 v21, v2

    .line 894
    .line 895
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 896
    .line 897
    .line 898
    move-result v2

    .line 899
    move-object/from16 v22, v4

    .line 900
    .line 901
    const v4, -0x4815c26c

    .line 902
    .line 903
    .line 904
    if-eq v2, v4, :cond_2c

    .line 905
    .line 906
    const v4, -0x3c65884e

    .line 907
    .line 908
    .line 909
    if-eq v2, v4, :cond_2a

    .line 910
    .line 911
    const v4, 0x77297f71

    .line 912
    .line 913
    .line 914
    if-eq v2, v4, :cond_28

    .line 915
    .line 916
    :goto_14
    move-object/from16 v31, v6

    .line 917
    .line 918
    move-object/from16 v23, v7

    .line 919
    .line 920
    goto :goto_15

    .line 921
    :cond_28
    const-string v2, "CUSTOM"

    .line 922
    .line 923
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 924
    .line 925
    .line 926
    move-result v1

    .line 927
    if-nez v1, :cond_29

    .line 928
    .line 929
    goto :goto_14

    .line 930
    :cond_29
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getValue()Ljava/lang/String;

    .line 931
    .line 932
    .line 933
    move-result-object v1

    .line 934
    move-object v2, v6

    .line 935
    move-object/from16 v23, v7

    .line 936
    .line 937
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getPrice()D

    .line 938
    .line 939
    .line 940
    move-result-wide v6

    .line 941
    new-instance v4, Lvk0/n0;

    .line 942
    .line 943
    invoke-direct {v4, v6, v7, v1}, Lvk0/n0;-><init>(DLjava/lang/String;)V

    .line 944
    .line 945
    .line 946
    move-object/from16 v31, v2

    .line 947
    .line 948
    goto :goto_16

    .line 949
    :cond_2a
    move-object v2, v6

    .line 950
    move-object/from16 v23, v7

    .line 951
    .line 952
    const-string v4, "DURATION_ADDITIONAL"

    .line 953
    .line 954
    invoke-virtual {v1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 955
    .line 956
    .line 957
    move-result v1

    .line 958
    if-nez v1, :cond_2b

    .line 959
    .line 960
    move-object/from16 v31, v2

    .line 961
    .line 962
    goto :goto_15

    .line 963
    :cond_2b
    sget v1, Lmy0/c;->g:I

    .line 964
    .line 965
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getValue()Ljava/lang/String;

    .line 966
    .line 967
    .line 968
    move-result-object v1

    .line 969
    invoke-static {v1}, Lmy0/h;->o(Ljava/lang/String;)J

    .line 970
    .line 971
    .line 972
    move-result-wide v6

    .line 973
    move-object v4, v2

    .line 974
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getPrice()D

    .line 975
    .line 976
    .line 977
    move-result-wide v1

    .line 978
    move-object/from16 v31, v4

    .line 979
    .line 980
    new-instance v4, Lvk0/m0;

    .line 981
    .line 982
    invoke-direct {v4, v1, v2, v6, v7}, Lvk0/m0;-><init>(DJ)V

    .line 983
    .line 984
    .line 985
    goto :goto_16

    .line 986
    :cond_2c
    move-object/from16 v31, v6

    .line 987
    .line 988
    move-object/from16 v23, v7

    .line 989
    .line 990
    const-string v2, "DURATION"

    .line 991
    .line 992
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 993
    .line 994
    .line 995
    move-result v1

    .line 996
    if-eqz v1, :cond_2d

    .line 997
    .line 998
    sget v1, Lmy0/c;->g:I

    .line 999
    .line 1000
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getValue()Ljava/lang/String;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v1

    .line 1004
    invoke-static {v1}, Lmy0/h;->o(Ljava/lang/String;)J

    .line 1005
    .line 1006
    .line 1007
    move-result-wide v1

    .line 1008
    invoke-virtual/range {v19 .. v19}, Lcz/myskoda/api/bff_maps/v3/RateDto;->getPrice()D

    .line 1009
    .line 1010
    .line 1011
    move-result-wide v6

    .line 1012
    new-instance v4, Lvk0/o0;

    .line 1013
    .line 1014
    invoke-direct {v4, v6, v7, v1, v2}, Lvk0/o0;-><init>(DJ)V

    .line 1015
    .line 1016
    .line 1017
    goto :goto_16

    .line 1018
    :cond_2d
    :goto_15
    const/4 v4, 0x0

    .line 1019
    :goto_16
    if-eqz v4, :cond_2e

    .line 1020
    .line 1021
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1022
    .line 1023
    .line 1024
    :cond_2e
    move-object/from16 v1, v20

    .line 1025
    .line 1026
    move-object/from16 v2, v21

    .line 1027
    .line 1028
    move-object/from16 v4, v22

    .line 1029
    .line 1030
    move-object/from16 v7, v23

    .line 1031
    .line 1032
    move-object/from16 v6, v31

    .line 1033
    .line 1034
    goto/16 :goto_13

    .line 1035
    .line 1036
    :cond_2f
    move-object/from16 v20, v1

    .line 1037
    .line 1038
    move-object/from16 v21, v2

    .line 1039
    .line 1040
    move-object/from16 v22, v4

    .line 1041
    .line 1042
    move-object/from16 v23, v7

    .line 1043
    .line 1044
    new-instance v1, Lvk0/f0;

    .line 1045
    .line 1046
    invoke-direct {v1, v3, v0, v11}, Lvk0/f0;-><init>(Ljava/time/LocalTime;Ljava/time/LocalTime;Ljava/util/ArrayList;)V

    .line 1047
    .line 1048
    .line 1049
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1050
    .line 1051
    .line 1052
    move-object/from16 v1, v20

    .line 1053
    .line 1054
    move-object/from16 v0, v24

    .line 1055
    .line 1056
    const/16 v3, 0xa

    .line 1057
    .line 1058
    const/4 v6, 0x1

    .line 1059
    goto/16 :goto_12

    .line 1060
    .line 1061
    :cond_30
    move-object/from16 v24, v0

    .line 1062
    .line 1063
    move-object/from16 v20, v1

    .line 1064
    .line 1065
    move-object/from16 v21, v2

    .line 1066
    .line 1067
    move-object/from16 v23, v7

    .line 1068
    .line 1069
    new-instance v0, Lvk0/h0;

    .line 1070
    .line 1071
    invoke-direct {v0, v13, v14, v15}, Lvk0/h0;-><init>(Ljava/time/DayOfWeek;Ljava/time/DayOfWeek;Ljava/util/ArrayList;)V

    .line 1072
    .line 1073
    .line 1074
    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1075
    .line 1076
    .line 1077
    move-object/from16 v0, v24

    .line 1078
    .line 1079
    const/16 v3, 0xa

    .line 1080
    .line 1081
    const/4 v6, 0x1

    .line 1082
    goto/16 :goto_11

    .line 1083
    .line 1084
    :cond_31
    move-object/from16 v24, v0

    .line 1085
    .line 1086
    move-object/from16 v20, v1

    .line 1087
    .line 1088
    move-object/from16 v21, v2

    .line 1089
    .line 1090
    move-object/from16 v23, v7

    .line 1091
    .line 1092
    new-instance v0, Lvk0/q0;

    .line 1093
    .line 1094
    invoke-direct {v0, v9, v12, v10}, Lvk0/q0;-><init>(Lvk0/r0;Lmy0/c;Ljava/util/ArrayList;)V

    .line 1095
    .line 1096
    .line 1097
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1098
    .line 1099
    .line 1100
    move-object/from16 v0, v24

    .line 1101
    .line 1102
    const/16 v3, 0xa

    .line 1103
    .line 1104
    const/4 v6, 0x1

    .line 1105
    goto/16 :goto_d

    .line 1106
    .line 1107
    :cond_32
    move-object/from16 v24, v0

    .line 1108
    .line 1109
    move-object/from16 v23, v7

    .line 1110
    .line 1111
    :goto_17
    move-object/from16 v32, v5

    .line 1112
    .line 1113
    goto :goto_18

    .line 1114
    :cond_33
    move-object/from16 v24, v0

    .line 1115
    .line 1116
    move-object/from16 v23, v7

    .line 1117
    .line 1118
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 1119
    .line 1120
    goto :goto_17

    .line 1121
    :goto_18
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v0

    .line 1125
    if-eqz v0, :cond_34

    .line 1126
    .line 1127
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->getRestrictions()Lcz/myskoda/api/bff_maps/v3/RestrictionsDto;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v0

    .line 1131
    if-eqz v0, :cond_34

    .line 1132
    .line 1133
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/RestrictionsDto;->getRestrictions()Ljava/util/List;

    .line 1134
    .line 1135
    .line 1136
    move-result-object v0

    .line 1137
    if-eqz v0, :cond_34

    .line 1138
    .line 1139
    const-string v1, "NO_RESTR_OUT_HOURS"

    .line 1140
    .line 1141
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 1142
    .line 1143
    .line 1144
    move-result v0

    .line 1145
    const/4 v1, 0x1

    .line 1146
    if-ne v0, v1, :cond_34

    .line 1147
    .line 1148
    move/from16 v33, v1

    .line 1149
    .line 1150
    goto :goto_19

    .line 1151
    :cond_34
    const/16 v33, 0x0

    .line 1152
    .line 1153
    :goto_19
    invoke-virtual/range {p0 .. p0}, Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;->getParking()Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v0

    .line 1157
    if-eqz v0, :cond_35

    .line 1158
    .line 1159
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/ParkingDetailDto;->isOpen24h()Ljava/lang/Boolean;

    .line 1160
    .line 1161
    .line 1162
    move-result-object v0

    .line 1163
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1164
    .line 1165
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1166
    .line 1167
    .line 1168
    move-result v3

    .line 1169
    move/from16 v34, v3

    .line 1170
    .line 1171
    goto :goto_1a

    .line 1172
    :cond_35
    const/16 v34, 0x0

    .line 1173
    .line 1174
    :goto_1a
    new-instance v22, Lvk0/d0;

    .line 1175
    .line 1176
    const/16 v31, 0x0

    .line 1177
    .line 1178
    move/from16 v35, p1

    .line 1179
    .line 1180
    invoke-direct/range {v22 .. v35}, Lvk0/d0;-><init>(Lvk0/d;Ljava/net/URL;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lon0/s;Lon0/t;Ljava/util/List;ZZZ)V

    .line 1181
    .line 1182
    .line 1183
    return-object v22

    .line 1184
    :cond_36
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1185
    .line 1186
    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1187
    .line 1188
    .line 1189
    throw v0

    .line 1190
    :cond_37
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1191
    .line 1192
    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1193
    .line 1194
    .line 1195
    throw v0

    .line 1196
    nop

    .line 1197
    :sswitch_data_0
    .sparse-switch
        -0x79209ddf -> :sswitch_16
        -0x72e5b63b -> :sswitch_15
        -0x6d8bcc51 -> :sswitch_14
        -0x6760f53b -> :sswitch_13
        -0x615bbfa0 -> :sswitch_12
        -0x59d7dc3d -> :sswitch_11
        -0x4fbf10f7 -> :sswitch_10
        -0x4cf0e12b -> :sswitch_f
        0x3f47a7a -> :sswitch_e
        0x4da9770 -> :sswitch_d
        0x19d1382a -> :sswitch_c
        0x1a513479 -> :sswitch_b
        0x237978da -> :sswitch_a
        0x2d44fcb5 -> :sswitch_9
        0x3228f3f7 -> :sswitch_8
        0x386e7cd3 -> :sswitch_7
        0x3ca59937 -> :sswitch_6
        0x47d5b162 -> :sswitch_5
        0x50948df0 -> :sswitch_4
        0x52c76fde -> :sswitch_3
        0x5cbb33d3 -> :sswitch_2
        0x66672f07 -> :sswitch_1
        0x784f660e -> :sswitch_0
    .end sparse-switch
.end method

.method public static d(I[Ljava/lang/Object;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    if-ge v0, p0, :cond_1

    .line 3
    .line 4
    aget-object v1, p1, v0

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    add-int/lit8 v0, v0, 0x1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 12
    .line 13
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    new-instance v1, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    add-int/lit8 p1, p1, 0x9

    .line 24
    .line 25
    invoke-direct {v1, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const-string p1, "at index "

    .line 29
    .line 30
    invoke-static {v0, p1, v1}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    return-void
.end method
