.class public final synthetic Li70/q;
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
    iput p1, p0, Li70/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Li70/r;)V
    .locals 0

    .line 2
    const/4 p1, 0x0

    iput p1, p0, Li70/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 69

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Li70/q;->d:I

    .line 4
    .line 5
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    const-class v3, Lretrofit2/Retrofit;

    .line 8
    .line 9
    const/16 v4, 0xb

    .line 10
    .line 11
    const-string v5, "$this$module"

    .line 12
    .line 13
    const-string v6, "<this>"

    .line 14
    .line 15
    const-string v7, "$this$log"

    .line 16
    .line 17
    const-string v8, "_connection"

    .line 18
    .line 19
    const-wide v9, 0x408f400000000000L    # 1000.0

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    const/4 v11, 0x0

    .line 25
    const/16 v12, 0xa

    .line 26
    .line 27
    const-string v13, "it"

    .line 28
    .line 29
    const-string v14, "$this$request"

    .line 30
    .line 31
    sget-object v15, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    packed-switch v0, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    move-object/from16 v0, p1

    .line 37
    .line 38
    check-cast v0, Le21/a;

    .line 39
    .line 40
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    new-instance v10, Li91/i0;

    .line 44
    .line 45
    const/16 v1, 0x9

    .line 46
    .line 47
    invoke-direct {v10, v1}, Li91/i0;-><init>(I)V

    .line 48
    .line 49
    .line 50
    sget-object v17, Li21/b;->e:Lh21/b;

    .line 51
    .line 52
    sget-object v21, La21/c;->e:La21/c;

    .line 53
    .line 54
    new-instance v6, La21/a;

    .line 55
    .line 56
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 57
    .line 58
    const-class v2, Lcz/myskoda/api/idk/ConsentControllerApi;

    .line 59
    .line 60
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    const/4 v9, 0x0

    .line 65
    move-object/from16 v7, v17

    .line 66
    .line 67
    move-object/from16 v11, v21

    .line 68
    .line 69
    invoke-direct/range {v6 .. v11}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 70
    .line 71
    .line 72
    new-instance v2, Lc21/a;

    .line 73
    .line 74
    invoke-direct {v2, v6}, Lc21/b;-><init>(La21/a;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 78
    .line 79
    .line 80
    new-instance v2, Li91/i0;

    .line 81
    .line 82
    invoke-direct {v2, v12}, Li91/i0;-><init>(I)V

    .line 83
    .line 84
    .line 85
    new-instance v16, La21/a;

    .line 86
    .line 87
    const-class v5, Lli0/b;

    .line 88
    .line 89
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 90
    .line 91
    .line 92
    move-result-object v18

    .line 93
    const/16 v19, 0x0

    .line 94
    .line 95
    move-object/from16 v20, v2

    .line 96
    .line 97
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 98
    .line 99
    .line 100
    move-object/from16 v2, v16

    .line 101
    .line 102
    new-instance v5, Lc21/a;

    .line 103
    .line 104
    invoke-direct {v5, v2}, Lc21/b;-><init>(La21/a;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0, v5}, Le21/a;->a(Lc21/b;)V

    .line 108
    .line 109
    .line 110
    new-instance v2, Lhd0/a;

    .line 111
    .line 112
    const/4 v5, 0x6

    .line 113
    invoke-direct {v2, v5}, Lhd0/a;-><init>(I)V

    .line 114
    .line 115
    .line 116
    new-instance v16, La21/a;

    .line 117
    .line 118
    const-class v5, Lji0/b;

    .line 119
    .line 120
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 121
    .line 122
    .line 123
    move-result-object v18

    .line 124
    move-object/from16 v20, v2

    .line 125
    .line 126
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 127
    .line 128
    .line 129
    move-object/from16 v2, v16

    .line 130
    .line 131
    new-instance v5, Lc21/a;

    .line 132
    .line 133
    invoke-direct {v5, v2}, Lc21/b;-><init>(La21/a;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0, v5}, Le21/a;->a(Lc21/b;)V

    .line 137
    .line 138
    .line 139
    const-string v2, "idk-api-retrofit"

    .line 140
    .line 141
    invoke-static {v2}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 142
    .line 143
    .line 144
    move-result-object v19

    .line 145
    new-instance v2, Li91/i0;

    .line 146
    .line 147
    invoke-direct {v2, v4}, Li91/i0;-><init>(I)V

    .line 148
    .line 149
    .line 150
    sget-object v21, La21/c;->d:La21/c;

    .line 151
    .line 152
    new-instance v16, La21/a;

    .line 153
    .line 154
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 155
    .line 156
    .line 157
    move-result-object v18

    .line 158
    move-object/from16 v20, v2

    .line 159
    .line 160
    invoke-direct/range {v16 .. v21}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 161
    .line 162
    .line 163
    move-object/from16 v1, v16

    .line 164
    .line 165
    invoke-static {v1, v0}, Lf2/m0;->t(La21/a;Le21/a;)V

    .line 166
    .line 167
    .line 168
    return-object v15

    .line 169
    :pswitch_0
    move-object/from16 v0, p1

    .line 170
    .line 171
    check-cast v0, Lhy0/d;

    .line 172
    .line 173
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-interface {v0}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    if-eqz v0, :cond_0

    .line 181
    .line 182
    goto :goto_0

    .line 183
    :cond_0
    const-string v0, "unknown"

    .line 184
    .line 185
    :goto_0
    return-object v0

    .line 186
    :pswitch_1
    move-object/from16 v0, p1

    .line 187
    .line 188
    check-cast v0, Lgi/c;

    .line 189
    .line 190
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    const-string v0, "Closing Lokator instance"

    .line 194
    .line 195
    return-object v0

    .line 196
    :pswitch_2
    move-object/from16 v0, p1

    .line 197
    .line 198
    check-cast v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;

    .line 199
    .line 200
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getCapturedAt()Ljava/time/OffsetDateTime;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getInspectionDueInDays()Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getInspectionDueInKm()Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    if-eqz v1, :cond_1

    .line 216
    .line 217
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    int-to-double v4, v1

    .line 222
    mul-double/2addr v4, v9

    .line 223
    new-instance v1, Lqr0/d;

    .line 224
    .line 225
    invoke-direct {v1, v4, v5}, Lqr0/d;-><init>(D)V

    .line 226
    .line 227
    .line 228
    move-object v4, v1

    .line 229
    goto :goto_1

    .line 230
    :cond_1
    move-object v4, v11

    .line 231
    :goto_1
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getMileageInKm()Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    if-eqz v1, :cond_2

    .line 236
    .line 237
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    int-to-double v5, v1

    .line 242
    mul-double/2addr v5, v9

    .line 243
    new-instance v1, Lqr0/d;

    .line 244
    .line 245
    invoke-direct {v1, v5, v6}, Lqr0/d;-><init>(D)V

    .line 246
    .line 247
    .line 248
    move-object v5, v1

    .line 249
    goto :goto_2

    .line 250
    :cond_2
    move-object v5, v11

    .line 251
    :goto_2
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getOilServiceDueInDays()Ljava/lang/Integer;

    .line 252
    .line 253
    .line 254
    move-result-object v6

    .line 255
    invoke-virtual {v0}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;->getOilServiceDueInKm()Ljava/lang/Integer;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    if-eqz v0, :cond_3

    .line 260
    .line 261
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 262
    .line 263
    .line 264
    move-result v0

    .line 265
    int-to-double v0, v0

    .line 266
    mul-double/2addr v0, v9

    .line 267
    new-instance v11, Lqr0/d;

    .line 268
    .line 269
    invoke-direct {v11, v0, v1}, Lqr0/d;-><init>(D)V

    .line 270
    .line 271
    .line 272
    :cond_3
    move-object v7, v11

    .line 273
    new-instance v1, Llf0/a;

    .line 274
    .line 275
    invoke-direct/range {v1 .. v7}, Llf0/a;-><init>(Ljava/time/OffsetDateTime;Ljava/lang/Integer;Lqr0/d;Lqr0/d;Ljava/lang/Integer;Lqr0/d;)V

    .line 276
    .line 277
    .line 278
    return-object v1

    .line 279
    :pswitch_3
    move-object/from16 v0, p1

    .line 280
    .line 281
    check-cast v0, Lcz/myskoda/api/bff/v1/RendersDto;

    .line 282
    .line 283
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/RendersDto;->getCompositeRenders()Ljava/util/List;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    check-cast v0, Ljava/lang/Iterable;

    .line 291
    .line 292
    new-instance v1, Ljava/util/ArrayList;

    .line 293
    .line 294
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 295
    .line 296
    .line 297
    move-result v2

    .line 298
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 299
    .line 300
    .line 301
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 306
    .line 307
    .line 308
    move-result v2

    .line 309
    if-eqz v2, :cond_4

    .line 310
    .line 311
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v2

    .line 315
    check-cast v2, Lcz/myskoda/api/bff/v1/CompositeRenderDto;

    .line 316
    .line 317
    invoke-static {v2}, Lif0/b;->a(Lcz/myskoda/api/bff/v1/CompositeRenderDto;)Lhp0/e;

    .line 318
    .line 319
    .line 320
    move-result-object v2

    .line 321
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    goto :goto_3

    .line 325
    :cond_4
    return-object v1

    .line 326
    :pswitch_4
    move-object/from16 v0, p1

    .line 327
    .line 328
    check-cast v0, Lcz/myskoda/api/bff/v1/VehicleInformationDto;

    .line 329
    .line 330
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleInformationDto;->getDevicePlatform()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    const v3, 0x1294d

    .line 345
    .line 346
    .line 347
    if-eq v2, v3, :cond_9

    .line 348
    .line 349
    const v3, 0x288ffd

    .line 350
    .line 351
    .line 352
    if-eq v2, v3, :cond_7

    .line 353
    .line 354
    const v3, 0x5dae1b29

    .line 355
    .line 356
    .line 357
    if-eq v2, v3, :cond_5

    .line 358
    .line 359
    goto :goto_4

    .line 360
    :cond_5
    const-string v2, "MBB_ODP"

    .line 361
    .line 362
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 363
    .line 364
    .line 365
    move-result v1

    .line 366
    if-nez v1, :cond_6

    .line 367
    .line 368
    goto :goto_4

    .line 369
    :cond_6
    sget-object v1, Lss0/n;->e:Lss0/n;

    .line 370
    .line 371
    goto :goto_5

    .line 372
    :cond_7
    const-string v2, "WCAR"

    .line 373
    .line 374
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    move-result v1

    .line 378
    if-nez v1, :cond_8

    .line 379
    .line 380
    goto :goto_4

    .line 381
    :cond_8
    sget-object v1, Lss0/n;->f:Lss0/n;

    .line 382
    .line 383
    goto :goto_5

    .line 384
    :cond_9
    const-string v2, "MBB"

    .line 385
    .line 386
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 387
    .line 388
    .line 389
    move-result v1

    .line 390
    if-eqz v1, :cond_a

    .line 391
    .line 392
    sget-object v1, Lss0/n;->d:Lss0/n;

    .line 393
    .line 394
    goto :goto_5

    .line 395
    :cond_a
    :goto_4
    sget-object v1, Lss0/n;->h:Lss0/n;

    .line 396
    .line 397
    :goto_5
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleInformationDto;->getCompositeRenders()Ljava/util/List;

    .line 398
    .line 399
    .line 400
    move-result-object v2

    .line 401
    check-cast v2, Ljava/lang/Iterable;

    .line 402
    .line 403
    new-instance v3, Ljava/util/ArrayList;

    .line 404
    .line 405
    invoke-static {v2, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 406
    .line 407
    .line 408
    move-result v4

    .line 409
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 410
    .line 411
    .line 412
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 413
    .line 414
    .line 415
    move-result-object v2

    .line 416
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 417
    .line 418
    .line 419
    move-result v4

    .line 420
    if-eqz v4, :cond_b

    .line 421
    .line 422
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    check-cast v4, Lcz/myskoda/api/bff/v1/CompositeRenderDto;

    .line 427
    .line 428
    invoke-static {v4}, Lif0/b;->a(Lcz/myskoda/api/bff/v1/CompositeRenderDto;)Lhp0/e;

    .line 429
    .line 430
    .line 431
    move-result-object v4

    .line 432
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 433
    .line 434
    .line 435
    goto :goto_6

    .line 436
    :cond_b
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleInformationDto;->getVehicleSpecification()Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    if-eqz v0, :cond_e

    .line 441
    .line 442
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getTitle()Ljava/lang/String;

    .line 443
    .line 444
    .line 445
    move-result-object v13

    .line 446
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getSystemCode()Ljava/lang/String;

    .line 447
    .line 448
    .line 449
    move-result-object v14

    .line 450
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getSystemModelId()Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v15

    .line 454
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getModel()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v16

    .line 458
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getManufacturingDate()Ljava/time/LocalDate;

    .line 459
    .line 460
    .line 461
    move-result-object v17

    .line 462
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getBody()Ljava/lang/String;

    .line 463
    .line 464
    .line 465
    move-result-object v20

    .line 466
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getEngine()Lcz/myskoda/api/bff/v1/VehicleSpecificationEngineDto;

    .line 467
    .line 468
    .line 469
    move-result-object v2

    .line 470
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 471
    .line 472
    .line 473
    new-instance v4, Lss0/o;

    .line 474
    .line 475
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/VehicleSpecificationEngineDto;->getPowerInKW()I

    .line 476
    .line 477
    .line 478
    move-result v5

    .line 479
    int-to-double v7, v5

    .line 480
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/VehicleSpecificationEngineDto;->getType()Ljava/lang/String;

    .line 481
    .line 482
    .line 483
    move-result-object v5

    .line 484
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/VehicleSpecificationEngineDto;->getCapacityInLiters()Ljava/lang/Float;

    .line 485
    .line 486
    .line 487
    move-result-object v2

    .line 488
    invoke-direct {v4, v7, v8, v5, v2}, Lss0/o;-><init>(DLjava/lang/String;Ljava/lang/Float;)V

    .line 489
    .line 490
    .line 491
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getBattery()Lcz/myskoda/api/bff/v1/VehicleSpecificationBatteryDto;

    .line 492
    .line 493
    .line 494
    move-result-object v2

    .line 495
    if-eqz v2, :cond_c

    .line 496
    .line 497
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/VehicleSpecificationBatteryDto;->getCapacityInKWh()I

    .line 498
    .line 499
    .line 500
    move-result v2

    .line 501
    new-instance v5, Lqr0/h;

    .line 502
    .line 503
    invoke-direct {v5, v2}, Lqr0/h;-><init>(I)V

    .line 504
    .line 505
    .line 506
    move-object/from16 v21, v5

    .line 507
    .line 508
    goto :goto_7

    .line 509
    :cond_c
    move-object/from16 v21, v11

    .line 510
    .line 511
    :goto_7
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getGearbox()Lcz/myskoda/api/bff/v1/VehicleSpecificationGearboxDto;

    .line 512
    .line 513
    .line 514
    move-result-object v2

    .line 515
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 516
    .line 517
    .line 518
    sget-object v5, Lss0/p;->d:La61/a;

    .line 519
    .line 520
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/VehicleSpecificationGearboxDto;->getType()Ljava/lang/String;

    .line 521
    .line 522
    .line 523
    move-result-object v2

    .line 524
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 525
    .line 526
    .line 527
    invoke-static {v2}, La61/a;->q(Ljava/lang/String;)Lss0/p;

    .line 528
    .line 529
    .line 530
    move-result-object v19

    .line 531
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getTrimLevel()Ljava/lang/String;

    .line 532
    .line 533
    .line 534
    move-result-object v22

    .line 535
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getMaxChargingPowerInKW()Ljava/lang/Integer;

    .line 536
    .line 537
    .line 538
    move-result-object v2

    .line 539
    if-eqz v2, :cond_d

    .line 540
    .line 541
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 542
    .line 543
    .line 544
    move-result v2

    .line 545
    int-to-double v5, v2

    .line 546
    new-instance v2, Lqr0/n;

    .line 547
    .line 548
    invoke-direct {v2, v5, v6}, Lqr0/n;-><init>(D)V

    .line 549
    .line 550
    .line 551
    move-object/from16 v23, v2

    .line 552
    .line 553
    goto :goto_8

    .line 554
    :cond_d
    move-object/from16 v23, v11

    .line 555
    .line 556
    :goto_8
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/VehicleSpecificationDto;->getModelYear()Ljava/lang/String;

    .line 557
    .line 558
    .line 559
    move-result-object v24

    .line 560
    new-instance v12, Lss0/l;

    .line 561
    .line 562
    new-instance v0, Lss0/b0;

    .line 563
    .line 564
    invoke-direct {v0, v11, v11, v11}, Lss0/b0;-><init>(Lqr0/b;Lqr0/b;Lqr0/b;)V

    .line 565
    .line 566
    .line 567
    const/16 v26, 0x0

    .line 568
    .line 569
    move-object/from16 v25, v0

    .line 570
    .line 571
    move-object/from16 v18, v4

    .line 572
    .line 573
    invoke-direct/range {v12 .. v26}, Lss0/l;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/o;Lss0/p;Ljava/lang/String;Lqr0/h;Ljava/lang/String;Lqr0/n;Ljava/lang/String;Lss0/b0;Ljava/lang/String;)V

    .line 574
    .line 575
    .line 576
    move-object v11, v12

    .line 577
    :cond_e
    new-instance v0, Llf0/e;

    .line 578
    .line 579
    invoke-direct {v0, v1, v3, v11}, Llf0/e;-><init>(Lss0/n;Ljava/util/ArrayList;Lss0/l;)V

    .line 580
    .line 581
    .line 582
    return-object v0

    .line 583
    :pswitch_5
    move-object/from16 v0, p1

    .line 584
    .line 585
    check-cast v0, Lcz/myskoda/api/bff_garage/v2/VehicleDto;

    .line 586
    .line 587
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 588
    .line 589
    .line 590
    invoke-static {v0}, Lif0/b;->b(Lcz/myskoda/api/bff_garage/v2/VehicleDto;)Lss0/k;

    .line 591
    .line 592
    .line 593
    move-result-object v0

    .line 594
    return-object v0

    .line 595
    :pswitch_6
    move-object/from16 v0, p1

    .line 596
    .line 597
    check-cast v0, Lcz/myskoda/api/bff_garage/v2/VehicleDto;

    .line 598
    .line 599
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    invoke-static {v0}, Lif0/b;->b(Lcz/myskoda/api/bff_garage/v2/VehicleDto;)Lss0/k;

    .line 603
    .line 604
    .line 605
    move-result-object v0

    .line 606
    return-object v0

    .line 607
    :pswitch_7
    move-object/from16 v0, p1

    .line 608
    .line 609
    check-cast v0, Lua/a;

    .line 610
    .line 611
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    const-string v1, "DELETE FROM vehicle"

    .line 615
    .line 616
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 617
    .line 618
    .line 619
    move-result-object v1

    .line 620
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 621
    .line 622
    .line 623
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 624
    .line 625
    .line 626
    return-object v15

    .line 627
    :catchall_0
    move-exception v0

    .line 628
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 629
    .line 630
    .line 631
    throw v0

    .line 632
    :pswitch_8
    move-object/from16 v0, p1

    .line 633
    .line 634
    check-cast v0, Lua/a;

    .line 635
    .line 636
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    const-string v1, "DELETE FROM capability_error"

    .line 640
    .line 641
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 642
    .line 643
    .line 644
    move-result-object v1

    .line 645
    :try_start_1
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 646
    .line 647
    .line 648
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 649
    .line 650
    .line 651
    return-object v15

    .line 652
    :catchall_1
    move-exception v0

    .line 653
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 654
    .line 655
    .line 656
    throw v0

    .line 657
    :pswitch_9
    move-object/from16 v0, p1

    .line 658
    .line 659
    check-cast v0, Lss0/f;

    .line 660
    .line 661
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 665
    .line 666
    .line 667
    move-result-object v0

    .line 668
    return-object v0

    .line 669
    :pswitch_a
    move-object/from16 v0, p1

    .line 670
    .line 671
    check-cast v0, Lua/a;

    .line 672
    .line 673
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    const-string v1, "DELETE FROM capability"

    .line 677
    .line 678
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    :try_start_2
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 683
    .line 684
    .line 685
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 686
    .line 687
    .line 688
    return-object v15

    .line 689
    :catchall_2
    move-exception v0

    .line 690
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 691
    .line 692
    .line 693
    throw v0

    .line 694
    :pswitch_b
    move-object/from16 v0, p1

    .line 695
    .line 696
    check-cast v0, Le21/a;

    .line 697
    .line 698
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 699
    .line 700
    .line 701
    new-instance v10, Lhd0/a;

    .line 702
    .line 703
    const/4 v1, 0x2

    .line 704
    invoke-direct {v10, v1}, Lhd0/a;-><init>(I)V

    .line 705
    .line 706
    .line 707
    sget-object v3, Li21/b;->e:Lh21/b;

    .line 708
    .line 709
    sget-object v7, La21/c;->e:La21/c;

    .line 710
    .line 711
    new-instance v6, La21/a;

    .line 712
    .line 713
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 714
    .line 715
    const-class v2, Lje0/a;

    .line 716
    .line 717
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 718
    .line 719
    .line 720
    move-result-object v8

    .line 721
    const/4 v9, 0x0

    .line 722
    move-object v11, v7

    .line 723
    move-object v7, v3

    .line 724
    invoke-direct/range {v6 .. v11}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 725
    .line 726
    .line 727
    move-object v7, v11

    .line 728
    new-instance v2, Lc21/a;

    .line 729
    .line 730
    invoke-direct {v2, v6}, Lc21/b;-><init>(La21/a;)V

    .line 731
    .line 732
    .line 733
    invoke-virtual {v0, v2}, Le21/a;->a(Lc21/b;)V

    .line 734
    .line 735
    .line 736
    new-instance v6, Lhd0/a;

    .line 737
    .line 738
    const/4 v2, 0x3

    .line 739
    invoke-direct {v6, v2}, Lhd0/a;-><init>(I)V

    .line 740
    .line 741
    .line 742
    new-instance v2, La21/a;

    .line 743
    .line 744
    const-class v4, Lje0/d;

    .line 745
    .line 746
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 747
    .line 748
    .line 749
    move-result-object v4

    .line 750
    const/4 v5, 0x0

    .line 751
    invoke-direct/range {v2 .. v7}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 752
    .line 753
    .line 754
    new-instance v4, Lc21/a;

    .line 755
    .line 756
    invoke-direct {v4, v2}, Lc21/b;-><init>(La21/a;)V

    .line 757
    .line 758
    .line 759
    invoke-virtual {v0, v4}, Le21/a;->a(Lc21/b;)V

    .line 760
    .line 761
    .line 762
    new-instance v6, Lhd0/a;

    .line 763
    .line 764
    const/4 v2, 0x4

    .line 765
    invoke-direct {v6, v2}, Lhd0/a;-><init>(I)V

    .line 766
    .line 767
    .line 768
    new-instance v2, La21/a;

    .line 769
    .line 770
    const-class v4, Lhe0/b;

    .line 771
    .line 772
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 773
    .line 774
    .line 775
    move-result-object v4

    .line 776
    invoke-direct/range {v2 .. v7}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 777
    .line 778
    .line 779
    new-instance v4, Lc21/a;

    .line 780
    .line 781
    invoke-direct {v4, v2}, Lc21/b;-><init>(La21/a;)V

    .line 782
    .line 783
    .line 784
    invoke-virtual {v0, v4}, Le21/a;->a(Lc21/b;)V

    .line 785
    .line 786
    .line 787
    const-class v2, Lje0/b;

    .line 788
    .line 789
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 790
    .line 791
    .line 792
    move-result-object v2

    .line 793
    const-string v5, "clazz"

    .line 794
    .line 795
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 796
    .line 797
    .line 798
    iget-object v5, v4, Lc21/b;->a:La21/a;

    .line 799
    .line 800
    iget-object v6, v5, La21/a;->f:Ljava/lang/Object;

    .line 801
    .line 802
    check-cast v6, Ljava/util/Collection;

    .line 803
    .line 804
    invoke-static {v6, v2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 805
    .line 806
    .line 807
    move-result-object v6

    .line 808
    iput-object v6, v5, La21/a;->f:Ljava/lang/Object;

    .line 809
    .line 810
    iget-object v6, v5, La21/a;->c:Lh21/a;

    .line 811
    .line 812
    iget-object v5, v5, La21/a;->a:Lh21/a;

    .line 813
    .line 814
    new-instance v8, Ljava/lang/StringBuilder;

    .line 815
    .line 816
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 817
    .line 818
    .line 819
    const/16 v9, 0x3a

    .line 820
    .line 821
    invoke-static {v2, v8, v9}, Lia/b;->s(Lhy0/d;Ljava/lang/StringBuilder;C)V

    .line 822
    .line 823
    .line 824
    if-eqz v6, :cond_f

    .line 825
    .line 826
    invoke-interface {v6}, Lh21/a;->getValue()Ljava/lang/String;

    .line 827
    .line 828
    .line 829
    move-result-object v2

    .line 830
    if-nez v2, :cond_10

    .line 831
    .line 832
    :cond_f
    const-string v2, ""

    .line 833
    .line 834
    :cond_10
    invoke-static {v8, v2, v9, v5}, Lia/b;->h(Ljava/lang/StringBuilder;Ljava/lang/String;CLh21/a;)Ljava/lang/String;

    .line 835
    .line 836
    .line 837
    move-result-object v2

    .line 838
    invoke-virtual {v0, v2, v4}, Le21/a;->b(Ljava/lang/String;Lc21/b;)V

    .line 839
    .line 840
    .line 841
    new-instance v6, Lhd0/a;

    .line 842
    .line 843
    const/4 v2, 0x5

    .line 844
    invoke-direct {v6, v2}, Lhd0/a;-><init>(I)V

    .line 845
    .line 846
    .line 847
    new-instance v2, La21/a;

    .line 848
    .line 849
    const-class v4, Lke0/a;

    .line 850
    .line 851
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 852
    .line 853
    .line 854
    move-result-object v4

    .line 855
    const/4 v5, 0x0

    .line 856
    invoke-direct/range {v2 .. v7}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 857
    .line 858
    .line 859
    invoke-static {v2, v0}, Lvj/b;->v(La21/a;Le21/a;)V

    .line 860
    .line 861
    .line 862
    return-object v15

    .line 863
    :pswitch_c
    move-object/from16 v0, p1

    .line 864
    .line 865
    check-cast v0, Lhi/a;

    .line 866
    .line 867
    const-string v1, "$this$single"

    .line 868
    .line 869
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 870
    .line 871
    .line 872
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 873
    .line 874
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 875
    .line 876
    .line 877
    move-result-object v1

    .line 878
    check-cast v0, Lii/a;

    .line 879
    .line 880
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 881
    .line 882
    .line 883
    move-result-object v0

    .line 884
    check-cast v0, Lretrofit2/Retrofit;

    .line 885
    .line 886
    const-class v1, Lke/g;

    .line 887
    .line 888
    invoke-virtual {v0, v1}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v0

    .line 892
    check-cast v0, Lke/g;

    .line 893
    .line 894
    new-instance v1, Lke/f;

    .line 895
    .line 896
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 897
    .line 898
    .line 899
    invoke-direct {v1, v0}, Lke/f;-><init>(Lke/g;)V

    .line 900
    .line 901
    .line 902
    return-object v1

    .line 903
    :pswitch_d
    move-object/from16 v0, p1

    .line 904
    .line 905
    check-cast v0, Lgi/c;

    .line 906
    .line 907
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    const-string v0, "No consents left"

    .line 911
    .line 912
    return-object v0

    .line 913
    :pswitch_e
    move-object/from16 v0, p1

    .line 914
    .line 915
    check-cast v0, Lgi/c;

    .line 916
    .line 917
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 918
    .line 919
    .line 920
    const-string v0, "No consent documents returned from BFF"

    .line 921
    .line 922
    return-object v0

    .line 923
    :pswitch_f
    move-object/from16 v0, p1

    .line 924
    .line 925
    check-cast v0, Lcz/myskoda/api/bff/v1/TodoListDto;

    .line 926
    .line 927
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 928
    .line 929
    .line 930
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TodoListDto;->getTodos()Ljava/util/List;

    .line 931
    .line 932
    .line 933
    move-result-object v0

    .line 934
    check-cast v0, Ljava/lang/Iterable;

    .line 935
    .line 936
    new-instance v1, Ljava/util/ArrayList;

    .line 937
    .line 938
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 939
    .line 940
    .line 941
    move-result v2

    .line 942
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 943
    .line 944
    .line 945
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 946
    .line 947
    .line 948
    move-result-object v0

    .line 949
    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 950
    .line 951
    .line 952
    move-result v2

    .line 953
    if-eqz v2, :cond_11

    .line 954
    .line 955
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 956
    .line 957
    .line 958
    move-result-object v2

    .line 959
    check-cast v2, Lcz/myskoda/api/bff/v1/TodoDto;

    .line 960
    .line 961
    invoke-static {v2}, Llp/ba;->b(Lcz/myskoda/api/bff/v1/TodoDto;)Lla0/a;

    .line 962
    .line 963
    .line 964
    move-result-object v2

    .line 965
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 966
    .line 967
    .line 968
    goto :goto_9

    .line 969
    :cond_11
    return-object v1

    .line 970
    :pswitch_10
    move-object/from16 v0, p1

    .line 971
    .line 972
    check-cast v0, Lg4/l0;

    .line 973
    .line 974
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 975
    .line 976
    .line 977
    return-object v15

    .line 978
    :pswitch_11
    move-object/from16 v0, p1

    .line 979
    .line 980
    check-cast v0, Lg4/l0;

    .line 981
    .line 982
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 983
    .line 984
    .line 985
    return-object v15

    .line 986
    :pswitch_12
    move-object/from16 v0, p1

    .line 987
    .line 988
    check-cast v0, Ljava/lang/String;

    .line 989
    .line 990
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 991
    .line 992
    .line 993
    return-object v15

    .line 994
    :pswitch_13
    move-object/from16 v0, p1

    .line 995
    .line 996
    check-cast v0, Lg3/d;

    .line 997
    .line 998
    const-string v1, "$this$LinearProgressIndicator"

    .line 999
    .line 1000
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1001
    .line 1002
    .line 1003
    return-object v15

    .line 1004
    :pswitch_14
    move-object/from16 v0, p1

    .line 1005
    .line 1006
    check-cast v0, Lh2/s8;

    .line 1007
    .line 1008
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1009
    .line 1010
    .line 1011
    sget-object v1, Lh2/s8;->f:Lh2/s8;

    .line 1012
    .line 1013
    if-ne v0, v1, :cond_12

    .line 1014
    .line 1015
    const/4 v2, 0x1

    .line 1016
    goto :goto_a

    .line 1017
    :cond_12
    const/4 v2, 0x0

    .line 1018
    :goto_a
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1019
    .line 1020
    .line 1021
    move-result-object v0

    .line 1022
    return-object v0

    .line 1023
    :pswitch_15
    move-object/from16 v0, p1

    .line 1024
    .line 1025
    check-cast v0, Lcz/myskoda/api/bff/v1/CertificateMetadataDto;

    .line 1026
    .line 1027
    const-string v1, "$this$requestSynchronous"

    .line 1028
    .line 1029
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1030
    .line 1031
    .line 1032
    new-instance v1, Lm90/a;

    .line 1033
    .line 1034
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/CertificateMetadataDto;->getCertificateId()Ljava/lang/String;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v2

    .line 1038
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/CertificateMetadataDto;->getFileName()Ljava/lang/String;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v0

    .line 1042
    invoke-direct {v1, v2, v0}, Lm90/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1043
    .line 1044
    .line 1045
    return-object v1

    .line 1046
    :pswitch_16
    move-object/from16 v0, p1

    .line 1047
    .line 1048
    check-cast v0, Ljava/lang/String;

    .line 1049
    .line 1050
    invoke-static {v0, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1051
    .line 1052
    .line 1053
    return-object v15

    .line 1054
    :pswitch_17
    move-object/from16 v0, p1

    .line 1055
    .line 1056
    check-cast v0, Lua/a;

    .line 1057
    .line 1058
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1059
    .line 1060
    .line 1061
    const-string v1, "DELETE FROM trips_overview"

    .line 1062
    .line 1063
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1064
    .line 1065
    .line 1066
    move-result-object v1

    .line 1067
    :try_start_3
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 1068
    .line 1069
    .line 1070
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1071
    .line 1072
    .line 1073
    return-object v15

    .line 1074
    :catchall_3
    move-exception v0

    .line 1075
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 1076
    .line 1077
    .line 1078
    throw v0

    .line 1079
    :pswitch_18
    move-object/from16 v0, p1

    .line 1080
    .line 1081
    check-cast v0, Lcz/myskoda/api/bff/v1/TripsOverviewDto;

    .line 1082
    .line 1083
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1084
    .line 1085
    .line 1086
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripsOverviewDto;->getVehicleType()Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v1

    .line 1090
    invoke-static {v1}, Li70/e0;->c(Lcz/myskoda/api/bff/v1/VehicleTypeDto;)Ll70/a0;

    .line 1091
    .line 1092
    .line 1093
    move-result-object v3

    .line 1094
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripsOverviewDto;->getEndMileageInKm()Ljava/lang/Integer;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v1

    .line 1098
    if-eqz v1, :cond_13

    .line 1099
    .line 1100
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1101
    .line 1102
    .line 1103
    move-result v1

    .line 1104
    int-to-double v1, v1

    .line 1105
    mul-double/2addr v1, v9

    .line 1106
    new-instance v4, Lqr0/d;

    .line 1107
    .line 1108
    invoke-direct {v4, v1, v2}, Lqr0/d;-><init>(D)V

    .line 1109
    .line 1110
    .line 1111
    goto :goto_b

    .line 1112
    :cond_13
    move-object v4, v11

    .line 1113
    :goto_b
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripsOverviewDto;->getAverageFuelConsumption()Ljava/lang/Double;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    if-eqz v1, :cond_14

    .line 1118
    .line 1119
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 1120
    .line 1121
    .line 1122
    move-result-wide v1

    .line 1123
    new-instance v5, Lqr0/i;

    .line 1124
    .line 1125
    invoke-direct {v5, v1, v2}, Lqr0/i;-><init>(D)V

    .line 1126
    .line 1127
    .line 1128
    goto :goto_c

    .line 1129
    :cond_14
    move-object v5, v11

    .line 1130
    :goto_c
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripsOverviewDto;->getAverageElectricConsumption()Ljava/lang/Double;

    .line 1131
    .line 1132
    .line 1133
    move-result-object v1

    .line 1134
    if-eqz v1, :cond_15

    .line 1135
    .line 1136
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 1137
    .line 1138
    .line 1139
    move-result-wide v1

    .line 1140
    new-instance v6, Lqr0/g;

    .line 1141
    .line 1142
    invoke-direct {v6, v1, v2}, Lqr0/g;-><init>(D)V

    .line 1143
    .line 1144
    .line 1145
    goto :goto_d

    .line 1146
    :cond_15
    move-object v6, v11

    .line 1147
    :goto_d
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripsOverviewDto;->getAverageGasConsumption()Ljava/lang/Double;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v0

    .line 1151
    if-eqz v0, :cond_16

    .line 1152
    .line 1153
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1154
    .line 1155
    .line 1156
    move-result-wide v0

    .line 1157
    new-instance v11, Lqr0/j;

    .line 1158
    .line 1159
    invoke-direct {v11, v0, v1}, Lqr0/j;-><init>(D)V

    .line 1160
    .line 1161
    .line 1162
    :cond_16
    move-object v7, v11

    .line 1163
    new-instance v2, Ll70/z;

    .line 1164
    .line 1165
    invoke-direct/range {v2 .. v7}, Ll70/z;-><init>(Ll70/a0;Lqr0/d;Lqr0/i;Lqr0/g;Lqr0/j;)V

    .line 1166
    .line 1167
    .line 1168
    return-object v2

    .line 1169
    :pswitch_19
    move-object/from16 v0, p1

    .line 1170
    .line 1171
    check-cast v0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;

    .line 1172
    .line 1173
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1174
    .line 1175
    .line 1176
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallMileageInKm()Ljava/lang/Long;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v3

    .line 1180
    if-eqz v3, :cond_17

    .line 1181
    .line 1182
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 1183
    .line 1184
    .line 1185
    move-result-wide v3

    .line 1186
    long-to-int v3, v3

    .line 1187
    goto :goto_e

    .line 1188
    :cond_17
    const/4 v3, 0x0

    .line 1189
    :goto_e
    int-to-double v3, v3

    .line 1190
    mul-double v15, v3, v9

    .line 1191
    .line 1192
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallTravelTimeInMin()Ljava/lang/Long;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v3

    .line 1196
    if-eqz v3, :cond_18

    .line 1197
    .line 1198
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 1199
    .line 1200
    .line 1201
    move-result-wide v3

    .line 1202
    long-to-int v3, v3

    .line 1203
    move/from16 v17, v3

    .line 1204
    .line 1205
    goto :goto_f

    .line 1206
    :cond_18
    const/16 v17, 0x0

    .line 1207
    .line 1208
    :goto_f
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageMileageInKm()Ljava/lang/Long;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v3

    .line 1212
    if-eqz v3, :cond_19

    .line 1213
    .line 1214
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 1215
    .line 1216
    .line 1217
    move-result-wide v3

    .line 1218
    long-to-int v3, v3

    .line 1219
    goto :goto_10

    .line 1220
    :cond_19
    const/4 v3, 0x0

    .line 1221
    :goto_10
    int-to-double v3, v3

    .line 1222
    mul-double v18, v3, v9

    .line 1223
    .line 1224
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageTravelTimeInMin()Ljava/lang/Long;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v3

    .line 1228
    if-eqz v3, :cond_1a

    .line 1229
    .line 1230
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 1231
    .line 1232
    .line 1233
    move-result-wide v3

    .line 1234
    long-to-int v3, v3

    .line 1235
    move/from16 v20, v3

    .line 1236
    .line 1237
    goto :goto_11

    .line 1238
    :cond_1a
    const/16 v20, 0x0

    .line 1239
    .line 1240
    :goto_11
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageFuelConsumption()Ljava/lang/Double;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v3

    .line 1244
    if-eqz v3, :cond_1b

    .line 1245
    .line 1246
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 1247
    .line 1248
    .line 1249
    move-result-wide v7

    .line 1250
    goto :goto_12

    .line 1251
    :cond_1b
    const-wide/16 v7, 0x0

    .line 1252
    .line 1253
    :goto_12
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageElectricConsumption()Ljava/lang/Double;

    .line 1254
    .line 1255
    .line 1256
    move-result-object v3

    .line 1257
    if-eqz v3, :cond_1c

    .line 1258
    .line 1259
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 1260
    .line 1261
    .line 1262
    move-result-wide v13

    .line 1263
    goto :goto_13

    .line 1264
    :cond_1c
    const-wide/16 v13, 0x0

    .line 1265
    .line 1266
    :goto_13
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageGasConsumption()Ljava/lang/Double;

    .line 1267
    .line 1268
    .line 1269
    move-result-object v3

    .line 1270
    if-eqz v3, :cond_1d

    .line 1271
    .line 1272
    invoke-virtual {v3}, Ljava/lang/Double;->doubleValue()D

    .line 1273
    .line 1274
    .line 1275
    move-result-wide v21

    .line 1276
    move-wide/from16 v2, v21

    .line 1277
    .line 1278
    goto :goto_14

    .line 1279
    :cond_1d
    const-wide/16 v2, 0x0

    .line 1280
    .line 1281
    :goto_14
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallAverageSpeedInKmph()Ljava/lang/Long;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v21

    .line 1285
    if-eqz v21, :cond_1e

    .line 1286
    .line 1287
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Long;->longValue()J

    .line 1288
    .line 1289
    .line 1290
    move-result-wide v4

    .line 1291
    long-to-double v4, v4

    .line 1292
    move-wide/from16 v24, v4

    .line 1293
    .line 1294
    goto :goto_15

    .line 1295
    :cond_1e
    const-wide/16 v24, 0x0

    .line 1296
    .line 1297
    :goto_15
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getVehicleType()Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 1298
    .line 1299
    .line 1300
    move-result-object v4

    .line 1301
    invoke-static {v4}, Li70/e0;->c(Lcz/myskoda/api/bff/v1/VehicleTypeDto;)Ll70/a0;

    .line 1302
    .line 1303
    .line 1304
    move-result-object v26

    .line 1305
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getDetailedStatistics()Ljava/util/List;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v4

    .line 1309
    if-eqz v4, :cond_28

    .line 1310
    .line 1311
    check-cast v4, Ljava/lang/Iterable;

    .line 1312
    .line 1313
    new-instance v5, Ljava/util/ArrayList;

    .line 1314
    .line 1315
    invoke-static {v4, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1316
    .line 1317
    .line 1318
    move-result v12

    .line 1319
    invoke-direct {v5, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 1320
    .line 1321
    .line 1322
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v4

    .line 1326
    :goto_16
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1327
    .line 1328
    .line 1329
    move-result v12

    .line 1330
    if-eqz v12, :cond_27

    .line 1331
    .line 1332
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v12

    .line 1336
    check-cast v12, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;

    .line 1337
    .line 1338
    invoke-static {v12, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1339
    .line 1340
    .line 1341
    new-instance v27, Ll70/r;

    .line 1342
    .line 1343
    move-wide/from16 v42, v9

    .line 1344
    .line 1345
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getDate()Ljava/time/LocalDate;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v9

    .line 1349
    sget-object v10, Ljava/time/LocalTime;->NOON:Ljava/time/LocalTime;

    .line 1350
    .line 1351
    sget-object v11, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 1352
    .line 1353
    invoke-static {v9, v10, v11}, Ljava/time/OffsetDateTime;->of(Ljava/time/LocalDate;Ljava/time/LocalTime;Ljava/time/ZoneOffset;)Ljava/time/OffsetDateTime;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v9

    .line 1357
    const-string v10, "of(...)"

    .line 1358
    .line 1359
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1360
    .line 1361
    .line 1362
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getTripIds()Ljava/util/List;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v10

    .line 1366
    if-nez v10, :cond_1f

    .line 1367
    .line 1368
    move-object/from16 v29, v1

    .line 1369
    .line 1370
    goto :goto_17

    .line 1371
    :cond_1f
    move-object/from16 v29, v10

    .line 1372
    .line 1373
    :goto_17
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getMileageInKm()Ljava/lang/Long;

    .line 1374
    .line 1375
    .line 1376
    move-result-object v10

    .line 1377
    if-eqz v10, :cond_20

    .line 1378
    .line 1379
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 1380
    .line 1381
    .line 1382
    move-result-wide v10

    .line 1383
    long-to-int v10, v10

    .line 1384
    goto :goto_18

    .line 1385
    :cond_20
    const/4 v10, 0x0

    .line 1386
    :goto_18
    int-to-double v10, v10

    .line 1387
    mul-double v30, v10, v42

    .line 1388
    .line 1389
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getTravelTimeInMin()Ljava/lang/Long;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v10

    .line 1393
    if-eqz v10, :cond_21

    .line 1394
    .line 1395
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 1396
    .line 1397
    .line 1398
    move-result-wide v10

    .line 1399
    long-to-int v10, v10

    .line 1400
    move/from16 v32, v10

    .line 1401
    .line 1402
    goto :goto_19

    .line 1403
    :cond_21
    const/16 v32, 0x0

    .line 1404
    .line 1405
    :goto_19
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getAverageFuelConsumption()Ljava/lang/Double;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v10

    .line 1409
    if-eqz v10, :cond_22

    .line 1410
    .line 1411
    invoke-virtual {v10}, Ljava/lang/Double;->doubleValue()D

    .line 1412
    .line 1413
    .line 1414
    move-result-wide v10

    .line 1415
    move-wide/from16 v33, v10

    .line 1416
    .line 1417
    goto :goto_1a

    .line 1418
    :cond_22
    const-wide/16 v33, 0x0

    .line 1419
    .line 1420
    :goto_1a
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getAverageElectricConsumption()Ljava/lang/Double;

    .line 1421
    .line 1422
    .line 1423
    move-result-object v10

    .line 1424
    if-eqz v10, :cond_23

    .line 1425
    .line 1426
    invoke-virtual {v10}, Ljava/lang/Double;->doubleValue()D

    .line 1427
    .line 1428
    .line 1429
    move-result-wide v10

    .line 1430
    move-wide/from16 v35, v10

    .line 1431
    .line 1432
    goto :goto_1b

    .line 1433
    :cond_23
    const-wide/16 v35, 0x0

    .line 1434
    .line 1435
    :goto_1b
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getAverageGasConsumption()Ljava/lang/Double;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v10

    .line 1439
    if-eqz v10, :cond_24

    .line 1440
    .line 1441
    invoke-virtual {v10}, Ljava/lang/Double;->doubleValue()D

    .line 1442
    .line 1443
    .line 1444
    move-result-wide v10

    .line 1445
    move-wide/from16 v37, v10

    .line 1446
    .line 1447
    goto :goto_1c

    .line 1448
    :cond_24
    const-wide/16 v37, 0x0

    .line 1449
    .line 1450
    :goto_1c
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getAverageSpeedInKmph()Ljava/lang/Long;

    .line 1451
    .line 1452
    .line 1453
    move-result-object v10

    .line 1454
    if-eqz v10, :cond_25

    .line 1455
    .line 1456
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 1457
    .line 1458
    .line 1459
    move-result-wide v10

    .line 1460
    long-to-double v10, v10

    .line 1461
    move-wide/from16 v39, v10

    .line 1462
    .line 1463
    goto :goto_1d

    .line 1464
    :cond_25
    const-wide/16 v39, 0x0

    .line 1465
    .line 1466
    :goto_1d
    invoke-virtual {v12}, Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;->getCost()Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 1467
    .line 1468
    .line 1469
    move-result-object v10

    .line 1470
    if-eqz v10, :cond_26

    .line 1471
    .line 1472
    invoke-static {v10}, Li70/e0;->b(Lcz/myskoda/api/bff/v1/FuelCostDto;)Ll70/u;

    .line 1473
    .line 1474
    .line 1475
    move-result-object v10

    .line 1476
    move-object/from16 v41, v10

    .line 1477
    .line 1478
    :goto_1e
    move-object/from16 v28, v9

    .line 1479
    .line 1480
    goto :goto_1f

    .line 1481
    :cond_26
    const/16 v41, 0x0

    .line 1482
    .line 1483
    goto :goto_1e

    .line 1484
    :goto_1f
    invoke-direct/range {v27 .. v41}, Ll70/r;-><init>(Ljava/time/OffsetDateTime;Ljava/util/List;DIDDDDLl70/u;)V

    .line 1485
    .line 1486
    .line 1487
    move-object/from16 v9, v27

    .line 1488
    .line 1489
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1490
    .line 1491
    .line 1492
    move-wide/from16 v9, v42

    .line 1493
    .line 1494
    const/4 v11, 0x0

    .line 1495
    goto/16 :goto_16

    .line 1496
    .line 1497
    :cond_27
    move-object/from16 v27, v5

    .line 1498
    .line 1499
    goto :goto_20

    .line 1500
    :cond_28
    move-object/from16 v27, v1

    .line 1501
    .line 1502
    :goto_20
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->getOverallCost()Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 1503
    .line 1504
    .line 1505
    move-result-object v0

    .line 1506
    if-eqz v0, :cond_29

    .line 1507
    .line 1508
    invoke-static {v0}, Li70/e0;->b(Lcz/myskoda/api/bff/v1/FuelCostDto;)Ll70/u;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v11

    .line 1512
    goto :goto_21

    .line 1513
    :cond_29
    const/4 v11, 0x0

    .line 1514
    :goto_21
    new-instance v0, Ll70/p;

    .line 1515
    .line 1516
    new-instance v1, Lqr0/i;

    .line 1517
    .line 1518
    invoke-direct {v1, v7, v8}, Lqr0/i;-><init>(D)V

    .line 1519
    .line 1520
    .line 1521
    new-instance v4, Lqr0/g;

    .line 1522
    .line 1523
    invoke-direct {v4, v13, v14}, Lqr0/g;-><init>(D)V

    .line 1524
    .line 1525
    .line 1526
    new-instance v5, Lqr0/j;

    .line 1527
    .line 1528
    invoke-direct {v5, v2, v3}, Lqr0/j;-><init>(D)V

    .line 1529
    .line 1530
    .line 1531
    move-object v13, v0

    .line 1532
    move-object/from16 v21, v1

    .line 1533
    .line 1534
    move-object/from16 v22, v4

    .line 1535
    .line 1536
    move-object/from16 v23, v5

    .line 1537
    .line 1538
    move-object v14, v11

    .line 1539
    invoke-direct/range {v13 .. v27}, Ll70/p;-><init>(Ll70/u;DIDILqr0/i;Lqr0/g;Lqr0/j;DLl70/a0;Ljava/util/List;)V

    .line 1540
    .line 1541
    .line 1542
    return-object v13

    .line 1543
    :pswitch_1a
    move-wide/from16 v42, v9

    .line 1544
    .line 1545
    move-object/from16 v0, p1

    .line 1546
    .line 1547
    check-cast v0, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;

    .line 1548
    .line 1549
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1550
    .line 1551
    .line 1552
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;->getVehicleType()Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 1553
    .line 1554
    .line 1555
    move-result-object v2

    .line 1556
    invoke-static {v2}, Li70/e0;->c(Lcz/myskoda/api/bff/v1/VehicleTypeDto;)Ll70/a0;

    .line 1557
    .line 1558
    .line 1559
    move-result-object v2

    .line 1560
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;->getDailyTrips()Ljava/util/List;

    .line 1561
    .line 1562
    .line 1563
    move-result-object v3

    .line 1564
    check-cast v3, Ljava/lang/Iterable;

    .line 1565
    .line 1566
    new-instance v4, Ljava/util/ArrayList;

    .line 1567
    .line 1568
    invoke-static {v3, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1569
    .line 1570
    .line 1571
    move-result v5

    .line 1572
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 1573
    .line 1574
    .line 1575
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1576
    .line 1577
    .line 1578
    move-result-object v3

    .line 1579
    :goto_22
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1580
    .line 1581
    .line 1582
    move-result v5

    .line 1583
    if-eqz v5, :cond_41

    .line 1584
    .line 1585
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1586
    .line 1587
    .line 1588
    move-result-object v5

    .line 1589
    check-cast v5, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;

    .line 1590
    .line 1591
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;->getShortTripThresholdInKm()Ljava/lang/Integer;

    .line 1592
    .line 1593
    .line 1594
    move-result-object v7

    .line 1595
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;->getShortTripThresholdInMi()Ljava/lang/Integer;

    .line 1596
    .line 1597
    .line 1598
    move-result-object v8

    .line 1599
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1600
    .line 1601
    .line 1602
    invoke-virtual {v5}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->getDate()Ljava/time/LocalDate;

    .line 1603
    .line 1604
    .line 1605
    move-result-object v14

    .line 1606
    invoke-virtual {v5}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->getTrips()Ljava/util/List;

    .line 1607
    .line 1608
    .line 1609
    move-result-object v9

    .line 1610
    check-cast v9, Ljava/lang/Iterable;

    .line 1611
    .line 1612
    new-instance v15, Ljava/util/ArrayList;

    .line 1613
    .line 1614
    invoke-static {v9, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1615
    .line 1616
    .line 1617
    move-result v10

    .line 1618
    invoke-direct {v15, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 1619
    .line 1620
    .line 1621
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1622
    .line 1623
    .line 1624
    move-result-object v9

    .line 1625
    :goto_23
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 1626
    .line 1627
    .line 1628
    move-result v10

    .line 1629
    if-eqz v10, :cond_3f

    .line 1630
    .line 1631
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1632
    .line 1633
    .line 1634
    move-result-object v10

    .line 1635
    check-cast v10, Lcz/myskoda/api/bff/v1/SingleTripDto;

    .line 1636
    .line 1637
    invoke-virtual {v5}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->getDate()Ljava/time/LocalDate;

    .line 1638
    .line 1639
    .line 1640
    move-result-object v11

    .line 1641
    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1642
    .line 1643
    .line 1644
    const-string v13, "date"

    .line 1645
    .line 1646
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1647
    .line 1648
    .line 1649
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getId()Ljava/lang/String;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v45

    .line 1653
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getStartLocationName()Ljava/lang/String;

    .line 1654
    .line 1655
    .line 1656
    move-result-object v47

    .line 1657
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getEndLocationName()Ljava/lang/String;

    .line 1658
    .line 1659
    .line 1660
    move-result-object v48

    .line 1661
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getStartTime()Ljava/lang/String;

    .line 1662
    .line 1663
    .line 1664
    move-result-object v13

    .line 1665
    if-eqz v13, :cond_2a

    .line 1666
    .line 1667
    invoke-static {v13}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 1668
    .line 1669
    .line 1670
    move-result-object v13

    .line 1671
    move-object/from16 v49, v13

    .line 1672
    .line 1673
    goto :goto_24

    .line 1674
    :cond_2a
    const/16 v49, 0x0

    .line 1675
    .line 1676
    :goto_24
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getEndTime()Ljava/lang/String;

    .line 1677
    .line 1678
    .line 1679
    move-result-object v13

    .line 1680
    invoke-static {v13}, Ljava/time/LocalTime;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalTime;

    .line 1681
    .line 1682
    .line 1683
    move-result-object v13

    .line 1684
    const-string v12, "parse(...)"

    .line 1685
    .line 1686
    invoke-static {v13, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1687
    .line 1688
    .line 1689
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getStartMileageInKm()Ljava/lang/Integer;

    .line 1690
    .line 1691
    .line 1692
    move-result-object v12

    .line 1693
    if-eqz v12, :cond_2b

    .line 1694
    .line 1695
    invoke-virtual {v12}, Ljava/lang/Number;->intValue()I

    .line 1696
    .line 1697
    .line 1698
    move-result v12

    .line 1699
    move-object/from16 p1, v0

    .line 1700
    .line 1701
    move-object/from16 v19, v1

    .line 1702
    .line 1703
    int-to-double v0, v12

    .line 1704
    mul-double v0, v0, v42

    .line 1705
    .line 1706
    new-instance v12, Lqr0/d;

    .line 1707
    .line 1708
    invoke-direct {v12, v0, v1}, Lqr0/d;-><init>(D)V

    .line 1709
    .line 1710
    .line 1711
    move-object/from16 v51, v12

    .line 1712
    .line 1713
    goto :goto_25

    .line 1714
    :cond_2b
    move-object/from16 p1, v0

    .line 1715
    .line 1716
    move-object/from16 v19, v1

    .line 1717
    .line 1718
    const/16 v51, 0x0

    .line 1719
    .line 1720
    :goto_25
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getEndMileageInKm()Ljava/lang/Integer;

    .line 1721
    .line 1722
    .line 1723
    move-result-object v0

    .line 1724
    if-eqz v0, :cond_2c

    .line 1725
    .line 1726
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1727
    .line 1728
    .line 1729
    move-result v0

    .line 1730
    int-to-double v0, v0

    .line 1731
    mul-double v0, v0, v42

    .line 1732
    .line 1733
    new-instance v12, Lqr0/d;

    .line 1734
    .line 1735
    invoke-direct {v12, v0, v1}, Lqr0/d;-><init>(D)V

    .line 1736
    .line 1737
    .line 1738
    move-object/from16 v52, v12

    .line 1739
    .line 1740
    goto :goto_26

    .line 1741
    :cond_2c
    const/16 v52, 0x0

    .line 1742
    .line 1743
    :goto_26
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getMileageInKm()I

    .line 1744
    .line 1745
    .line 1746
    move-result v0

    .line 1747
    int-to-double v0, v0

    .line 1748
    mul-double v53, v0, v42

    .line 1749
    .line 1750
    sget v0, Lmy0/c;->g:I

    .line 1751
    .line 1752
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getTravelTimeInMin()I

    .line 1753
    .line 1754
    .line 1755
    move-result v0

    .line 1756
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 1757
    .line 1758
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 1759
    .line 1760
    .line 1761
    move-result-wide v55

    .line 1762
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getStartBatteryStateOfChargeInPercent()Ljava/lang/Integer;

    .line 1763
    .line 1764
    .line 1765
    move-result-object v0

    .line 1766
    if-eqz v0, :cond_2d

    .line 1767
    .line 1768
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1769
    .line 1770
    .line 1771
    move-result v0

    .line 1772
    new-instance v1, Lqr0/l;

    .line 1773
    .line 1774
    invoke-direct {v1, v0}, Lqr0/l;-><init>(I)V

    .line 1775
    .line 1776
    .line 1777
    move-object/from16 v57, v1

    .line 1778
    .line 1779
    goto :goto_27

    .line 1780
    :cond_2d
    const/16 v57, 0x0

    .line 1781
    .line 1782
    :goto_27
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getEndBatteryStateOfChargeInPercent()Ljava/lang/Integer;

    .line 1783
    .line 1784
    .line 1785
    move-result-object v0

    .line 1786
    if-eqz v0, :cond_2e

    .line 1787
    .line 1788
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1789
    .line 1790
    .line 1791
    move-result v0

    .line 1792
    new-instance v1, Lqr0/l;

    .line 1793
    .line 1794
    invoke-direct {v1, v0}, Lqr0/l;-><init>(I)V

    .line 1795
    .line 1796
    .line 1797
    move-object/from16 v58, v1

    .line 1798
    .line 1799
    goto :goto_28

    .line 1800
    :cond_2e
    const/16 v58, 0x0

    .line 1801
    .line 1802
    :goto_28
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageSpeedInKmph()Ljava/lang/Integer;

    .line 1803
    .line 1804
    .line 1805
    move-result-object v0

    .line 1806
    if-eqz v0, :cond_2f

    .line 1807
    .line 1808
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1809
    .line 1810
    .line 1811
    move-result v0

    .line 1812
    int-to-double v0, v0

    .line 1813
    new-instance v12, Lqr0/p;

    .line 1814
    .line 1815
    invoke-direct {v12, v0, v1}, Lqr0/p;-><init>(D)V

    .line 1816
    .line 1817
    .line 1818
    move-object/from16 v59, v12

    .line 1819
    .line 1820
    goto :goto_29

    .line 1821
    :cond_2f
    const/16 v59, 0x0

    .line 1822
    .line 1823
    :goto_29
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageFuelConsumption()Ljava/lang/Double;

    .line 1824
    .line 1825
    .line 1826
    move-result-object v0

    .line 1827
    if-eqz v0, :cond_30

    .line 1828
    .line 1829
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1830
    .line 1831
    .line 1832
    move-result-wide v0

    .line 1833
    new-instance v12, Lqr0/i;

    .line 1834
    .line 1835
    invoke-direct {v12, v0, v1}, Lqr0/i;-><init>(D)V

    .line 1836
    .line 1837
    .line 1838
    move-object/from16 v60, v12

    .line 1839
    .line 1840
    goto :goto_2a

    .line 1841
    :cond_30
    const/16 v60, 0x0

    .line 1842
    .line 1843
    :goto_2a
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getElectricConsumption()Ljava/lang/Double;

    .line 1844
    .line 1845
    .line 1846
    move-result-object v0

    .line 1847
    if-eqz v0, :cond_31

    .line 1848
    .line 1849
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 1850
    .line 1851
    .line 1852
    move-result-wide v0

    .line 1853
    invoke-static {v0, v1}, Lcy0/a;->h(D)I

    .line 1854
    .line 1855
    .line 1856
    move-result v0

    .line 1857
    new-instance v1, Lqr0/h;

    .line 1858
    .line 1859
    invoke-direct {v1, v0}, Lqr0/h;-><init>(I)V

    .line 1860
    .line 1861
    .line 1862
    move-object/from16 v61, v1

    .line 1863
    .line 1864
    goto :goto_2b

    .line 1865
    :cond_31
    const/16 v61, 0x0

    .line 1866
    .line 1867
    :goto_2b
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageElectricConsumption()Ljava/lang/Double;

    .line 1868
    .line 1869
    .line 1870
    move-result-object v0

    .line 1871
    if-eqz v0, :cond_32

    .line 1872
    .line 1873
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1874
    .line 1875
    .line 1876
    move-result-wide v0

    .line 1877
    new-instance v12, Lqr0/g;

    .line 1878
    .line 1879
    invoke-direct {v12, v0, v1}, Lqr0/g;-><init>(D)V

    .line 1880
    .line 1881
    .line 1882
    move-object/from16 v62, v12

    .line 1883
    .line 1884
    goto :goto_2c

    .line 1885
    :cond_32
    const/16 v62, 0x0

    .line 1886
    .line 1887
    :goto_2c
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageGasConsumption()Ljava/lang/Double;

    .line 1888
    .line 1889
    .line 1890
    move-result-object v0

    .line 1891
    if-eqz v0, :cond_33

    .line 1892
    .line 1893
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1894
    .line 1895
    .line 1896
    move-result-wide v0

    .line 1897
    new-instance v12, Lqr0/j;

    .line 1898
    .line 1899
    invoke-direct {v12, v0, v1}, Lqr0/j;-><init>(D)V

    .line 1900
    .line 1901
    .line 1902
    move-object/from16 v63, v12

    .line 1903
    .line 1904
    goto :goto_2d

    .line 1905
    :cond_33
    const/16 v63, 0x0

    .line 1906
    .line 1907
    :goto_2d
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageRecuperation()Ljava/lang/Double;

    .line 1908
    .line 1909
    .line 1910
    move-result-object v0

    .line 1911
    if-eqz v0, :cond_34

    .line 1912
    .line 1913
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1914
    .line 1915
    .line 1916
    move-result-wide v0

    .line 1917
    new-instance v12, Lqr0/g;

    .line 1918
    .line 1919
    invoke-direct {v12, v0, v1}, Lqr0/g;-><init>(D)V

    .line 1920
    .line 1921
    .line 1922
    move-object/from16 v64, v12

    .line 1923
    .line 1924
    goto :goto_2e

    .line 1925
    :cond_34
    const/16 v64, 0x0

    .line 1926
    .line 1927
    :goto_2e
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getAverageAuxConsumption()Ljava/lang/Double;

    .line 1928
    .line 1929
    .line 1930
    move-result-object v0

    .line 1931
    if-eqz v0, :cond_35

    .line 1932
    .line 1933
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 1934
    .line 1935
    .line 1936
    move-result-wide v0

    .line 1937
    new-instance v12, Lqr0/i;

    .line 1938
    .line 1939
    invoke-direct {v12, v0, v1}, Lqr0/i;-><init>(D)V

    .line 1940
    .line 1941
    .line 1942
    move-object/from16 v65, v12

    .line 1943
    .line 1944
    goto :goto_2f

    .line 1945
    :cond_35
    const/16 v65, 0x0

    .line 1946
    .line 1947
    :goto_2f
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getCost()Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 1948
    .line 1949
    .line 1950
    move-result-object v0

    .line 1951
    if-eqz v0, :cond_36

    .line 1952
    .line 1953
    invoke-static {v0}, Li70/e0;->b(Lcz/myskoda/api/bff/v1/FuelCostDto;)Ll70/u;

    .line 1954
    .line 1955
    .line 1956
    move-result-object v0

    .line 1957
    move-object/from16 v66, v0

    .line 1958
    .line 1959
    goto :goto_30

    .line 1960
    :cond_36
    const/16 v66, 0x0

    .line 1961
    .line 1962
    :goto_30
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->getWaypoints()Ljava/util/List;

    .line 1963
    .line 1964
    .line 1965
    move-result-object v0

    .line 1966
    if-eqz v0, :cond_3d

    .line 1967
    .line 1968
    check-cast v0, Ljava/lang/Iterable;

    .line 1969
    .line 1970
    new-instance v1, Ljava/util/ArrayList;

    .line 1971
    .line 1972
    move-object/from16 p0, v3

    .line 1973
    .line 1974
    const/16 v12, 0xa

    .line 1975
    .line 1976
    invoke-static {v0, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1977
    .line 1978
    .line 1979
    move-result v3

    .line 1980
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 1981
    .line 1982
    .line 1983
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1984
    .line 1985
    .line 1986
    move-result-object v0

    .line 1987
    :goto_31
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1988
    .line 1989
    .line 1990
    move-result v3

    .line 1991
    if-eqz v3, :cond_3c

    .line 1992
    .line 1993
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1994
    .line 1995
    .line 1996
    move-result-object v3

    .line 1997
    check-cast v3, Lcz/myskoda/api/bff/v1/WaypointDto;

    .line 1998
    .line 1999
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2000
    .line 2001
    .line 2002
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getCoordinates()Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 2003
    .line 2004
    .line 2005
    move-result-object v16

    .line 2006
    if-eqz v16, :cond_37

    .line 2007
    .line 2008
    new-instance v12, Lxj0/f;

    .line 2009
    .line 2010
    move-object/from16 v17, v5

    .line 2011
    .line 2012
    move-object/from16 v22, v6

    .line 2013
    .line 2014
    invoke-virtual/range {v16 .. v16}, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;->getLatitude()D

    .line 2015
    .line 2016
    .line 2017
    move-result-wide v5

    .line 2018
    move-object/from16 v18, v7

    .line 2019
    .line 2020
    move-object/from16 v23, v8

    .line 2021
    .line 2022
    invoke-virtual/range {v16 .. v16}, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;->getLongitude()D

    .line 2023
    .line 2024
    .line 2025
    move-result-wide v7

    .line 2026
    invoke-direct {v12, v5, v6, v7, v8}, Lxj0/f;-><init>(DD)V

    .line 2027
    .line 2028
    .line 2029
    move-object/from16 v25, v12

    .line 2030
    .line 2031
    goto :goto_32

    .line 2032
    :cond_37
    move-object/from16 v17, v5

    .line 2033
    .line 2034
    move-object/from16 v22, v6

    .line 2035
    .line 2036
    move-object/from16 v18, v7

    .line 2037
    .line 2038
    move-object/from16 v23, v8

    .line 2039
    .line 2040
    const/16 v25, 0x0

    .line 2041
    .line 2042
    :goto_32
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getLocationName()Ljava/lang/String;

    .line 2043
    .line 2044
    .line 2045
    move-result-object v26

    .line 2046
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getFormattedAddress()Ljava/lang/String;

    .line 2047
    .line 2048
    .line 2049
    move-result-object v27

    .line 2050
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getChargedHere()Z

    .line 2051
    .line 2052
    .line 2053
    move-result v28

    .line 2054
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getDepartureTime()Ljava/time/OffsetDateTime;

    .line 2055
    .line 2056
    .line 2057
    move-result-object v29

    .line 2058
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getArrivalTime()Ljava/time/OffsetDateTime;

    .line 2059
    .line 2060
    .line 2061
    move-result-object v30

    .line 2062
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getArrivalStateOfChargeInPercent()Ljava/lang/Integer;

    .line 2063
    .line 2064
    .line 2065
    move-result-object v5

    .line 2066
    if-eqz v5, :cond_38

    .line 2067
    .line 2068
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 2069
    .line 2070
    .line 2071
    move-result v5

    .line 2072
    new-instance v6, Lqr0/l;

    .line 2073
    .line 2074
    invoke-direct {v6, v5}, Lqr0/l;-><init>(I)V

    .line 2075
    .line 2076
    .line 2077
    move-object/from16 v31, v6

    .line 2078
    .line 2079
    goto :goto_33

    .line 2080
    :cond_38
    const/16 v31, 0x0

    .line 2081
    .line 2082
    :goto_33
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getDepartureStateOfChargeInPercent()Ljava/lang/Integer;

    .line 2083
    .line 2084
    .line 2085
    move-result-object v5

    .line 2086
    if-eqz v5, :cond_39

    .line 2087
    .line 2088
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 2089
    .line 2090
    .line 2091
    move-result v5

    .line 2092
    new-instance v6, Lqr0/l;

    .line 2093
    .line 2094
    invoke-direct {v6, v5}, Lqr0/l;-><init>(I)V

    .line 2095
    .line 2096
    .line 2097
    move-object/from16 v32, v6

    .line 2098
    .line 2099
    goto :goto_34

    .line 2100
    :cond_39
    const/16 v32, 0x0

    .line 2101
    .line 2102
    :goto_34
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getDistanceToNextWaypointInKm()Ljava/lang/Integer;

    .line 2103
    .line 2104
    .line 2105
    move-result-object v5

    .line 2106
    if-eqz v5, :cond_3a

    .line 2107
    .line 2108
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 2109
    .line 2110
    .line 2111
    move-result v5

    .line 2112
    int-to-double v5, v5

    .line 2113
    mul-double v5, v5, v42

    .line 2114
    .line 2115
    new-instance v7, Lqr0/d;

    .line 2116
    .line 2117
    invoke-direct {v7, v5, v6}, Lqr0/d;-><init>(D)V

    .line 2118
    .line 2119
    .line 2120
    move-object/from16 v33, v7

    .line 2121
    .line 2122
    goto :goto_35

    .line 2123
    :cond_3a
    const/16 v33, 0x0

    .line 2124
    .line 2125
    :goto_35
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/WaypointDto;->getTimeToNextWaypointInMin()Ljava/lang/Integer;

    .line 2126
    .line 2127
    .line 2128
    move-result-object v3

    .line 2129
    if-eqz v3, :cond_3b

    .line 2130
    .line 2131
    sget v5, Lmy0/c;->g:I

    .line 2132
    .line 2133
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 2134
    .line 2135
    .line 2136
    move-result v3

    .line 2137
    sget-object v5, Lmy0/e;->i:Lmy0/e;

    .line 2138
    .line 2139
    invoke-static {v3, v5}, Lmy0/h;->s(ILmy0/e;)J

    .line 2140
    .line 2141
    .line 2142
    move-result-wide v5

    .line 2143
    new-instance v3, Lmy0/c;

    .line 2144
    .line 2145
    invoke-direct {v3, v5, v6}, Lmy0/c;-><init>(J)V

    .line 2146
    .line 2147
    .line 2148
    move-object/from16 v34, v3

    .line 2149
    .line 2150
    goto :goto_36

    .line 2151
    :cond_3b
    const/16 v34, 0x0

    .line 2152
    .line 2153
    :goto_36
    new-instance v24, Ll70/l;

    .line 2154
    .line 2155
    invoke-direct/range {v24 .. v34}, Ll70/l;-><init>(Lxj0/f;Ljava/lang/String;Ljava/lang/String;ZLjava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Lqr0/l;Lqr0/l;Lqr0/d;Lmy0/c;)V

    .line 2156
    .line 2157
    .line 2158
    move-object/from16 v3, v24

    .line 2159
    .line 2160
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2161
    .line 2162
    .line 2163
    move-object/from16 v5, v17

    .line 2164
    .line 2165
    move-object/from16 v7, v18

    .line 2166
    .line 2167
    move-object/from16 v6, v22

    .line 2168
    .line 2169
    move-object/from16 v8, v23

    .line 2170
    .line 2171
    const/16 v12, 0xa

    .line 2172
    .line 2173
    goto/16 :goto_31

    .line 2174
    .line 2175
    :cond_3c
    move-object/from16 v67, v1

    .line 2176
    .line 2177
    :goto_37
    move-object/from16 v17, v5

    .line 2178
    .line 2179
    move-object/from16 v22, v6

    .line 2180
    .line 2181
    move-object/from16 v18, v7

    .line 2182
    .line 2183
    move-object/from16 v23, v8

    .line 2184
    .line 2185
    goto :goto_38

    .line 2186
    :cond_3d
    move-object/from16 p0, v3

    .line 2187
    .line 2188
    move-object/from16 v67, v19

    .line 2189
    .line 2190
    goto :goto_37

    .line 2191
    :goto_38
    invoke-virtual {v10}, Lcz/myskoda/api/bff/v1/SingleTripDto;->isShortTrip()Ljava/lang/Boolean;

    .line 2192
    .line 2193
    .line 2194
    move-result-object v0

    .line 2195
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 2196
    .line 2197
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2198
    .line 2199
    .line 2200
    move-result v0

    .line 2201
    if-eqz v0, :cond_3e

    .line 2202
    .line 2203
    if-eqz v18, :cond_3e

    .line 2204
    .line 2205
    if-eqz v23, :cond_3e

    .line 2206
    .line 2207
    new-instance v0, Ll70/n;

    .line 2208
    .line 2209
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Integer;->intValue()I

    .line 2210
    .line 2211
    .line 2212
    move-result v1

    .line 2213
    int-to-double v5, v1

    .line 2214
    mul-double v5, v5, v42

    .line 2215
    .line 2216
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Integer;->intValue()I

    .line 2217
    .line 2218
    .line 2219
    move-result v1

    .line 2220
    int-to-double v7, v1

    .line 2221
    const-wide v24, 0x4099258000000000L    # 1609.375

    .line 2222
    .line 2223
    .line 2224
    .line 2225
    .line 2226
    mul-double v7, v7, v24

    .line 2227
    .line 2228
    invoke-direct {v0, v5, v6, v7, v8}, Ll70/n;-><init>(DD)V

    .line 2229
    .line 2230
    .line 2231
    :goto_39
    move-object/from16 v68, v0

    .line 2232
    .line 2233
    goto :goto_3a

    .line 2234
    :cond_3e
    sget-object v0, Ll70/m;->a:Ll70/m;

    .line 2235
    .line 2236
    goto :goto_39

    .line 2237
    :goto_3a
    new-instance v44, Ll70/i;

    .line 2238
    .line 2239
    move-object/from16 v46, v11

    .line 2240
    .line 2241
    move-object/from16 v50, v13

    .line 2242
    .line 2243
    invoke-direct/range {v44 .. v68}, Ll70/i;-><init>(Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalTime;Ljava/time/LocalTime;Lqr0/d;Lqr0/d;DJLqr0/l;Lqr0/l;Lqr0/p;Lqr0/i;Lqr0/h;Lqr0/g;Lqr0/j;Lqr0/g;Lqr0/i;Ll70/u;Ljava/util/List;Ll70/o;)V

    .line 2244
    .line 2245
    .line 2246
    move-object/from16 v0, v44

    .line 2247
    .line 2248
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2249
    .line 2250
    .line 2251
    move-object/from16 v3, p0

    .line 2252
    .line 2253
    move-object/from16 v0, p1

    .line 2254
    .line 2255
    move-object/from16 v5, v17

    .line 2256
    .line 2257
    move-object/from16 v7, v18

    .line 2258
    .line 2259
    move-object/from16 v1, v19

    .line 2260
    .line 2261
    move-object/from16 v6, v22

    .line 2262
    .line 2263
    move-object/from16 v8, v23

    .line 2264
    .line 2265
    const/16 v12, 0xa

    .line 2266
    .line 2267
    goto/16 :goto_23

    .line 2268
    .line 2269
    :cond_3f
    move-object/from16 p1, v0

    .line 2270
    .line 2271
    move-object/from16 v19, v1

    .line 2272
    .line 2273
    move-object/from16 p0, v3

    .line 2274
    .line 2275
    move-object/from16 v17, v5

    .line 2276
    .line 2277
    move-object/from16 v22, v6

    .line 2278
    .line 2279
    invoke-virtual/range {v17 .. v17}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->getOverallCost()Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 2280
    .line 2281
    .line 2282
    move-result-object v0

    .line 2283
    if-eqz v0, :cond_40

    .line 2284
    .line 2285
    invoke-static {v0}, Li70/e0;->b(Lcz/myskoda/api/bff/v1/FuelCostDto;)Ll70/u;

    .line 2286
    .line 2287
    .line 2288
    move-result-object v0

    .line 2289
    move-object/from16 v16, v0

    .line 2290
    .line 2291
    goto :goto_3b

    .line 2292
    :cond_40
    const/16 v16, 0x0

    .line 2293
    .line 2294
    :goto_3b
    invoke-virtual/range {v17 .. v17}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->getOverallMileage()I

    .line 2295
    .line 2296
    .line 2297
    move-result v0

    .line 2298
    int-to-double v0, v0

    .line 2299
    mul-double v17, v0, v42

    .line 2300
    .line 2301
    new-instance v13, Ll70/a;

    .line 2302
    .line 2303
    invoke-direct/range {v13 .. v18}, Ll70/a;-><init>(Ljava/time/LocalDate;Ljava/util/ArrayList;Ll70/u;D)V

    .line 2304
    .line 2305
    .line 2306
    invoke-virtual {v4, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2307
    .line 2308
    .line 2309
    move-object/from16 v3, p0

    .line 2310
    .line 2311
    move-object/from16 v0, p1

    .line 2312
    .line 2313
    move-object/from16 v1, v19

    .line 2314
    .line 2315
    move-object/from16 v6, v22

    .line 2316
    .line 2317
    const/16 v12, 0xa

    .line 2318
    .line 2319
    goto/16 :goto_22

    .line 2320
    .line 2321
    :cond_41
    move-object/from16 p1, v0

    .line 2322
    .line 2323
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;->getNextPageCursor()Ljava/lang/String;

    .line 2324
    .line 2325
    .line 2326
    move-result-object v0

    .line 2327
    new-instance v1, Ll70/j;

    .line 2328
    .line 2329
    invoke-direct {v1, v2, v4, v0}, Ll70/j;-><init>(Ll70/a0;Ljava/util/List;Ljava/lang/String;)V

    .line 2330
    .line 2331
    .line 2332
    return-object v1

    .line 2333
    :pswitch_1b
    move-object/from16 v0, p1

    .line 2334
    .line 2335
    check-cast v0, Lcz/myskoda/api/bff/v1/FuelPriceResponseDto;

    .line 2336
    .line 2337
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2338
    .line 2339
    .line 2340
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/FuelPriceResponseDto;->getFuelPrices()Ljava/util/List;

    .line 2341
    .line 2342
    .line 2343
    move-result-object v1

    .line 2344
    check-cast v1, Ljava/lang/Iterable;

    .line 2345
    .line 2346
    new-instance v2, Ljava/util/ArrayList;

    .line 2347
    .line 2348
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 2349
    .line 2350
    .line 2351
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2352
    .line 2353
    .line 2354
    move-result-object v1

    .line 2355
    :cond_42
    :goto_3c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 2356
    .line 2357
    .line 2358
    move-result v3

    .line 2359
    if-eqz v3, :cond_4a

    .line 2360
    .line 2361
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2362
    .line 2363
    .line 2364
    move-result-object v3

    .line 2365
    check-cast v3, Lcz/myskoda/api/bff/v1/FuelPriceDto;

    .line 2366
    .line 2367
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getFuelType()Ljava/lang/String;

    .line 2368
    .line 2369
    .line 2370
    move-result-object v5

    .line 2371
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 2372
    .line 2373
    .line 2374
    move-result v6

    .line 2375
    const v7, 0x112b9

    .line 2376
    .line 2377
    .line 2378
    if-eq v6, v7, :cond_47

    .line 2379
    .line 2380
    const v7, 0x2119b6

    .line 2381
    .line 2382
    .line 2383
    if-eq v6, v7, :cond_45

    .line 2384
    .line 2385
    const v7, 0x2da0a51d

    .line 2386
    .line 2387
    .line 2388
    if-eq v6, v7, :cond_43

    .line 2389
    .line 2390
    goto :goto_3e

    .line 2391
    :cond_43
    const-string v6, "ELECTRIC"

    .line 2392
    .line 2393
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2394
    .line 2395
    .line 2396
    move-result v5

    .line 2397
    if-nez v5, :cond_44

    .line 2398
    .line 2399
    goto :goto_3e

    .line 2400
    :cond_44
    sget-object v5, Ll70/h;->e:Ll70/h;

    .line 2401
    .line 2402
    :goto_3d
    move-object v10, v5

    .line 2403
    goto :goto_3f

    .line 2404
    :cond_45
    const-string v6, "FUEL"

    .line 2405
    .line 2406
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2407
    .line 2408
    .line 2409
    move-result v5

    .line 2410
    if-nez v5, :cond_46

    .line 2411
    .line 2412
    goto :goto_3e

    .line 2413
    :cond_46
    sget-object v5, Ll70/h;->d:Ll70/h;

    .line 2414
    .line 2415
    goto :goto_3d

    .line 2416
    :cond_47
    const-string v6, "GAS"

    .line 2417
    .line 2418
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2419
    .line 2420
    .line 2421
    move-result v5

    .line 2422
    if-nez v5, :cond_48

    .line 2423
    .line 2424
    :goto_3e
    const/4 v10, 0x0

    .line 2425
    goto :goto_3f

    .line 2426
    :cond_48
    sget-object v5, Ll70/h;->f:Ll70/h;

    .line 2427
    .line 2428
    goto :goto_3d

    .line 2429
    :goto_3f
    if-nez v10, :cond_49

    .line 2430
    .line 2431
    new-instance v5, Lh50/q0;

    .line 2432
    .line 2433
    invoke-direct {v5, v3, v4}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 2434
    .line 2435
    .line 2436
    invoke-static {v0, v5}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 2437
    .line 2438
    .line 2439
    const/4 v6, 0x0

    .line 2440
    goto :goto_40

    .line 2441
    :cond_49
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getId()Ljava/lang/String;

    .line 2442
    .line 2443
    .line 2444
    move-result-object v7

    .line 2445
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getPriceCurrency()Ljava/lang/String;

    .line 2446
    .line 2447
    .line 2448
    move-result-object v9

    .line 2449
    new-instance v8, Ljava/math/BigDecimal;

    .line 2450
    .line 2451
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getPricePerUnit()F

    .line 2452
    .line 2453
    .line 2454
    move-result v5

    .line 2455
    invoke-static {v5}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 2456
    .line 2457
    .line 2458
    move-result-object v5

    .line 2459
    invoke-direct {v8, v5}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 2460
    .line 2461
    .line 2462
    invoke-virtual {v3}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getValidFromDate()Ljava/time/LocalDate;

    .line 2463
    .line 2464
    .line 2465
    move-result-object v11

    .line 2466
    new-instance v6, Ll70/d;

    .line 2467
    .line 2468
    invoke-direct/range {v6 .. v11}, Ll70/d;-><init>(Ljava/lang/String;Ljava/math/BigDecimal;Ljava/lang/String;Ll70/h;Ljava/time/LocalDate;)V

    .line 2469
    .line 2470
    .line 2471
    :goto_40
    if-eqz v6, :cond_42

    .line 2472
    .line 2473
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2474
    .line 2475
    .line 2476
    goto :goto_3c

    .line 2477
    :cond_4a
    return-object v2

    .line 2478
    :pswitch_1c
    move-object/from16 v0, p1

    .line 2479
    .line 2480
    check-cast v0, Lne0/c;

    .line 2481
    .line 2482
    const-string v1, "$this$mapError"

    .line 2483
    .line 2484
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2485
    .line 2486
    .line 2487
    invoke-static {v0}, Li70/r;->a(Lne0/c;)Lne0/c;

    .line 2488
    .line 2489
    .line 2490
    move-result-object v0

    .line 2491
    return-object v0

    .line 2492
    nop

    .line 2493
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
