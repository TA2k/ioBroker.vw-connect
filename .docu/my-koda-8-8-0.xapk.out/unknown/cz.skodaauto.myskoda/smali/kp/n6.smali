.class public abstract Lkp/n6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(DLqr0/s;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    const-string v0, " "

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    if-eqz p2, :cond_2

    .line 14
    .line 15
    if-eq p2, v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    if-ne p2, v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    :goto_0
    const-wide v1, 0x3ff574d1633482bfL    # 1.34102

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    mul-double/2addr p0, v1

    .line 33
    invoke-static {p0, p1}, Lcy0/a;->h(D)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {}, Ljava/text/NumberFormat;->getInstance()Ljava/text/NumberFormat;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p1, p0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    sget-object p1, Lqr0/o;->d:Lqr0/o;

    .line 50
    .line 51
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :cond_2
    const-wide/high16 v2, -0x4010000000000000L    # -1.0

    .line 61
    .line 62
    cmpg-double p2, v2, p0

    .line 63
    .line 64
    if-gtz p2, :cond_3

    .line 65
    .line 66
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 67
    .line 68
    cmpg-double p2, p0, v2

    .line 69
    .line 70
    if-gtz p2, :cond_3

    .line 71
    .line 72
    invoke-static {v1, p0, p1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    goto :goto_1

    .line 77
    :cond_3
    invoke-static {p0, p1}, Ljava/lang/Math;->ceil(D)D

    .line 78
    .line 79
    .line 80
    move-result-wide p0

    .line 81
    const/4 p2, 0x0

    .line 82
    invoke-static {p2, p0, p1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    :goto_1
    sget-object p1, Lqr0/o;->e:Lqr0/o;

    .line 87
    .line 88
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

.method public static b(Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;)Lss0/u;
    .locals 24

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getCommissionId()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    const-string v3, "value"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getName()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getCompositeRenders()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Ljava/lang/Iterable;

    .line 26
    .line 27
    new-instance v5, Ljava/util/ArrayList;

    .line 28
    .line 29
    const/16 v6, 0xa

    .line 30
    .line 31
    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 32
    .line 33
    .line 34
    move-result v7

    .line 35
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    if-eqz v7, :cond_0

    .line 47
    .line 48
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    check-cast v7, Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;

    .line 53
    .line 54
    invoke-static {v7}, Lps0/b;->a(Lcz/myskoda/api/bff_garage/v2/CompositeRenderDto;)Lhp0/e;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getActivationState()Lcz/myskoda/api/bff_garage/v2/ActivationStateDto;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    sget-object v7, Len0/a;->a:[I

    .line 70
    .line 71
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    aget v4, v7, v4

    .line 76
    .line 77
    const/4 v7, 0x1

    .line 78
    if-eq v4, v7, :cond_4

    .line 79
    .line 80
    const/4 v7, 0x2

    .line 81
    if-eq v4, v7, :cond_3

    .line 82
    .line 83
    const/4 v7, 0x3

    .line 84
    if-eq v4, v7, :cond_2

    .line 85
    .line 86
    const/4 v7, 0x4

    .line 87
    if-ne v4, v7, :cond_1

    .line 88
    .line 89
    sget-object v4, Lss0/a;->g:Lss0/a;

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_1
    new-instance v0, La8/r0;

    .line 93
    .line 94
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 95
    .line 96
    .line 97
    throw v0

    .line 98
    :cond_2
    sget-object v4, Lss0/a;->f:Lss0/a;

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    sget-object v4, Lss0/a;->e:Lss0/a;

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_4
    sget-object v4, Lss0/a;->d:Lss0/a;

    .line 105
    .line 106
    :goto_1
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getVin()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    if-eqz v7, :cond_5

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_5
    const/4 v7, 0x0

    .line 114
    :goto_2
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getOrderStatus()Lcz/myskoda/api/bff_garage/v2/OrderStatusDto;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    invoke-static {v9}, Lkp/n6;->c(Lcz/myskoda/api/bff_garage/v2/OrderStatusDto;)Lss0/t;

    .line 119
    .line 120
    .line 121
    move-result-object v9

    .line 122
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getDealer()Lcz/myskoda/api/bff_garage/v2/VehicleServicePartnerDto;

    .line 123
    .line 124
    .line 125
    move-result-object v10

    .line 126
    if-eqz v10, :cond_6

    .line 127
    .line 128
    invoke-virtual {v10}, Lcz/myskoda/api/bff_garage/v2/VehicleServicePartnerDto;->getServicePartnerId()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v10

    .line 132
    goto :goto_3

    .line 133
    :cond_6
    const/4 v10, 0x0

    .line 134
    :goto_3
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getDeliveryDateRange()Lcz/myskoda/api/bff_garage/v2/DateRangeDto;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    if-eqz v11, :cond_7

    .line 139
    .line 140
    new-instance v12, Lss0/j;

    .line 141
    .line 142
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/DateRangeDto;->getFrom()Ljava/time/LocalDate;

    .line 143
    .line 144
    .line 145
    move-result-object v13

    .line 146
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/DateRangeDto;->getTo()Ljava/time/LocalDate;

    .line 147
    .line 148
    .line 149
    move-result-object v11

    .line 150
    invoke-direct {v12, v13, v11}, Lss0/j;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 151
    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_7
    const/4 v12, 0x0

    .line 155
    :goto_4
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getVehicleSpecification()Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;

    .line 156
    .line 157
    .line 158
    move-result-object v11

    .line 159
    if-eqz v11, :cond_f

    .line 160
    .line 161
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getModel()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v14

    .line 165
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getTrimLevel()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v15

    .line 169
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getEngine()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v16

    .line 173
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getExteriorColour()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v17

    .line 177
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getInteriorColour()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v18

    .line 181
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getBattery()Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationBatteryDto;

    .line 182
    .line 183
    .line 184
    move-result-object v13

    .line 185
    if-eqz v13, :cond_8

    .line 186
    .line 187
    invoke-virtual {v13}, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationBatteryDto;->getCapacityInKWh()I

    .line 188
    .line 189
    .line 190
    move-result v13

    .line 191
    new-instance v8, Lqr0/h;

    .line 192
    .line 193
    invoke-direct {v8, v13}, Lqr0/h;-><init>(I)V

    .line 194
    .line 195
    .line 196
    move-object/from16 v19, v8

    .line 197
    .line 198
    goto :goto_5

    .line 199
    :cond_8
    const/16 v19, 0x0

    .line 200
    .line 201
    :goto_5
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getMaxPerformanceInKW()Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object v8

    .line 205
    if-eqz v8, :cond_9

    .line 206
    .line 207
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 208
    .line 209
    .line 210
    move-result v8

    .line 211
    move-object/from16 v23, v7

    .line 212
    .line 213
    int-to-double v6, v8

    .line 214
    new-instance v8, Lqr0/n;

    .line 215
    .line 216
    invoke-direct {v8, v6, v7}, Lqr0/n;-><init>(D)V

    .line 217
    .line 218
    .line 219
    move-object/from16 v20, v8

    .line 220
    .line 221
    goto :goto_6

    .line 222
    :cond_9
    move-object/from16 v23, v7

    .line 223
    .line 224
    const/16 v20, 0x0

    .line 225
    .line 226
    :goto_6
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getWltpRangeInKm()Ljava/lang/Integer;

    .line 227
    .line 228
    .line 229
    move-result-object v6

    .line 230
    if-eqz v6, :cond_a

    .line 231
    .line 232
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 233
    .line 234
    .line 235
    move-result v6

    .line 236
    int-to-double v6, v6

    .line 237
    const-wide v21, 0x408f400000000000L    # 1000.0

    .line 238
    .line 239
    .line 240
    .line 241
    .line 242
    mul-double v6, v6, v21

    .line 243
    .line 244
    new-instance v8, Lqr0/d;

    .line 245
    .line 246
    invoke-direct {v8, v6, v7}, Lqr0/d;-><init>(D)V

    .line 247
    .line 248
    .line 249
    move-object/from16 v21, v8

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_a
    const/16 v21, 0x0

    .line 253
    .line 254
    :goto_7
    invoke-virtual {v11}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationDto;->getWltpConsumption()Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationWltpConsumptionDto;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    if-eqz v6, :cond_e

    .line 259
    .line 260
    invoke-virtual {v6}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationWltpConsumptionDto;->getConsumptionInLitersPer100Km()Ljava/lang/Float;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    if-eqz v7, :cond_b

    .line 265
    .line 266
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 267
    .line 268
    .line 269
    move-result v7

    .line 270
    float-to-double v7, v7

    .line 271
    new-instance v11, Lqr0/i;

    .line 272
    .line 273
    invoke-direct {v11, v7, v8}, Lqr0/i;-><init>(D)V

    .line 274
    .line 275
    .line 276
    goto :goto_8

    .line 277
    :cond_b
    const/4 v11, 0x0

    .line 278
    :goto_8
    invoke-virtual {v6}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationWltpConsumptionDto;->getConsumptionInKWhPer100Km()Ljava/lang/Float;

    .line 279
    .line 280
    .line 281
    move-result-object v7

    .line 282
    if-eqz v7, :cond_c

    .line 283
    .line 284
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 285
    .line 286
    .line 287
    move-result v7

    .line 288
    float-to-double v7, v7

    .line 289
    new-instance v13, Lqr0/g;

    .line 290
    .line 291
    invoke-direct {v13, v7, v8}, Lqr0/g;-><init>(D)V

    .line 292
    .line 293
    .line 294
    goto :goto_9

    .line 295
    :cond_c
    const/4 v13, 0x0

    .line 296
    :goto_9
    invoke-virtual {v6}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleSpecificationWltpConsumptionDto;->getConsumptionInKgPer100Km()Ljava/lang/Float;

    .line 297
    .line 298
    .line 299
    move-result-object v6

    .line 300
    if-eqz v6, :cond_d

    .line 301
    .line 302
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 303
    .line 304
    .line 305
    move-result v6

    .line 306
    float-to-double v6, v6

    .line 307
    new-instance v8, Lqr0/j;

    .line 308
    .line 309
    invoke-direct {v8, v6, v7}, Lqr0/j;-><init>(D)V

    .line 310
    .line 311
    .line 312
    goto :goto_a

    .line 313
    :cond_d
    const/4 v8, 0x0

    .line 314
    :goto_a
    new-instance v6, Lss0/k0;

    .line 315
    .line 316
    invoke-direct {v6, v11, v13, v8}, Lss0/k0;-><init>(Lqr0/i;Lqr0/g;Lqr0/j;)V

    .line 317
    .line 318
    .line 319
    move-object/from16 v22, v6

    .line 320
    .line 321
    goto :goto_b

    .line 322
    :cond_e
    const/16 v22, 0x0

    .line 323
    .line 324
    :goto_b
    new-instance v13, Lss0/v;

    .line 325
    .line 326
    invoke-direct/range {v13 .. v22}, Lss0/v;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/h;Lqr0/n;Lqr0/d;Lss0/k0;)V

    .line 327
    .line 328
    .line 329
    move-object v11, v13

    .line 330
    goto :goto_c

    .line 331
    :cond_f
    move-object/from16 v23, v7

    .line 332
    .line 333
    const/4 v11, 0x0

    .line 334
    :goto_c
    invoke-virtual {v1}, Lcz/myskoda/api/bff_garage/v2/OrderedVehicleDto;->getCheckPoints()Ljava/util/List;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    if-eqz v1, :cond_12

    .line 339
    .line 340
    check-cast v1, Ljava/lang/Iterable;

    .line 341
    .line 342
    new-instance v6, Ljava/util/ArrayList;

    .line 343
    .line 344
    const/16 v7, 0xa

    .line 345
    .line 346
    invoke-static {v1, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 347
    .line 348
    .line 349
    move-result v7

    .line 350
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 351
    .line 352
    .line 353
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 354
    .line 355
    .line 356
    move-result-object v1

    .line 357
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 358
    .line 359
    .line 360
    move-result v7

    .line 361
    if-eqz v7, :cond_11

    .line 362
    .line 363
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v7

    .line 367
    check-cast v7, Lcz/myskoda/api/bff_garage/v2/CheckPointDto;

    .line 368
    .line 369
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    new-instance v8, Lss0/s;

    .line 373
    .line 374
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/CheckPointDto;->getStatus()Lcz/myskoda/api/bff_garage/v2/OrderStatusDto;

    .line 375
    .line 376
    .line 377
    move-result-object v13

    .line 378
    invoke-static {v13}, Lkp/n6;->c(Lcz/myskoda/api/bff_garage/v2/OrderStatusDto;)Lss0/t;

    .line 379
    .line 380
    .line 381
    move-result-object v13

    .line 382
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/CheckPointDto;->getDate()Ljava/time/LocalDate;

    .line 383
    .line 384
    .line 385
    move-result-object v14

    .line 386
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/CheckPointDto;->getEstimatedDateRange()Lcz/myskoda/api/bff_garage/v2/DateRangeDto;

    .line 387
    .line 388
    .line 389
    move-result-object v7

    .line 390
    if-eqz v7, :cond_10

    .line 391
    .line 392
    new-instance v15, Lss0/j;

    .line 393
    .line 394
    move-object/from16 v16, v0

    .line 395
    .line 396
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/DateRangeDto;->getFrom()Ljava/time/LocalDate;

    .line 397
    .line 398
    .line 399
    move-result-object v0

    .line 400
    invoke-virtual {v7}, Lcz/myskoda/api/bff_garage/v2/DateRangeDto;->getTo()Ljava/time/LocalDate;

    .line 401
    .line 402
    .line 403
    move-result-object v7

    .line 404
    invoke-direct {v15, v0, v7}, Lss0/j;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 405
    .line 406
    .line 407
    goto :goto_e

    .line 408
    :cond_10
    move-object/from16 v16, v0

    .line 409
    .line 410
    const/4 v15, 0x0

    .line 411
    :goto_e
    invoke-direct {v8, v13, v14, v15}, Lss0/s;-><init>(Lss0/t;Ljava/time/LocalDate;Lss0/j;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    move-object/from16 v0, v16

    .line 418
    .line 419
    goto :goto_d

    .line 420
    :cond_11
    move-object v8, v6

    .line 421
    goto :goto_f

    .line 422
    :cond_12
    const/4 v8, 0x0

    .line 423
    :goto_f
    new-instance v1, Lss0/u;

    .line 424
    .line 425
    move-object v7, v9

    .line 426
    move-object v9, v10

    .line 427
    const/4 v10, 0x0

    .line 428
    move-object v6, v12

    .line 429
    move-object v12, v8

    .line 430
    move-object v8, v6

    .line 431
    move-object/from16 v6, v23

    .line 432
    .line 433
    invoke-direct/range {v1 .. v12}, Lss0/u;-><init>(Ljava/lang/String;Ljava/lang/String;Lss0/a;Ljava/util/List;Ljava/lang/String;Lss0/t;Lss0/j;Ljava/lang/String;ILss0/v;Ljava/util/List;)V

    .line 434
    .line 435
    .line 436
    return-object v1
.end method

.method public static c(Lcz/myskoda/api/bff_garage/v2/OrderStatusDto;)Lss0/t;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Len0/a;->b:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p0, v0, :cond_4

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-eq p0, v0, :cond_3

    .line 19
    .line 20
    const/4 v0, 0x3

    .line 21
    if-eq p0, v0, :cond_2

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    if-eq p0, v0, :cond_1

    .line 25
    .line 26
    const/4 v0, 0x5

    .line 27
    if-ne p0, v0, :cond_0

    .line 28
    .line 29
    sget-object p0, Lss0/t;->n:Lss0/t;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    new-instance p0, La8/r0;

    .line 33
    .line 34
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    sget-object p0, Lss0/t;->m:Lss0/t;

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_2
    sget-object p0, Lss0/t;->l:Lss0/t;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_3
    sget-object p0, Lss0/t;->k:Lss0/t;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_4
    sget-object p0, Lss0/t;->j:Lss0/t;

    .line 48
    .line 49
    return-object p0
.end method
