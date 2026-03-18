.class public final Lhz0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/z1;
.implements Lhz0/i;
.implements Llz0/c;


# instance fields
.field public final a:Lhz0/l0;

.field public b:Ljava/lang/Integer;

.field public c:Ljava/lang/Integer;

.field public d:Ljava/lang/Integer;


# direct methods
.method public synthetic constructor <init>()V
    .locals 2

    .line 6
    new-instance v0, Lhz0/l0;

    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1}, Lhz0/l0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 8
    invoke-direct {p0, v0, v1, v1, v1}, Lhz0/h0;-><init>(Lhz0/l0;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    return-void
.end method

.method public constructor <init>(Lhz0/l0;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 3
    iput-object p2, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 4
    iput-object p3, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 5
    iput-object p4, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    return-void
.end method


# virtual methods
.method public final A(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final C()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final a()Lhz0/h0;
    .locals 4

    .line 1
    new-instance v0, Lhz0/h0;

    .line 2
    .line 3
    new-instance v1, Lhz0/l0;

    .line 4
    .line 5
    iget-object v2, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 6
    .line 7
    iget-object v3, v2, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 8
    .line 9
    iget-object v2, v2, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-direct {v1, v3, v2}, Lhz0/l0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 15
    .line 16
    iget-object v3, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 17
    .line 18
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-direct {v0, v1, v2, v3, p0}, Lhz0/h0;-><init>(Lhz0/l0;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public final b()Lgz0/s;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, " of "

    .line 4
    .line 5
    iget-object v2, v0, Lhz0/h0;->a:Lhz0/l0;

    .line 6
    .line 7
    iget-object v3, v2, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 8
    .line 9
    const-string v4, "year"

    .line 10
    .line 11
    invoke-static {v3, v4}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    iget-object v4, v0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    const-string v6, "<this>"

    .line 22
    .line 23
    const/4 v7, 0x1

    .line 24
    if-nez v4, :cond_0

    .line 25
    .line 26
    new-instance v1, Lgz0/s;

    .line 27
    .line 28
    iget-object v2, v2, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 29
    .line 30
    const-string v4, "monthNumber"

    .line 31
    .line 32
    invoke-static {v2, v4}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    iget-object v4, v0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 40
    .line 41
    const-string v8, "day"

    .line 42
    .line 43
    invoke-static {v4, v8}, Lhz0/e2;->a(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    invoke-direct {v1, v3, v2, v4}, Lgz0/s;-><init>(III)V

    .line 51
    .line 52
    .line 53
    move v15, v7

    .line 54
    goto/16 :goto_2

    .line 55
    .line 56
    :cond_0
    new-instance v8, Lgz0/s;

    .line 57
    .line 58
    invoke-direct {v8, v3, v7, v7}, Lgz0/s;-><init>(III)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    sub-int/2addr v9, v7

    .line 66
    sget-object v10, Lgz0/k;->Companion:Lgz0/b;

    .line 67
    .line 68
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    sget-object v10, Lgz0/k;->a:Lgz0/f;

    .line 72
    .line 73
    const-string v11, "unit"

    .line 74
    .line 75
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    int-to-long v11, v9

    .line 79
    sget v9, Lgz0/t;->c:I

    .line 80
    .line 81
    iget-object v9, v8, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 82
    .line 83
    :try_start_0
    iget v13, v10, Lgz0/f;->b:I

    .line 84
    .line 85
    int-to-long v13, v13

    .line 86
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->multiplyExact(JJ)J

    .line 87
    .line 88
    .line 89
    move-result-wide v13
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    .line 90
    move v15, v7

    .line 91
    move-object/from16 v16, v8

    .line 92
    .line 93
    :try_start_1
    invoke-virtual {v9}, Ljava/time/LocalDate;->toEpochDay()J

    .line 94
    .line 95
    .line 96
    move-result-wide v7

    .line 97
    invoke-static {v7, v8, v13, v14}, Ljava/lang/Math;->addExact(JJ)J

    .line 98
    .line 99
    .line 100
    move-result-wide v7

    .line 101
    sget-wide v13, Lgz0/t;->a:J

    .line 102
    .line 103
    sget-wide v17, Lgz0/t;->b:J

    .line 104
    .line 105
    cmp-long v9, v7, v17

    .line 106
    .line 107
    if-gtz v9, :cond_8

    .line 108
    .line 109
    cmp-long v9, v13, v7

    .line 110
    .line 111
    if-gtz v9, :cond_8

    .line 112
    .line 113
    invoke-static {v7, v8}, Ljava/time/LocalDate;->ofEpochDay(J)Ljava/time/LocalDate;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    const-string v8, "ofEpochDay(...)"

    .line 118
    .line 119
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    new-instance v8, Lgz0/s;

    .line 123
    .line 124
    invoke-direct {v8, v7}, Lgz0/s;-><init>(Ljava/time/LocalDate;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 125
    .line 126
    .line 127
    invoke-virtual {v7}, Ljava/time/LocalDate;->getYear()I

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    const-string v10, "Can not create a LocalDate from the given input: the day of year is "

    .line 132
    .line 133
    if-ne v9, v3, :cond_7

    .line 134
    .line 135
    iget-object v3, v2, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 136
    .line 137
    const-string v9, "getMonth(...)"

    .line 138
    .line 139
    const-string v11, ", but "

    .line 140
    .line 141
    if-eqz v3, :cond_2

    .line 142
    .line 143
    invoke-virtual {v7}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v3}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    add-int/2addr v3, v15

    .line 162
    iget-object v12, v2, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 163
    .line 164
    if-eqz v12, :cond_1

    .line 165
    .line 166
    invoke-virtual {v12}, Ljava/lang/Integer;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v12

    .line 170
    if-ne v3, v12, :cond_1

    .line 171
    .line 172
    goto :goto_0

    .line 173
    :cond_1
    new-instance v0, Lgz0/a;

    .line 174
    .line 175
    new-instance v1, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    invoke-direct {v1, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v3, ", which is "

    .line 184
    .line 185
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v7}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    invoke-static {v3}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 196
    .line 197
    .line 198
    move-result-object v3

    .line 199
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 200
    .line 201
    .line 202
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    iget-object v2, v2, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 206
    .line 207
    const-string v3, " was specified as the month number"

    .line 208
    .line 209
    invoke-static {v1, v2, v3}, Lkx/a;->l(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    invoke-direct {v0, v1, v5}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 214
    .line 215
    .line 216
    throw v0

    .line 217
    :cond_2
    :goto_0
    iget-object v2, v0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 218
    .line 219
    if-eqz v2, :cond_4

    .line 220
    .line 221
    invoke-virtual {v7}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    iget-object v3, v0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 226
    .line 227
    if-eqz v3, :cond_3

    .line 228
    .line 229
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    if-ne v2, v3, :cond_3

    .line 234
    .line 235
    goto :goto_1

    .line 236
    :cond_3
    new-instance v2, Lgz0/a;

    .line 237
    .line 238
    new-instance v3, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    invoke-direct {v3, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    const-string v4, ", which is the day "

    .line 247
    .line 248
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    invoke-virtual {v7}, Ljava/time/LocalDate;->getDayOfMonth()I

    .line 252
    .line 253
    .line 254
    move-result v4

    .line 255
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 256
    .line 257
    .line 258
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    invoke-virtual {v7}, Ljava/time/LocalDate;->getMonth()Ljava/time/Month;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    invoke-static {v1}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v3, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    iget-object v0, v0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 279
    .line 280
    const-string v1, " was specified as the day of month"

    .line 281
    .line 282
    invoke-static {v3, v0, v1}, Lkx/a;->l(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;)Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    invoke-direct {v2, v0, v5}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 287
    .line 288
    .line 289
    throw v2

    .line 290
    :cond_4
    :goto_1
    move-object v1, v8

    .line 291
    :goto_2
    iget-object v0, v0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 292
    .line 293
    if-eqz v0, :cond_6

    .line 294
    .line 295
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 296
    .line 297
    .line 298
    move-result v0

    .line 299
    iget-object v2, v1, Lgz0/s;->d:Ljava/time/LocalDate;

    .line 300
    .line 301
    invoke-virtual {v2}, Ljava/time/LocalDate;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    const-string v4, "getDayOfWeek(...)"

    .line 306
    .line 307
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    sget-object v7, Lgz0/l;->e:Lsx0/b;

    .line 311
    .line 312
    invoke-virtual {v3}, Ljava/time/DayOfWeek;->getValue()I

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    sub-int/2addr v3, v15

    .line 317
    invoke-virtual {v7, v3}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v3

    .line 321
    check-cast v3, Lgz0/l;

    .line 322
    .line 323
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 327
    .line 328
    .line 329
    move-result v3

    .line 330
    add-int/2addr v3, v15

    .line 331
    if-eq v0, v3, :cond_6

    .line 332
    .line 333
    new-instance v3, Lgz0/a;

    .line 334
    .line 335
    new-instance v6, Ljava/lang/StringBuilder;

    .line 336
    .line 337
    const-string v8, "Can not create a LocalDate from the given input: the day of week is "

    .line 338
    .line 339
    invoke-direct {v6, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    if-gt v15, v0, :cond_5

    .line 343
    .line 344
    const/16 v8, 0x8

    .line 345
    .line 346
    if-ge v0, v8, :cond_5

    .line 347
    .line 348
    sub-int/2addr v0, v15

    .line 349
    invoke-virtual {v7, v0}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    check-cast v0, Lgz0/l;

    .line 354
    .line 355
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 356
    .line 357
    .line 358
    const-string v0, " but the date is "

    .line 359
    .line 360
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 364
    .line 365
    .line 366
    const-string v0, ", which is a "

    .line 367
    .line 368
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    invoke-virtual {v2}, Ljava/time/LocalDate;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v0}, Ljava/time/DayOfWeek;->getValue()I

    .line 379
    .line 380
    .line 381
    move-result v0

    .line 382
    const/4 v15, 0x1

    .line 383
    sub-int/2addr v0, v15

    .line 384
    invoke-virtual {v7, v0}, Lsx0/b;->get(I)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v0

    .line 388
    check-cast v0, Lgz0/l;

    .line 389
    .line 390
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 391
    .line 392
    .line 393
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    invoke-direct {v3, v0, v5}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 398
    .line 399
    .line 400
    throw v3

    .line 401
    :cond_5
    const-string v1, "Expected ISO day-of-week number in 1..7, got "

    .line 402
    .line 403
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 404
    .line 405
    .line 406
    move-result-object v0

    .line 407
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 408
    .line 409
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 410
    .line 411
    .line 412
    move-result-object v0

    .line 413
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    throw v1

    .line 417
    :cond_6
    return-object v1

    .line 418
    :cond_7
    new-instance v0, Lgz0/a;

    .line 419
    .line 420
    new-instance v1, Ljava/lang/StringBuilder;

    .line 421
    .line 422
    invoke-direct {v1, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 426
    .line 427
    .line 428
    const-string v2, ", which is not a valid day of year for the year "

    .line 429
    .line 430
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 431
    .line 432
    .line 433
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 434
    .line 435
    .line 436
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    invoke-direct {v0, v1, v5}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 441
    .line 442
    .line 443
    throw v0

    .line 444
    :catch_0
    move-exception v0

    .line 445
    goto :goto_3

    .line 446
    :cond_8
    :try_start_2
    new-instance v0, Ljava/time/DateTimeException;

    .line 447
    .line 448
    const-string v2, "The resulting day "

    .line 449
    .line 450
    const-string v3, " is out of supported LocalDate range."

    .line 451
    .line 452
    invoke-static {v7, v8, v2, v3}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v2

    .line 456
    invoke-direct {v0, v2}, Ljava/time/DateTimeException;-><init>(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    throw v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 460
    :catch_1
    move-exception v0

    .line 461
    move-object/from16 v16, v8

    .line 462
    .line 463
    :goto_3
    instance-of v2, v0, Ljava/time/DateTimeException;

    .line 464
    .line 465
    if-nez v2, :cond_9

    .line 466
    .line 467
    instance-of v2, v0, Ljava/lang/ArithmeticException;

    .line 468
    .line 469
    if-nez v2, :cond_9

    .line 470
    .line 471
    throw v0

    .line 472
    :cond_9
    new-instance v2, La8/r0;

    .line 473
    .line 474
    new-instance v3, Ljava/lang/StringBuilder;

    .line 475
    .line 476
    const-string v4, "The result of adding "

    .line 477
    .line 478
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v3, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 482
    .line 483
    .line 484
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    invoke-virtual {v3, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 488
    .line 489
    .line 490
    const-string v1, " to "

    .line 491
    .line 492
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 493
    .line 494
    .line 495
    move-object/from16 v1, v16

    .line 496
    .line 497
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 498
    .line 499
    .line 500
    const-string v1, " is out of LocalDate range."

    .line 501
    .line 502
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 503
    .line 504
    .line 505
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v1

    .line 509
    const-string v3, "message"

    .line 510
    .line 511
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    invoke-direct {v2, v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 515
    .line 516
    .line 517
    throw v2
.end method

.method public final bridge synthetic copy()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhz0/h0;->a()Lhz0/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lhz0/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lhz0/h0;

    .line 6
    .line 7
    iget-object v0, p1, Lhz0/h0;->a:Lhz0/l0;

    .line 8
    .line 9
    iget-object v1, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 18
    .line 19
    iget-object v1, p1, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    iget-object v0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 28
    .line 29
    iget-object v1, p1, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 38
    .line 39
    iget-object p1, p1, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_0

    .line 46
    .line 47
    const/4 p0, 0x1

    .line 48
    return p0

    .line 49
    :cond_0
    const/4 p0, 0x0

    .line 50
    return p0
.end method

.method public final g(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lhz0/l0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit16 v0, v0, 0x745f

    .line 8
    .line 9
    iget-object v1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v1, v2

    .line 20
    :goto_0
    mul-int/lit16 v1, v1, 0x3c1

    .line 21
    .line 22
    add-int/2addr v1, v0

    .line 23
    iget-object v0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v2

    .line 33
    :goto_1
    mul-int/lit8 v0, v0, 0x1f

    .line 34
    .line 35
    add-int/2addr v0, v1

    .line 36
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 37
    .line 38
    if-eqz p0, :cond_2

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    :cond_2
    add-int/2addr v0, v2

    .line 45
    return v0
.end method

.method public final i(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final n(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final s(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 2
    .line 3
    iput-object p1, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 4
    .line 5
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 2
    .line 3
    const/16 v1, 0x2d

    .line 4
    .line 5
    const/16 v2, 0x29

    .line 6
    .line 7
    const-string v3, " (day of week is "

    .line 8
    .line 9
    iget-object v4, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 10
    .line 11
    const-string v5, "??"

    .line 12
    .line 13
    if-nez v0, :cond_2

    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 27
    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    move-object v1, v5

    .line 31
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 38
    .line 39
    if-nez p0, :cond_1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    move-object v5, p0

    .line 43
    :goto_0
    invoke-static {v0, v5, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->n(Ljava/lang/StringBuilder;Ljava/lang/Object;C)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_2
    iget-object v0, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 49
    .line 50
    if-nez v0, :cond_5

    .line 51
    .line 52
    iget-object v0, v4, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 53
    .line 54
    if-nez v0, :cond_5

    .line 55
    .line 56
    new-instance v0, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v1, "("

    .line 59
    .line 60
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    iget-object v1, v4, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 64
    .line 65
    if-nez v1, :cond_3

    .line 66
    .line 67
    move-object v1, v5

    .line 68
    :cond_3
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ")-"

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 85
    .line 86
    if-nez p0, :cond_4

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_4
    move-object v5, p0

    .line 90
    :goto_1
    invoke-static {v0, v5, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->n(Ljava/lang/StringBuilder;Ljava/lang/Object;C)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :cond_5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    iget-object v1, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 107
    .line 108
    if-nez v1, :cond_6

    .line 109
    .line 110
    move-object v1, v5

    .line 111
    :cond_6
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    iget-object v1, p0, Lhz0/h0;->c:Ljava/lang/Integer;

    .line 118
    .line 119
    if-nez v1, :cond_7

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_7
    move-object v5, v1

    .line 123
    :goto_2
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v1, ", day of year is "

    .line 127
    .line 128
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 132
    .line 133
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0
.end method

.method public final v()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->a:Lhz0/l0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    return-object p0
.end method

.method public final y()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final z()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/h0;->d:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method
