.class public final synthetic Lo10/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lo10/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lo10/e;I)V
    .locals 0

    .line 1
    iput p3, p0, Lo10/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo10/c;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lo10/c;->f:Lo10/e;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lo10/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lo10/c;->e:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Lo10/c;->f:Lo10/e;

    .line 9
    .line 10
    check-cast p1, Lua/a;

    .line 11
    .line 12
    const-string v1, "_connection"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "SELECT * FROM departure_plan WHERE vin = ? LIMIT 1"

    .line 18
    .line 19
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const/4 v2, 0x1

    .line 24
    :try_start_0
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string v0, "vin"

    .line 28
    .line 29
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const-string v2, "target_temperature_celsius"

    .line 34
    .line 35
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    const-string v3, "min_battery_charged_state_percent"

    .line 40
    .line 41
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    const-string v4, "first_occurring_timer_id"

    .line 46
    .line 47
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    const-string v5, "car_captured_timestamp"

    .line 52
    .line 53
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    new-instance v6, Landroidx/collection/f;

    .line 58
    .line 59
    const/4 v7, 0x0

    .line 60
    invoke-direct {v6, v7}, Landroidx/collection/a1;-><init>(I)V

    .line 61
    .line 62
    .line 63
    :cond_0
    :goto_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    if-eqz v7, :cond_1

    .line 68
    .line 69
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-virtual {v6, v7}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v8

    .line 77
    if-nez v8, :cond_0

    .line 78
    .line 79
    new-instance v8, Ljava/util/ArrayList;

    .line 80
    .line 81
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v6, v7, v8}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :catchall_0
    move-exception v0

    .line 89
    move-object p0, v0

    .line 90
    goto/16 :goto_5

    .line 91
    .line 92
    :cond_1
    invoke-interface {v1}, Lua/c;->reset()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0, p1, v6}, Lo10/e;->b(Lua/a;Landroidx/collection/f;)V

    .line 96
    .line 97
    .line 98
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    const/4 p1, 0x0

    .line 103
    if-eqz p0, :cond_6

    .line 104
    .line 105
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-eqz p0, :cond_2

    .line 114
    .line 115
    move-object v9, p1

    .line 116
    goto :goto_1

    .line 117
    :cond_2
    invoke-interface {v1, v2}, Lua/c;->getDouble(I)D

    .line 118
    .line 119
    .line 120
    move-result-wide v9

    .line 121
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    move-object v9, p0

    .line 126
    :goto_1
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-eqz p0, :cond_3

    .line 131
    .line 132
    move-object v10, p1

    .line 133
    goto :goto_2

    .line 134
    :cond_3
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 135
    .line 136
    .line 137
    move-result-wide v2

    .line 138
    long-to-int p0, v2

    .line 139
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    move-object v10, p0

    .line 144
    :goto_2
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 145
    .line 146
    .line 147
    move-result p0

    .line 148
    if-eqz p0, :cond_4

    .line 149
    .line 150
    move-object v11, p1

    .line 151
    goto :goto_3

    .line 152
    :cond_4
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 153
    .line 154
    .line 155
    move-result-wide v2

    .line 156
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    move-object v11, p0

    .line 161
    :goto_3
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-eqz p0, :cond_5

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_5
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    :goto_4
    invoke-static {p1}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 173
    .line 174
    .line 175
    move-result-object v12

    .line 176
    new-instance v7, Lo10/f;

    .line 177
    .line 178
    invoke-direct/range {v7 .. v12}, Lo10/f;-><init>(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Integer;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    invoke-static {v6, p0}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    const-string p1, "getValue(...)"

    .line 190
    .line 191
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    check-cast p0, Ljava/util/List;

    .line 195
    .line 196
    new-instance p1, Lo10/g;

    .line 197
    .line 198
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 199
    .line 200
    .line 201
    iput-object v7, p1, Lo10/g;->a:Lo10/f;

    .line 202
    .line 203
    iput-object p0, p1, Lo10/g;->b:Ljava/util/List;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 204
    .line 205
    :cond_6
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 206
    .line 207
    .line 208
    return-object p1

    .line 209
    :goto_5
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 210
    .line 211
    .line 212
    throw p0

    .line 213
    :pswitch_0
    iget-object v0, p0, Lo10/c;->e:Ljava/lang/String;

    .line 214
    .line 215
    iget-object p0, p0, Lo10/c;->f:Lo10/e;

    .line 216
    .line 217
    check-cast p1, Lua/a;

    .line 218
    .line 219
    const-string v1, "_connection"

    .line 220
    .line 221
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    const-string v1, "SELECT * FROM departure_plan WHERE vin = ? LIMIT 1"

    .line 225
    .line 226
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 227
    .line 228
    .line 229
    move-result-object v1

    .line 230
    const/4 v2, 0x1

    .line 231
    :try_start_1
    invoke-interface {v1, v2, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 232
    .line 233
    .line 234
    const-string v0, "vin"

    .line 235
    .line 236
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 237
    .line 238
    .line 239
    move-result v0

    .line 240
    const-string v2, "target_temperature_celsius"

    .line 241
    .line 242
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 243
    .line 244
    .line 245
    move-result v2

    .line 246
    const-string v3, "min_battery_charged_state_percent"

    .line 247
    .line 248
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 249
    .line 250
    .line 251
    move-result v3

    .line 252
    const-string v4, "first_occurring_timer_id"

    .line 253
    .line 254
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 255
    .line 256
    .line 257
    move-result v4

    .line 258
    const-string v5, "car_captured_timestamp"

    .line 259
    .line 260
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 261
    .line 262
    .line 263
    move-result v5

    .line 264
    new-instance v6, Landroidx/collection/f;

    .line 265
    .line 266
    const/4 v7, 0x0

    .line 267
    invoke-direct {v6, v7}, Landroidx/collection/a1;-><init>(I)V

    .line 268
    .line 269
    .line 270
    :cond_7
    :goto_6
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 271
    .line 272
    .line 273
    move-result v7

    .line 274
    if-eqz v7, :cond_8

    .line 275
    .line 276
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v7

    .line 280
    invoke-virtual {v6, v7}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v8

    .line 284
    if-nez v8, :cond_7

    .line 285
    .line 286
    new-instance v8, Ljava/util/ArrayList;

    .line 287
    .line 288
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v6, v7, v8}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    goto :goto_6

    .line 295
    :catchall_1
    move-exception v0

    .line 296
    move-object p0, v0

    .line 297
    goto/16 :goto_b

    .line 298
    .line 299
    :cond_8
    invoke-interface {v1}, Lua/c;->reset()V

    .line 300
    .line 301
    .line 302
    invoke-virtual {p0, p1, v6}, Lo10/e;->b(Lua/a;Landroidx/collection/f;)V

    .line 303
    .line 304
    .line 305
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 306
    .line 307
    .line 308
    move-result p0

    .line 309
    const/4 p1, 0x0

    .line 310
    if-eqz p0, :cond_d

    .line 311
    .line 312
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v8

    .line 316
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 317
    .line 318
    .line 319
    move-result p0

    .line 320
    if-eqz p0, :cond_9

    .line 321
    .line 322
    move-object v9, p1

    .line 323
    goto :goto_7

    .line 324
    :cond_9
    invoke-interface {v1, v2}, Lua/c;->getDouble(I)D

    .line 325
    .line 326
    .line 327
    move-result-wide v9

    .line 328
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    move-object v9, p0

    .line 333
    :goto_7
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 334
    .line 335
    .line 336
    move-result p0

    .line 337
    if-eqz p0, :cond_a

    .line 338
    .line 339
    move-object v10, p1

    .line 340
    goto :goto_8

    .line 341
    :cond_a
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 342
    .line 343
    .line 344
    move-result-wide v2

    .line 345
    long-to-int p0, v2

    .line 346
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    move-object v10, p0

    .line 351
    :goto_8
    invoke-interface {v1, v4}, Lua/c;->isNull(I)Z

    .line 352
    .line 353
    .line 354
    move-result p0

    .line 355
    if-eqz p0, :cond_b

    .line 356
    .line 357
    move-object v11, p1

    .line 358
    goto :goto_9

    .line 359
    :cond_b
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 360
    .line 361
    .line 362
    move-result-wide v2

    .line 363
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 364
    .line 365
    .line 366
    move-result-object p0

    .line 367
    move-object v11, p0

    .line 368
    :goto_9
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 369
    .line 370
    .line 371
    move-result p0

    .line 372
    if-eqz p0, :cond_c

    .line 373
    .line 374
    goto :goto_a

    .line 375
    :cond_c
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object p1

    .line 379
    :goto_a
    invoke-static {p1}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 380
    .line 381
    .line 382
    move-result-object v12

    .line 383
    new-instance v7, Lo10/f;

    .line 384
    .line 385
    invoke-direct/range {v7 .. v12}, Lo10/f;-><init>(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Integer;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V

    .line 386
    .line 387
    .line 388
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object p0

    .line 392
    invoke-static {v6, p0}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    const-string p1, "getValue(...)"

    .line 397
    .line 398
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 399
    .line 400
    .line 401
    check-cast p0, Ljava/util/List;

    .line 402
    .line 403
    new-instance p1, Lo10/g;

    .line 404
    .line 405
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 406
    .line 407
    .line 408
    iput-object v7, p1, Lo10/g;->a:Lo10/f;

    .line 409
    .line 410
    iput-object p0, p1, Lo10/g;->b:Ljava/util/List;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 411
    .line 412
    :cond_d
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 413
    .line 414
    .line 415
    return-object p1

    .line 416
    :goto_b
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 417
    .line 418
    .line 419
    throw p0

    .line 420
    nop

    .line 421
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
