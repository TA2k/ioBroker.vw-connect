.class public final Lc31/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/a;

.field public final b:Ljava/lang/String;

.field public final c:Lzv0/c;


# direct methods
.method public constructor <init>(Lay0/a;Ljava/lang/String;Lzv0/c;)V
    .locals 1

    .line 1
    const-string v0, "getVinVehicle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "baseUrl"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "http"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lc31/b;->a:Lay0/a;

    .line 20
    .line 21
    iput-object p2, p0, Lc31/b;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lc31/b;->c:Lzv0/c;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Le31/u;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    const-class v0, Le31/n2;

    .line 2
    .line 3
    const-class v1, Le31/g0;

    .line 4
    .line 5
    const-string v2, " - "

    .line 6
    .line 7
    instance-of v3, p2, Lc31/a;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, p2

    .line 12
    check-cast v3, Lc31/a;

    .line 13
    .line 14
    iget v4, v3, Lc31/a;->h:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lc31/a;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc31/a;

    .line 27
    .line 28
    invoke-direct {v3, p0, p2}, Lc31/a;-><init>(Lc31/b;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p2, v3, Lc31/a;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc31/a;->h:I

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const/4 v9, 0x0

    .line 41
    if-eqz v5, :cond_4

    .line 42
    .line 43
    if-eq v5, v8, :cond_3

    .line 44
    .line 45
    if-eq v5, v7, :cond_2

    .line 46
    .line 47
    if-ne v5, v6, :cond_1

    .line 48
    .line 49
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_4

    .line 50
    .line 51
    .line 52
    goto/16 :goto_8

    .line 53
    .line 54
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_2
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 63
    .line 64
    .line 65
    goto/16 :goto_5

    .line 66
    .line 67
    :cond_3
    iget p0, v3, Lc31/a;->e:I

    .line 68
    .line 69
    iget p1, v3, Lc31/a;->d:I

    .line 70
    .line 71
    :try_start_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_4

    .line 72
    .line 73
    .line 74
    goto/16 :goto_4

    .line 75
    .line 76
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p2, p0, Lc31/b;->a:Lay0/a;

    .line 80
    .line 81
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    new-instance v5, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 88
    .line 89
    .line 90
    iget-object v10, p0, Lc31/b;->b:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v10, "vehicle/v1/maintenance/availability/"

    .line 96
    .line 97
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v5, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    :try_start_3
    iget-object p0, p0, Lc31/b;->c:Lzv0/c;

    .line 108
    .line 109
    new-instance v5, Lkw0/c;

    .line 110
    .line 111
    invoke-direct {v5}, Lkw0/c;-><init>()V

    .line 112
    .line 113
    .line 114
    sget-object v10, Low0/s;->c:Low0/s;

    .line 115
    .line 116
    invoke-virtual {v5, v10}, Lkw0/c;->b(Low0/s;)V

    .line 117
    .line 118
    .line 119
    invoke-static {v5, p2}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    sget-object p2, Low0/b;->a:Low0/e;

    .line 123
    .line 124
    invoke-static {v5, p2}, Ljp/pc;->d(Lkw0/c;Low0/e;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_4

    .line 125
    .line 126
    .line 127
    const-class p2, Le31/u;

    .line 128
    .line 129
    if-nez p1, :cond_5

    .line 130
    .line 131
    :try_start_4
    sget-object p1, Lrw0/b;->a:Lrw0/b;

    .line 132
    .line 133
    iput-object p1, v5, Lkw0/c;->d:Ljava/lang/Object;

    .line 134
    .line 135
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 136
    .line 137
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 138
    .line 139
    .line 140
    move-result-object p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 141
    :try_start_5
    invoke-static {p2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 142
    .line 143
    .line 144
    move-result-object p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 145
    goto :goto_1

    .line 146
    :catchall_0
    move-object p2, v9

    .line 147
    :goto_1
    :try_start_6
    new-instance v10, Lzw0/a;

    .line 148
    .line 149
    invoke-direct {v10, p1, p2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5, v10}, Lkw0/c;->a(Lzw0/a;)V

    .line 153
    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_5
    iput-object p1, v5, Lkw0/c;->d:Ljava/lang/Object;

    .line 157
    .line 158
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 159
    .line 160
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 161
    .line 162
    .line 163
    move-result-object p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 164
    :try_start_7
    invoke-static {p2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 165
    .line 166
    .line 167
    move-result-object p2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 168
    goto :goto_2

    .line 169
    :catchall_1
    move-object p2, v9

    .line 170
    :goto_2
    :try_start_8
    new-instance v10, Lzw0/a;

    .line 171
    .line 172
    invoke-direct {v10, p1, p2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v5, v10}, Lkw0/c;->a(Lzw0/a;)V

    .line 176
    .line 177
    .line 178
    :goto_3
    sget-object p1, Low0/s;->c:Low0/s;

    .line 179
    .line 180
    invoke-virtual {v5, p1}, Lkw0/c;->b(Low0/s;)V

    .line 181
    .line 182
    .line 183
    new-instance p1, Lc2/k;

    .line 184
    .line 185
    invoke-direct {p1, v5, p0}, Lc2/k;-><init>(Lkw0/c;Lzv0/c;)V

    .line 186
    .line 187
    .line 188
    const/4 p0, 0x0

    .line 189
    iput p0, v3, Lc31/a;->d:I

    .line 190
    .line 191
    iput p0, v3, Lc31/a;->e:I

    .line 192
    .line 193
    iput v8, v3, Lc31/a;->h:I

    .line 194
    .line 195
    invoke-virtual {p1, v3}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p2

    .line 199
    if-ne p2, v4, :cond_6

    .line 200
    .line 201
    goto :goto_7

    .line 202
    :cond_6
    move p1, p0

    .line 203
    :goto_4
    check-cast p2, Law0/h;

    .line 204
    .line 205
    invoke-virtual {p2}, Law0/h;->c()Low0/v;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    sget-object v8, Low0/v;->f:Low0/v;

    .line 210
    .line 211
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v5

    .line 215
    if-eqz v5, :cond_9

    .line 216
    .line 217
    invoke-virtual {p2}, Law0/h;->M()Law0/c;

    .line 218
    .line 219
    .line 220
    move-result-object p2

    .line 221
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 222
    .line 223
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 224
    .line 225
    .line 226
    move-result-object v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 227
    :try_start_9
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 228
    .line 229
    .line 230
    move-result-object v9
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 231
    :catchall_2
    :try_start_a
    new-instance v1, Lzw0/a;

    .line 232
    .line 233
    invoke-direct {v1, v0, v9}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 234
    .line 235
    .line 236
    iput p1, v3, Lc31/a;->d:I

    .line 237
    .line 238
    iput p0, v3, Lc31/a;->e:I

    .line 239
    .line 240
    iput v7, v3, Lc31/a;->h:I

    .line 241
    .line 242
    invoke-virtual {p2, v1, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object p2

    .line 246
    if-ne p2, v4, :cond_7

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :cond_7
    :goto_5
    if-eqz p2, :cond_8

    .line 250
    .line 251
    check-cast p2, Le31/g0;

    .line 252
    .line 253
    new-instance p0, Lo41/b;

    .line 254
    .line 255
    invoke-direct {p0, p2}, Lo41/b;-><init>(Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    goto/16 :goto_b

    .line 259
    .line 260
    :cond_8
    new-instance p0, Ljava/lang/NullPointerException;

    .line 261
    .line 262
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.AvailableCapacityResponse"

    .line 263
    .line 264
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    throw p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 268
    :cond_9
    :try_start_b
    invoke-virtual {p2}, Law0/h;->M()Law0/c;

    .line 269
    .line 270
    .line 271
    move-result-object p2

    .line 272
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 273
    .line 274
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 275
    .line 276
    .line 277
    move-result-object v1
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_0
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 278
    :try_start_c
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 279
    .line 280
    .line 281
    move-result-object v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_3

    .line 282
    goto :goto_6

    .line 283
    :catchall_3
    move-object v0, v9

    .line 284
    :goto_6
    :try_start_d
    new-instance v5, Lzw0/a;

    .line 285
    .line 286
    invoke-direct {v5, v1, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 287
    .line 288
    .line 289
    iput p1, v3, Lc31/a;->d:I

    .line 290
    .line 291
    iput p0, v3, Lc31/a;->e:I

    .line 292
    .line 293
    iput v6, v3, Lc31/a;->h:I

    .line 294
    .line 295
    invoke-virtual {p2, v5, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object p2

    .line 299
    if-ne p2, v4, :cond_a

    .line 300
    .line 301
    :goto_7
    return-object v4

    .line 302
    :cond_a
    :goto_8
    if-eqz p2, :cond_e

    .line 303
    .line 304
    check-cast p2, Le31/n2;

    .line 305
    .line 306
    iget-object p0, p2, Le31/n2;->a:Le31/r1;

    .line 307
    .line 308
    if-eqz p0, :cond_b

    .line 309
    .line 310
    iget-object p1, p0, Le31/r1;->b:Ljava/lang/String;

    .line 311
    .line 312
    goto :goto_9

    .line 313
    :cond_b
    move-object p1, v9

    .line 314
    :goto_9
    if-nez p1, :cond_c

    .line 315
    .line 316
    const-string p1, ""

    .line 317
    .line 318
    :cond_c
    if-eqz p0, :cond_d

    .line 319
    .line 320
    iget-object p0, p0, Le31/r1;->a:Ljava/lang/String;

    .line 321
    .line 322
    if-eqz p0, :cond_d

    .line 323
    .line 324
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object v9

    .line 328
    :cond_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 331
    .line 332
    .line 333
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {p0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 337
    .line 338
    .line 339
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    goto :goto_a

    .line 344
    :cond_e
    new-instance p0, Ljava/lang/NullPointerException;

    .line 345
    .line 346
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ResponseError"

    .line 347
    .line 348
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    throw p0
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_0
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 352
    :catch_0
    move-exception p0

    .line 353
    :try_start_e
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object p0

    .line 357
    if-nez p0, :cond_f

    .line 358
    .line 359
    const-string p0, "UNKNOWN"

    .line 360
    .line 361
    :cond_f
    :goto_a
    new-instance p1, Ljava/lang/Exception;

    .line 362
    .line 363
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    new-instance p0, Lo41/a;

    .line 367
    .line 368
    invoke-direct {p0, p1}, Lo41/a;-><init>(Ljava/lang/Throwable;)V
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 369
    .line 370
    .line 371
    :goto_b
    return-object p0

    .line 372
    :catchall_4
    move-exception p0

    .line 373
    new-instance p1, Lo41/a;

    .line 374
    .line 375
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 376
    .line 377
    .line 378
    return-object p1
.end method
