.class public final Lc31/d;
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
    iput-object p1, p0, Lc31/d;->a:Lay0/a;

    .line 20
    .line 21
    iput-object p2, p0, Lc31/d;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lc31/d;->c:Lzv0/c;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Integer;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    const-class v0, Le31/n2;

    .line 2
    .line 3
    const-class v1, Ljava/util/List;

    .line 4
    .line 5
    const-string v2, " - "

    .line 6
    .line 7
    instance-of v3, p2, Lc31/c;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, p2

    .line 12
    check-cast v3, Lc31/c;

    .line 13
    .line 14
    iget v4, v3, Lc31/c;->h:I

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
    iput v4, v3, Lc31/c;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc31/c;

    .line 27
    .line 28
    invoke-direct {v3, p0, p2}, Lc31/c;-><init>(Lc31/d;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p2, v3, Lc31/c;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc31/c;->h:I

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
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 50
    .line 51
    .line 52
    goto/16 :goto_5

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
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 63
    .line 64
    .line 65
    goto/16 :goto_2

    .line 66
    .line 67
    :cond_3
    iget p0, v3, Lc31/c;->e:I

    .line 68
    .line 69
    iget p1, v3, Lc31/c;->d:I

    .line 70
    .line 71
    :try_start_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object p2, p0, Lc31/d;->a:Lay0/a;

    .line 79
    .line 80
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    new-instance v5, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 87
    .line 88
    .line 89
    iget-object v10, p0, Lc31/d;->b:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v10, "vehicle/v1/maintenance/services/"

    .line 95
    .line 96
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v5, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    :try_start_3
    iget-object p0, p0, Lc31/d;->c:Lzv0/c;

    .line 107
    .line 108
    new-instance v5, Lkw0/c;

    .line 109
    .line 110
    invoke-direct {v5}, Lkw0/c;-><init>()V

    .line 111
    .line 112
    .line 113
    invoke-static {v5, p2}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    if-eqz p1, :cond_5

    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    const-string p2, "odometerValue"

    .line 123
    .line 124
    new-instance v10, Ljava/lang/Integer;

    .line 125
    .line 126
    invoke-direct {v10, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 127
    .line 128
    .line 129
    invoke-static {v5, p2, v10}, Llp/je;->c(Lkw0/c;Ljava/lang/String;Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_5
    sget-object p1, Low0/b;->a:Low0/e;

    .line 133
    .line 134
    invoke-static {v5, p1}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 135
    .line 136
    .line 137
    sget-object p1, Low0/s;->b:Low0/s;

    .line 138
    .line 139
    invoke-virtual {v5, p1}, Lkw0/c;->b(Low0/s;)V

    .line 140
    .line 141
    .line 142
    new-instance p1, Lc2/k;

    .line 143
    .line 144
    invoke-direct {p1, v5, p0}, Lc2/k;-><init>(Lkw0/c;Lzv0/c;)V

    .line 145
    .line 146
    .line 147
    const/4 p0, 0x0

    .line 148
    iput p0, v3, Lc31/c;->d:I

    .line 149
    .line 150
    iput p0, v3, Lc31/c;->e:I

    .line 151
    .line 152
    iput v8, v3, Lc31/c;->h:I

    .line 153
    .line 154
    invoke-virtual {p1, v3}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p2

    .line 158
    if-ne p2, v4, :cond_6

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_6
    move p1, p0

    .line 162
    :goto_1
    check-cast p2, Law0/h;

    .line 163
    .line 164
    invoke-virtual {p2}, Law0/h;->c()Low0/v;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    sget-object v8, Low0/v;->f:Low0/v;

    .line 169
    .line 170
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    if-eqz v5, :cond_9

    .line 175
    .line 176
    invoke-virtual {p2}, Law0/h;->M()Law0/c;

    .line 177
    .line 178
    .line 179
    move-result-object p2

    .line 180
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 181
    .line 182
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 183
    .line 184
    .line 185
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 186
    :try_start_4
    sget-object v2, Lhy0/d0;->c:Lhy0/d0;

    .line 187
    .line 188
    const-class v2, Le31/s0;

    .line 189
    .line 190
    invoke-static {v2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    invoke-static {v2}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    invoke-static {v1, v2}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    .line 199
    .line 200
    .line 201
    move-result-object v9
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 202
    :catchall_0
    :try_start_5
    new-instance v1, Lzw0/a;

    .line 203
    .line 204
    invoke-direct {v1, v0, v9}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 205
    .line 206
    .line 207
    iput p1, v3, Lc31/c;->d:I

    .line 208
    .line 209
    iput p0, v3, Lc31/c;->e:I

    .line 210
    .line 211
    iput v7, v3, Lc31/c;->h:I

    .line 212
    .line 213
    invoke-virtual {p2, v1, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object p2

    .line 217
    if-ne p2, v4, :cond_7

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_7
    :goto_2
    if-eqz p2, :cond_8

    .line 221
    .line 222
    check-cast p2, Ljava/util/List;

    .line 223
    .line 224
    new-instance p0, Lo41/b;

    .line 225
    .line 226
    invoke-direct {p0, p2}, Lo41/b;-><init>(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    goto/16 :goto_8

    .line 230
    .line 231
    :cond_8
    new-instance p0, Ljava/lang/NullPointerException;

    .line 232
    .line 233
    const-string p1, "null cannot be cast to non-null type kotlin.collections.List<technology.cariad.appointmentbooking.base.data.models.AvailableServicesResponse>"

    .line 234
    .line 235
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 239
    :cond_9
    :try_start_6
    invoke-virtual {p2}, Law0/h;->M()Law0/c;

    .line 240
    .line 241
    .line 242
    move-result-object p2

    .line 243
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 244
    .line 245
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 246
    .line 247
    .line 248
    move-result-object v1
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 249
    :try_start_7
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 250
    .line 251
    .line 252
    move-result-object v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 253
    goto :goto_3

    .line 254
    :catchall_1
    move-object v0, v9

    .line 255
    :goto_3
    :try_start_8
    new-instance v5, Lzw0/a;

    .line 256
    .line 257
    invoke-direct {v5, v1, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 258
    .line 259
    .line 260
    iput p1, v3, Lc31/c;->d:I

    .line 261
    .line 262
    iput p0, v3, Lc31/c;->e:I

    .line 263
    .line 264
    iput v6, v3, Lc31/c;->h:I

    .line 265
    .line 266
    invoke-virtual {p2, v5, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object p2

    .line 270
    if-ne p2, v4, :cond_a

    .line 271
    .line 272
    :goto_4
    return-object v4

    .line 273
    :cond_a
    :goto_5
    if-eqz p2, :cond_e

    .line 274
    .line 275
    check-cast p2, Le31/n2;

    .line 276
    .line 277
    iget-object p0, p2, Le31/n2;->a:Le31/r1;

    .line 278
    .line 279
    if-eqz p0, :cond_b

    .line 280
    .line 281
    iget-object p1, p0, Le31/r1;->b:Ljava/lang/String;

    .line 282
    .line 283
    goto :goto_6

    .line 284
    :cond_b
    move-object p1, v9

    .line 285
    :goto_6
    if-nez p1, :cond_c

    .line 286
    .line 287
    const-string p1, ""

    .line 288
    .line 289
    :cond_c
    if-eqz p0, :cond_d

    .line 290
    .line 291
    iget-object p0, p0, Le31/r1;->a:Ljava/lang/String;

    .line 292
    .line 293
    if-eqz p0, :cond_d

    .line 294
    .line 295
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v9

    .line 299
    :cond_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 300
    .line 301
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 302
    .line 303
    .line 304
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 305
    .line 306
    .line 307
    invoke-virtual {p0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 308
    .line 309
    .line 310
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    goto :goto_7

    .line 315
    :cond_e
    new-instance p0, Ljava/lang/NullPointerException;

    .line 316
    .line 317
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ResponseError"

    .line 318
    .line 319
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    throw p0
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 323
    :catch_0
    move-exception p0

    .line 324
    :try_start_9
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object p0

    .line 328
    if-nez p0, :cond_f

    .line 329
    .line 330
    const-string p0, "UNKNOWN"

    .line 331
    .line 332
    :cond_f
    :goto_7
    new-instance p1, Ljava/lang/Exception;

    .line 333
    .line 334
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    new-instance p0, Lo41/a;

    .line 338
    .line 339
    invoke-direct {p0, p1}, Lo41/a;-><init>(Ljava/lang/Throwable;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 340
    .line 341
    .line 342
    :goto_8
    return-object p0

    .line 343
    :catchall_2
    move-exception p0

    .line 344
    new-instance p1, Lo41/a;

    .line 345
    .line 346
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 347
    .line 348
    .line 349
    return-object p1
.end method
