.class public final Lc31/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/a;

.field public final b:Ljava/lang/String;

.field public final c:Lzv0/c;

.field public final d:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lay0/a;Ljava/lang/String;Lzv0/c;Ljava/lang/String;)V
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
    const-string v0, "languageTag"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lc31/l;->a:Lay0/a;

    .line 25
    .line 26
    iput-object p2, p0, Lc31/l;->b:Ljava/lang/String;

    .line 27
    .line 28
    iput-object p3, p0, Lc31/l;->c:Lzv0/c;

    .line 29
    .line 30
    iput-object p4, p0, Lc31/l;->d:Ljava/lang/String;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    const-class v0, Le31/n2;

    .line 2
    .line 3
    const-class v1, Le31/i2;

    .line 4
    .line 5
    const-string v2, " - "

    .line 6
    .line 7
    instance-of v3, p1, Lc31/k;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, p1

    .line 12
    check-cast v3, Lc31/k;

    .line 13
    .line 14
    iget v4, v3, Lc31/k;->h:I

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
    iput v4, v3, Lc31/k;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc31/k;

    .line 27
    .line 28
    invoke-direct {v3, p0, p1}, Lc31/k;-><init>(Lc31/l;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p1, v3, Lc31/k;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc31/k;->h:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 63
    .line 64
    .line 65
    goto/16 :goto_2

    .line 66
    .line 67
    :cond_3
    iget p0, v3, Lc31/k;->e:I

    .line 68
    .line 69
    iget v5, v3, Lc31/k;->d:I

    .line 70
    .line 71
    :try_start_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Lc31/l;->a:Lay0/a;

    .line 79
    .line 80
    invoke-interface {p1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    check-cast p1, Ljava/lang/String;

    .line 85
    .line 86
    const/4 v5, 0x0

    .line 87
    const-string v10, "vehicle/v2/predictions/{VIN}/status"

    .line 88
    .line 89
    const-string v11, "{VIN}"

    .line 90
    .line 91
    invoke-static {v5, v10, v11, p1}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    iget-object v10, p0, Lc31/l;->b:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {v10, p1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    :try_start_3
    iget-object v10, p0, Lc31/l;->c:Lzv0/c;

    .line 102
    .line 103
    new-instance v11, Lkw0/c;

    .line 104
    .line 105
    invoke-direct {v11}, Lkw0/c;-><init>()V

    .line 106
    .line 107
    .line 108
    invoke-static {v11, p1}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iget-object p0, p0, Lc31/l;->d:Ljava/lang/String;

    .line 112
    .line 113
    const-string p1, "Accept-Language"

    .line 114
    .line 115
    if-eqz p0, :cond_5

    .line 116
    .line 117
    iget-object v12, v11, Lkw0/c;->c:Low0/n;

    .line 118
    .line 119
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-virtual {v12, p1, p0}, Lap0/o;->r(Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    :cond_5
    sget-object p0, Low0/b;->a:Low0/e;

    .line 127
    .line 128
    invoke-static {v11, p0}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 129
    .line 130
    .line 131
    sget-object p0, Low0/s;->b:Low0/s;

    .line 132
    .line 133
    invoke-virtual {v11, p0}, Lkw0/c;->b(Low0/s;)V

    .line 134
    .line 135
    .line 136
    new-instance p0, Lc2/k;

    .line 137
    .line 138
    invoke-direct {p0, v11, v10}, Lc2/k;-><init>(Lkw0/c;Lzv0/c;)V

    .line 139
    .line 140
    .line 141
    iput v5, v3, Lc31/k;->d:I

    .line 142
    .line 143
    iput v5, v3, Lc31/k;->e:I

    .line 144
    .line 145
    iput v8, v3, Lc31/k;->h:I

    .line 146
    .line 147
    invoke-virtual {p0, v3}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    if-ne p1, v4, :cond_6

    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_6
    move p0, v5

    .line 155
    :goto_1
    check-cast p1, Law0/h;

    .line 156
    .line 157
    invoke-virtual {p1}, Law0/h;->c()Low0/v;

    .line 158
    .line 159
    .line 160
    move-result-object v8

    .line 161
    sget-object v10, Low0/v;->f:Low0/v;

    .line 162
    .line 163
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v8

    .line 167
    if-eqz v8, :cond_9

    .line 168
    .line 169
    invoke-virtual {p1}, Law0/h;->M()Law0/c;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 174
    .line 175
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 176
    .line 177
    .line 178
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 179
    :try_start_4
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 180
    .line 181
    .line 182
    move-result-object v9
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 183
    :catchall_0
    :try_start_5
    new-instance v1, Lzw0/a;

    .line 184
    .line 185
    invoke-direct {v1, v0, v9}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 186
    .line 187
    .line 188
    iput v5, v3, Lc31/k;->d:I

    .line 189
    .line 190
    iput p0, v3, Lc31/k;->e:I

    .line 191
    .line 192
    iput v7, v3, Lc31/k;->h:I

    .line 193
    .line 194
    invoke-virtual {p1, v1, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    if-ne p1, v4, :cond_7

    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_7
    :goto_2
    if-eqz p1, :cond_8

    .line 202
    .line 203
    check-cast p1, Le31/i2;

    .line 204
    .line 205
    new-instance p0, Lo41/b;

    .line 206
    .line 207
    invoke-direct {p0, p1}, Lo41/b;-><init>(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    goto/16 :goto_8

    .line 211
    .line 212
    :cond_8
    new-instance p0, Ljava/lang/NullPointerException;

    .line 213
    .line 214
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.PredictionsResponse"

    .line 215
    .line 216
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 220
    :cond_9
    :try_start_6
    invoke-virtual {p1}, Law0/h;->M()Law0/c;

    .line 221
    .line 222
    .line 223
    move-result-object p1

    .line 224
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 225
    .line 226
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 227
    .line 228
    .line 229
    move-result-object v1
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 230
    :try_start_7
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 231
    .line 232
    .line 233
    move-result-object v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 234
    goto :goto_3

    .line 235
    :catchall_1
    move-object v0, v9

    .line 236
    :goto_3
    :try_start_8
    new-instance v7, Lzw0/a;

    .line 237
    .line 238
    invoke-direct {v7, v1, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 239
    .line 240
    .line 241
    iput v5, v3, Lc31/k;->d:I

    .line 242
    .line 243
    iput p0, v3, Lc31/k;->e:I

    .line 244
    .line 245
    iput v6, v3, Lc31/k;->h:I

    .line 246
    .line 247
    invoke-virtual {p1, v7, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    if-ne p1, v4, :cond_a

    .line 252
    .line 253
    :goto_4
    return-object v4

    .line 254
    :cond_a
    :goto_5
    if-eqz p1, :cond_e

    .line 255
    .line 256
    check-cast p1, Le31/n2;

    .line 257
    .line 258
    iget-object p0, p1, Le31/n2;->a:Le31/r1;

    .line 259
    .line 260
    if-eqz p0, :cond_b

    .line 261
    .line 262
    iget-object p1, p0, Le31/r1;->b:Ljava/lang/String;

    .line 263
    .line 264
    goto :goto_6

    .line 265
    :cond_b
    move-object p1, v9

    .line 266
    :goto_6
    if-nez p1, :cond_c

    .line 267
    .line 268
    const-string p1, ""

    .line 269
    .line 270
    :cond_c
    if-eqz p0, :cond_d

    .line 271
    .line 272
    iget-object p0, p0, Le31/r1;->a:Ljava/lang/String;

    .line 273
    .line 274
    if-eqz p0, :cond_d

    .line 275
    .line 276
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v9

    .line 280
    :cond_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 281
    .line 282
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 283
    .line 284
    .line 285
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 286
    .line 287
    .line 288
    invoke-virtual {p0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 289
    .line 290
    .line 291
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    goto :goto_7

    .line 296
    :cond_e
    new-instance p0, Ljava/lang/NullPointerException;

    .line 297
    .line 298
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ResponseError"

    .line 299
    .line 300
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    throw p0
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 304
    :catch_0
    move-exception p0

    .line 305
    :try_start_9
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    if-nez p0, :cond_f

    .line 310
    .line 311
    const-string p0, "UNKNOWN"

    .line 312
    .line 313
    :cond_f
    :goto_7
    new-instance p1, Ljava/lang/Exception;

    .line 314
    .line 315
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    new-instance p0, Lo41/a;

    .line 319
    .line 320
    invoke-direct {p0, p1}, Lo41/a;-><init>(Ljava/lang/Throwable;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 321
    .line 322
    .line 323
    :goto_8
    return-object p0

    .line 324
    :catchall_2
    move-exception p0

    .line 325
    new-instance p1, Lo41/a;

    .line 326
    .line 327
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 328
    .line 329
    .line 330
    return-object p1
.end method
