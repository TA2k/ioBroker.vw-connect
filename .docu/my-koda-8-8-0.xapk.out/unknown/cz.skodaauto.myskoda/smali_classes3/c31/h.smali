.class public final Lc31/h;
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
    iput-object p1, p0, Lc31/h;->a:Lay0/a;

    .line 20
    .line 21
    iput-object p2, p0, Lc31/h;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lc31/h;->c:Lzv0/c;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    const-class v0, Le31/n2;

    .line 2
    .line 3
    const-class v1, Le31/m3;

    .line 4
    .line 5
    const-string v2, " - "

    .line 6
    .line 7
    instance-of v3, p1, Lc31/g;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, p1

    .line 12
    check-cast v3, Lc31/g;

    .line 13
    .line 14
    iget v4, v3, Lc31/g;->h:I

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
    iput v4, v3, Lc31/g;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lc31/g;

    .line 27
    .line 28
    invoke-direct {v3, p0, p1}, Lc31/g;-><init>(Lc31/h;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object p1, v3, Lc31/g;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lc31/g;->h:I

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
    iget p0, v3, Lc31/g;->e:I

    .line 68
    .line 69
    iget v5, v3, Lc31/g;->d:I

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
    iget-object p1, p0, Lc31/h;->b:Ljava/lang/String;

    .line 79
    .line 80
    const-string v5, "dealer/v1/dealers/favorite"

    .line 81
    .line 82
    invoke-static {p1, v5}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    :try_start_3
    iget-object v5, p0, Lc31/h;->c:Lzv0/c;

    .line 87
    .line 88
    new-instance v10, Lkw0/c;

    .line 89
    .line 90
    invoke-direct {v10}, Lkw0/c;-><init>()V

    .line 91
    .line 92
    .line 93
    invoke-static {v10, p1}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const-string p1, "vin"

    .line 97
    .line 98
    iget-object p0, p0, Lc31/h;->a:Lay0/a;

    .line 99
    .line 100
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-static {v10, p1, p0}, Llp/je;->c(Lkw0/c;Ljava/lang/String;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    sget-object p0, Low0/b;->a:Low0/e;

    .line 108
    .line 109
    invoke-static {v10, p0}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 110
    .line 111
    .line 112
    sget-object p0, Low0/s;->b:Low0/s;

    .line 113
    .line 114
    invoke-virtual {v10, p0}, Lkw0/c;->b(Low0/s;)V

    .line 115
    .line 116
    .line 117
    new-instance p0, Lc2/k;

    .line 118
    .line 119
    invoke-direct {p0, v10, v5}, Lc2/k;-><init>(Lkw0/c;Lzv0/c;)V

    .line 120
    .line 121
    .line 122
    const/4 p1, 0x0

    .line 123
    iput p1, v3, Lc31/g;->d:I

    .line 124
    .line 125
    iput p1, v3, Lc31/g;->e:I

    .line 126
    .line 127
    iput v8, v3, Lc31/g;->h:I

    .line 128
    .line 129
    invoke-virtual {p0, v3}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-ne p0, v4, :cond_5

    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_5
    move v5, p1

    .line 137
    move-object p1, p0

    .line 138
    move p0, v5

    .line 139
    :goto_1
    check-cast p1, Law0/h;

    .line 140
    .line 141
    invoke-virtual {p1}, Law0/h;->c()Low0/v;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    sget-object v10, Low0/v;->f:Low0/v;

    .line 146
    .line 147
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v8

    .line 151
    if-eqz v8, :cond_8

    .line 152
    .line 153
    invoke-virtual {p1}, Law0/h;->M()Law0/c;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 158
    .line 159
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 160
    .line 161
    .line 162
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 163
    :try_start_4
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 164
    .line 165
    .line 166
    move-result-object v9
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 167
    :catchall_0
    :try_start_5
    new-instance v1, Lzw0/a;

    .line 168
    .line 169
    invoke-direct {v1, v0, v9}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 170
    .line 171
    .line 172
    iput v5, v3, Lc31/g;->d:I

    .line 173
    .line 174
    iput p0, v3, Lc31/g;->e:I

    .line 175
    .line 176
    iput v7, v3, Lc31/g;->h:I

    .line 177
    .line 178
    invoke-virtual {p1, v1, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    if-ne p1, v4, :cond_6

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_6
    :goto_2
    if-eqz p1, :cond_7

    .line 186
    .line 187
    check-cast p1, Le31/m3;

    .line 188
    .line 189
    new-instance p0, Lo41/b;

    .line 190
    .line 191
    invoke-direct {p0, p1}, Lo41/b;-><init>(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    goto/16 :goto_8

    .line 195
    .line 196
    :cond_7
    new-instance p0, Ljava/lang/NullPointerException;

    .line 197
    .line 198
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ServicePartnerResponse"

    .line 199
    .line 200
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 204
    :cond_8
    :try_start_6
    invoke-virtual {p1}, Law0/h;->M()Law0/c;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 209
    .line 210
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 211
    .line 212
    .line 213
    move-result-object v1
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 214
    :try_start_7
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 215
    .line 216
    .line 217
    move-result-object v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 218
    goto :goto_3

    .line 219
    :catchall_1
    move-object v0, v9

    .line 220
    :goto_3
    :try_start_8
    new-instance v7, Lzw0/a;

    .line 221
    .line 222
    invoke-direct {v7, v1, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 223
    .line 224
    .line 225
    iput v5, v3, Lc31/g;->d:I

    .line 226
    .line 227
    iput p0, v3, Lc31/g;->e:I

    .line 228
    .line 229
    iput v6, v3, Lc31/g;->h:I

    .line 230
    .line 231
    invoke-virtual {p1, v7, v3}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    if-ne p1, v4, :cond_9

    .line 236
    .line 237
    :goto_4
    return-object v4

    .line 238
    :cond_9
    :goto_5
    if-eqz p1, :cond_d

    .line 239
    .line 240
    check-cast p1, Le31/n2;

    .line 241
    .line 242
    iget-object p0, p1, Le31/n2;->a:Le31/r1;

    .line 243
    .line 244
    if-eqz p0, :cond_a

    .line 245
    .line 246
    iget-object p1, p0, Le31/r1;->b:Ljava/lang/String;

    .line 247
    .line 248
    goto :goto_6

    .line 249
    :cond_a
    move-object p1, v9

    .line 250
    :goto_6
    if-nez p1, :cond_b

    .line 251
    .line 252
    const-string p1, ""

    .line 253
    .line 254
    :cond_b
    if-eqz p0, :cond_c

    .line 255
    .line 256
    iget-object p0, p0, Le31/r1;->a:Ljava/lang/String;

    .line 257
    .line 258
    if-eqz p0, :cond_c

    .line 259
    .line 260
    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v9

    .line 264
    :cond_c
    new-instance p0, Ljava/lang/StringBuilder;

    .line 265
    .line 266
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    invoke-virtual {p0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    goto :goto_7

    .line 280
    :cond_d
    new-instance p0, Ljava/lang/NullPointerException;

    .line 281
    .line 282
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ResponseError"

    .line 283
    .line 284
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    throw p0
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 288
    :catch_0
    move-exception p0

    .line 289
    :try_start_9
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    if-nez p0, :cond_e

    .line 294
    .line 295
    const-string p0, "UNKNOWN"

    .line 296
    .line 297
    :cond_e
    :goto_7
    new-instance p1, Ljava/lang/Exception;

    .line 298
    .line 299
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    new-instance p0, Lo41/a;

    .line 303
    .line 304
    invoke-direct {p0, p1}, Lo41/a;-><init>(Ljava/lang/Throwable;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 305
    .line 306
    .line 307
    :goto_8
    return-object p0

    .line 308
    :catchall_2
    move-exception p0

    .line 309
    new-instance p1, Lo41/a;

    .line 310
    .line 311
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 312
    .line 313
    .line 314
    return-object p1
.end method
