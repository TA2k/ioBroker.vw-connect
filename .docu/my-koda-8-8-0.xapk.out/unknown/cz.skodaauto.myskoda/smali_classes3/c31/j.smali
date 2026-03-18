.class public final Lc31/j;
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
    iput-object p1, p0, Lc31/j;->a:Lay0/a;

    .line 20
    .line 21
    iput-object p2, p0, Lc31/j;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lc31/j;->c:Lzv0/c;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Le31/u1;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    const-class v0, Le31/n2;

    .line 2
    .line 3
    const-string v1, " - "

    .line 4
    .line 5
    instance-of v2, p2, Lc31/i;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, p2

    .line 10
    check-cast v2, Lc31/i;

    .line 11
    .line 12
    iget v3, v2, Lc31/i;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lc31/i;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lc31/i;

    .line 25
    .line 26
    invoke-direct {v2, p0, p2}, Lc31/i;-><init>(Lc31/j;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p2, v2, Lc31/i;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lc31/i;->h:I

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    const/4 v7, 0x0

    .line 38
    if-eqz v4, :cond_3

    .line 39
    .line 40
    if-eq v4, v6, :cond_2

    .line 41
    .line 42
    if-ne v4, v5, :cond_1

    .line 43
    .line 44
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 45
    .line 46
    .line 47
    goto/16 :goto_7

    .line 48
    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget p0, v2, Lc31/i;->e:I

    .line 58
    .line 59
    iget p1, v2, Lc31/i;->d:I

    .line 60
    .line 61
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 62
    .line 63
    .line 64
    goto/16 :goto_4

    .line 65
    .line 66
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p2, p0, Lc31/j;->a:Lay0/a;

    .line 70
    .line 71
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    new-instance v4, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 78
    .line 79
    .line 80
    iget-object v8, p0, Lc31/j;->b:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {v4, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v8, "vehicle/v1/lead/"

    .line 86
    .line 87
    invoke-virtual {v4, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    :try_start_2
    iget-object p0, p0, Lc31/j;->c:Lzv0/c;

    .line 98
    .line 99
    new-instance v4, Lkw0/c;

    .line 100
    .line 101
    invoke-direct {v4}, Lkw0/c;-><init>()V

    .line 102
    .line 103
    .line 104
    sget-object v8, Low0/s;->c:Low0/s;

    .line 105
    .line 106
    invoke-virtual {v4, v8}, Lkw0/c;->b(Low0/s;)V

    .line 107
    .line 108
    .line 109
    invoke-static {v4, p2}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    sget-object p2, Low0/b;->a:Low0/e;

    .line 113
    .line 114
    invoke-static {v4, p2}, Ljp/pc;->d(Lkw0/c;Low0/e;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 115
    .line 116
    .line 117
    const-class p2, Le31/u1;

    .line 118
    .line 119
    if-nez p1, :cond_4

    .line 120
    .line 121
    :try_start_3
    sget-object p1, Lrw0/b;->a:Lrw0/b;

    .line 122
    .line 123
    iput-object p1, v4, Lkw0/c;->d:Ljava/lang/Object;

    .line 124
    .line 125
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 126
    .line 127
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 128
    .line 129
    .line 130
    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 131
    :try_start_4
    invoke-static {p2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 132
    .line 133
    .line 134
    move-result-object p2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 135
    goto :goto_1

    .line 136
    :catchall_0
    move-object p2, v7

    .line 137
    :goto_1
    :try_start_5
    new-instance v8, Lzw0/a;

    .line 138
    .line 139
    invoke-direct {v8, p1, p2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v4, v8}, Lkw0/c;->a(Lzw0/a;)V

    .line 143
    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_4
    iput-object p1, v4, Lkw0/c;->d:Ljava/lang/Object;

    .line 147
    .line 148
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 149
    .line 150
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 151
    .line 152
    .line 153
    move-result-object p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 154
    :try_start_6
    invoke-static {p2}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 155
    .line 156
    .line 157
    move-result-object p2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 158
    goto :goto_2

    .line 159
    :catchall_1
    move-object p2, v7

    .line 160
    :goto_2
    :try_start_7
    new-instance v8, Lzw0/a;

    .line 161
    .line 162
    invoke-direct {v8, p1, p2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v4, v8}, Lkw0/c;->a(Lzw0/a;)V

    .line 166
    .line 167
    .line 168
    :goto_3
    sget-object p1, Low0/s;->c:Low0/s;

    .line 169
    .line 170
    invoke-virtual {v4, p1}, Lkw0/c;->b(Low0/s;)V

    .line 171
    .line 172
    .line 173
    new-instance p1, Lc2/k;

    .line 174
    .line 175
    invoke-direct {p1, v4, p0}, Lc2/k;-><init>(Lkw0/c;Lzv0/c;)V

    .line 176
    .line 177
    .line 178
    const/4 p0, 0x0

    .line 179
    iput p0, v2, Lc31/i;->d:I

    .line 180
    .line 181
    iput p0, v2, Lc31/i;->e:I

    .line 182
    .line 183
    iput v6, v2, Lc31/i;->h:I

    .line 184
    .line 185
    invoke-virtual {p1, v2}, Lc2/k;->s(Lrx0/c;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p2

    .line 189
    if-ne p2, v3, :cond_5

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_5
    move p1, p0

    .line 193
    :goto_4
    check-cast p2, Law0/h;

    .line 194
    .line 195
    invoke-virtual {p2}, Law0/h;->c()Low0/v;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    sget-object v6, Low0/v;->g:Low0/v;

    .line 200
    .line 201
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    if-eqz v4, :cond_6

    .line 206
    .line 207
    new-instance p0, Lo41/b;

    .line 208
    .line 209
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    invoke-direct {p0, p1}, Lo41/b;-><init>(Ljava/lang/Object;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 212
    .line 213
    .line 214
    goto :goto_a

    .line 215
    :cond_6
    :try_start_8
    invoke-virtual {p2}, Law0/h;->M()Law0/c;

    .line 216
    .line 217
    .line 218
    move-result-object p2

    .line 219
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 220
    .line 221
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 222
    .line 223
    .line 224
    move-result-object v4
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 225
    :try_start_9
    invoke-static {v0}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 226
    .line 227
    .line 228
    move-result-object v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 229
    goto :goto_5

    .line 230
    :catchall_2
    move-object v0, v7

    .line 231
    :goto_5
    :try_start_a
    new-instance v6, Lzw0/a;

    .line 232
    .line 233
    invoke-direct {v6, v4, v0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 234
    .line 235
    .line 236
    iput p1, v2, Lc31/i;->d:I

    .line 237
    .line 238
    iput p0, v2, Lc31/i;->e:I

    .line 239
    .line 240
    iput v5, v2, Lc31/i;->h:I

    .line 241
    .line 242
    invoke-virtual {p2, v6, v2}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object p2

    .line 246
    if-ne p2, v3, :cond_7

    .line 247
    .line 248
    :goto_6
    return-object v3

    .line 249
    :cond_7
    :goto_7
    if-eqz p2, :cond_b

    .line 250
    .line 251
    check-cast p2, Le31/n2;

    .line 252
    .line 253
    iget-object p0, p2, Le31/n2;->a:Le31/r1;

    .line 254
    .line 255
    if-eqz p0, :cond_8

    .line 256
    .line 257
    iget-object p1, p0, Le31/r1;->b:Ljava/lang/String;

    .line 258
    .line 259
    goto :goto_8

    .line 260
    :cond_8
    move-object p1, v7

    .line 261
    :goto_8
    if-nez p1, :cond_9

    .line 262
    .line 263
    const-string p1, ""

    .line 264
    .line 265
    :cond_9
    if-eqz p0, :cond_a

    .line 266
    .line 267
    iget-object p0, p0, Le31/r1;->a:Ljava/lang/String;

    .line 268
    .line 269
    if-eqz p0, :cond_a

    .line 270
    .line 271
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v7

    .line 275
    :cond_a
    new-instance p0, Ljava/lang/StringBuilder;

    .line 276
    .line 277
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 278
    .line 279
    .line 280
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {p0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    goto :goto_9

    .line 291
    :cond_b
    new-instance p0, Ljava/lang/NullPointerException;

    .line 292
    .line 293
    const-string p1, "null cannot be cast to non-null type technology.cariad.appointmentbooking.base.data.models.ResponseError"

    .line 294
    .line 295
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    throw p0
    :try_end_a
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_0
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 299
    :catch_0
    move-exception p0

    .line 300
    :try_start_b
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    if-nez p0, :cond_c

    .line 305
    .line 306
    const-string p0, "UNKNOWN"

    .line 307
    .line 308
    :cond_c
    :goto_9
    new-instance p1, Ljava/lang/Exception;

    .line 309
    .line 310
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    new-instance p0, Lo41/a;

    .line 314
    .line 315
    invoke-direct {p0, p1}, Lo41/a;-><init>(Ljava/lang/Throwable;)V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_3

    .line 316
    .line 317
    .line 318
    :goto_a
    return-object p0

    .line 319
    :catchall_3
    move-exception p0

    .line 320
    new-instance p1, Lo41/a;

    .line 321
    .line 322
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 323
    .line 324
    .line 325
    return-object p1
.end method
