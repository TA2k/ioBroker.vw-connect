.class public final Lfl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfl/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static d(Ld01/t0;I)I
    .locals 1

    .line 1
    const-string v0, "Retry-After"

    .line 2
    .line 3
    invoke-static {p0, v0}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    return p1

    .line 10
    :cond_0
    const-string p1, "\\d+"

    .line 11
    .line 12
    invoke-static {p1}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const-string v0, "compile(...)"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->matches()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(Ljava/lang/String;)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const-string p1, "valueOf(...)"

    .line 36
    .line 37
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0

    .line 45
    :cond_1
    const p0, 0x7fffffff

    .line 46
    .line 47
    .line 48
    return p0
.end method


# virtual methods
.method public a(Ld01/t0;Lh01/g;)Ld01/k0;
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p2, :cond_0

    .line 3
    .line 4
    invoke-virtual {p2}, Lh01/g;->c()Lh01/p;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    iget-object v1, v1, Lh01/p;->c:Ld01/w0;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v1, v0

    .line 12
    :goto_0
    iget v2, p1, Ld01/t0;->g:I

    .line 13
    .line 14
    iget-object v3, p1, Ld01/t0;->d:Ld01/k0;

    .line 15
    .line 16
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    const/16 v7, 0x134

    .line 21
    .line 22
    const/16 v8, 0x133

    .line 23
    .line 24
    if-eq v2, v8, :cond_e

    .line 25
    .line 26
    if-eq v2, v7, :cond_e

    .line 27
    .line 28
    const/16 v9, 0x191

    .line 29
    .line 30
    if-eq v2, v9, :cond_d

    .line 31
    .line 32
    const/16 v9, 0x1a5

    .line 33
    .line 34
    if-eq v2, v9, :cond_a

    .line 35
    .line 36
    const/16 p2, 0x1f7

    .line 37
    .line 38
    if-eq v2, p2, :cond_8

    .line 39
    .line 40
    const/16 p2, 0x197

    .line 41
    .line 42
    if-eq v2, p2, :cond_6

    .line 43
    .line 44
    const/16 p2, 0x198

    .line 45
    .line 46
    if-eq v2, p2, :cond_1

    .line 47
    .line 48
    packed-switch v2, :pswitch_data_0

    .line 49
    .line 50
    .line 51
    goto/16 :goto_2

    .line 52
    .line 53
    :cond_1
    iget-object p0, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Ld01/h0;

    .line 56
    .line 57
    iget-boolean p0, p0, Ld01/h0;->e:Z

    .line 58
    .line 59
    if-nez p0, :cond_2

    .line 60
    .line 61
    goto/16 :goto_2

    .line 62
    .line 63
    :cond_2
    iget-object p0, v3, Ld01/k0;->d:Ld01/r0;

    .line 64
    .line 65
    if-eqz p0, :cond_3

    .line 66
    .line 67
    invoke-virtual {p0}, Ld01/r0;->isOneShot()Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    goto/16 :goto_2

    .line 74
    .line 75
    :cond_3
    iget-object p0, p1, Ld01/t0;->n:Ld01/t0;

    .line 76
    .line 77
    if-eqz p0, :cond_4

    .line 78
    .line 79
    iget p0, p0, Ld01/t0;->g:I

    .line 80
    .line 81
    if-ne p0, p2, :cond_4

    .line 82
    .line 83
    goto/16 :goto_2

    .line 84
    .line 85
    :cond_4
    invoke-static {p1, v5}, Lfl/b;->d(Ld01/t0;I)I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    if-lez p0, :cond_5

    .line 90
    .line 91
    goto/16 :goto_2

    .line 92
    .line 93
    :cond_5
    iget-object p0, p1, Ld01/t0;->d:Ld01/k0;

    .line 94
    .line 95
    return-object p0

    .line 96
    :cond_6
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object p1, v1, Ld01/w0;->b:Ljava/net/Proxy;

    .line 100
    .line 101
    invoke-virtual {p1}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    sget-object p2, Ljava/net/Proxy$Type;->HTTP:Ljava/net/Proxy$Type;

    .line 106
    .line 107
    if-ne p1, p2, :cond_7

    .line 108
    .line 109
    iget-object p0, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p0, Ld01/h0;

    .line 112
    .line 113
    iget-object p0, p0, Ld01/h0;->n:Ld01/b;

    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    return-object v0

    .line 119
    :cond_7
    new-instance p0, Ljava/net/ProtocolException;

    .line 120
    .line 121
    const-string p1, "Received HTTP_PROXY_AUTH (407) code while not using proxy"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_8
    iget-object p0, p1, Ld01/t0;->n:Ld01/t0;

    .line 128
    .line 129
    if-eqz p0, :cond_9

    .line 130
    .line 131
    iget p0, p0, Ld01/t0;->g:I

    .line 132
    .line 133
    if-ne p0, p2, :cond_9

    .line 134
    .line 135
    goto/16 :goto_2

    .line 136
    .line 137
    :cond_9
    const p0, 0x7fffffff

    .line 138
    .line 139
    .line 140
    invoke-static {p1, p0}, Lfl/b;->d(Ld01/t0;I)I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-nez p0, :cond_13

    .line 145
    .line 146
    iget-object p0, p1, Ld01/t0;->d:Ld01/k0;

    .line 147
    .line 148
    return-object p0

    .line 149
    :cond_a
    iget-object p0, v3, Ld01/k0;->d:Ld01/r0;

    .line 150
    .line 151
    if-eqz p0, :cond_b

    .line 152
    .line 153
    invoke-virtual {p0}, Ld01/r0;->isOneShot()Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    if-eqz p0, :cond_b

    .line 158
    .line 159
    goto/16 :goto_2

    .line 160
    .line 161
    :cond_b
    if-eqz p2, :cond_13

    .line 162
    .line 163
    iget-object p0, p2, Lh01/g;->b:Lh01/h;

    .line 164
    .line 165
    invoke-interface {p0}, Lh01/h;->e()Lh01/r;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    iget-object p0, p0, Lh01/r;->i:Ld01/a;

    .line 170
    .line 171
    iget-object p0, p0, Ld01/a;->h:Ld01/a0;

    .line 172
    .line 173
    iget-object p0, p0, Ld01/a0;->d:Ljava/lang/String;

    .line 174
    .line 175
    iget-object v1, p2, Lh01/g;->c:Li01/d;

    .line 176
    .line 177
    invoke-interface {v1}, Li01/d;->i()Li01/c;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    invoke-interface {v1}, Li01/c;->e()Ld01/w0;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    iget-object v1, v1, Ld01/w0;->a:Ld01/a;

    .line 186
    .line 187
    iget-object v1, v1, Ld01/a;->h:Ld01/a0;

    .line 188
    .line 189
    iget-object v1, v1, Ld01/a0;->d:Ljava/lang/String;

    .line 190
    .line 191
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    if-eqz p0, :cond_c

    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_c
    invoke-virtual {p2}, Lh01/g;->c()Lh01/p;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    monitor-enter p0

    .line 203
    :try_start_0
    iput-boolean v6, p0, Lh01/p;->k:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 204
    .line 205
    monitor-exit p0

    .line 206
    iget-object p0, p1, Ld01/t0;->d:Ld01/k0;

    .line 207
    .line 208
    return-object p0

    .line 209
    :catchall_0
    move-exception p1

    .line 210
    monitor-exit p0

    .line 211
    throw p1

    .line 212
    :cond_d
    iget-object p0, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast p0, Ld01/h0;

    .line 215
    .line 216
    iget-object p0, p0, Ld01/h0;->g:Ld01/c;

    .line 217
    .line 218
    invoke-interface {p0, v1, p1}, Ld01/c;->a(Ld01/w0;Ld01/t0;)Ld01/k0;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0

    .line 223
    :cond_e
    :pswitch_0
    const-string p2, "PROPFIND"

    .line 224
    .line 225
    iget-object p0, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast p0, Ld01/h0;

    .line 228
    .line 229
    iget-boolean v1, p0, Ld01/h0;->h:Z

    .line 230
    .line 231
    if-nez v1, :cond_f

    .line 232
    .line 233
    goto :goto_2

    .line 234
    :cond_f
    const-string v1, "Location"

    .line 235
    .line 236
    invoke-static {p1, v1}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v1

    .line 240
    iget-object v2, p1, Ld01/t0;->d:Ld01/k0;

    .line 241
    .line 242
    if-nez v1, :cond_10

    .line 243
    .line 244
    goto :goto_2

    .line 245
    :cond_10
    iget-object v3, v2, Ld01/k0;->a:Ld01/a0;

    .line 246
    .line 247
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 248
    .line 249
    .line 250
    invoke-virtual {v3, v1}, Ld01/a0;->h(Ljava/lang/String;)Ld01/z;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    if-eqz v1, :cond_11

    .line 255
    .line 256
    invoke-virtual {v1}, Ld01/z;->c()Ld01/a0;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    goto :goto_1

    .line 261
    :cond_11
    move-object v1, v0

    .line 262
    :goto_1
    if-nez v1, :cond_12

    .line 263
    .line 264
    goto :goto_2

    .line 265
    :cond_12
    iget-object v3, v1, Ld01/a0;->a:Ljava/lang/String;

    .line 266
    .line 267
    iget-object v9, v2, Ld01/k0;->a:Ld01/a0;

    .line 268
    .line 269
    iget-object v9, v9, Ld01/a0;->a:Ljava/lang/String;

    .line 270
    .line 271
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v3

    .line 275
    if-nez v3, :cond_14

    .line 276
    .line 277
    iget-boolean p0, p0, Ld01/h0;->i:Z

    .line 278
    .line 279
    if-nez p0, :cond_14

    .line 280
    .line 281
    :cond_13
    :goto_2
    return-object v0

    .line 282
    :cond_14
    invoke-virtual {v2}, Ld01/k0;->b()Ld01/j0;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    invoke-static {v4}, Llp/l1;->c(Ljava/lang/String;)Z

    .line 287
    .line 288
    .line 289
    move-result v3

    .line 290
    if-eqz v3, :cond_19

    .line 291
    .line 292
    iget p1, p1, Ld01/t0;->g:I

    .line 293
    .line 294
    invoke-virtual {v4, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result v3

    .line 298
    if-nez v3, :cond_15

    .line 299
    .line 300
    if-eq p1, v7, :cond_15

    .line 301
    .line 302
    if-ne p1, v8, :cond_16

    .line 303
    .line 304
    :cond_15
    move v5, v6

    .line 305
    :cond_16
    invoke-virtual {v4, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result p2

    .line 309
    if-nez p2, :cond_17

    .line 310
    .line 311
    if-eq p1, v7, :cond_17

    .line 312
    .line 313
    if-eq p1, v8, :cond_17

    .line 314
    .line 315
    const-string p1, "GET"

    .line 316
    .line 317
    invoke-virtual {p0, p1, v0}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 318
    .line 319
    .line 320
    goto :goto_3

    .line 321
    :cond_17
    if-eqz v5, :cond_18

    .line 322
    .line 323
    iget-object v0, v2, Ld01/k0;->d:Ld01/r0;

    .line 324
    .line 325
    :cond_18
    invoke-virtual {p0, v4, v0}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 326
    .line 327
    .line 328
    :goto_3
    if-nez v5, :cond_19

    .line 329
    .line 330
    const-string p1, "Transfer-Encoding"

    .line 331
    .line 332
    iget-object p2, p0, Ld01/j0;->c:Ld01/x;

    .line 333
    .line 334
    invoke-virtual {p2, p1}, Ld01/x;->o(Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    const-string p1, "Content-Length"

    .line 338
    .line 339
    iget-object p2, p0, Ld01/j0;->c:Ld01/x;

    .line 340
    .line 341
    invoke-virtual {p2, p1}, Ld01/x;->o(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    const-string p1, "Content-Type"

    .line 345
    .line 346
    iget-object p2, p0, Ld01/j0;->c:Ld01/x;

    .line 347
    .line 348
    invoke-virtual {p2, p1}, Ld01/x;->o(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    :cond_19
    iget-object p1, v2, Ld01/k0;->a:Ld01/a0;

    .line 352
    .line 353
    invoke-static {p1, v1}, Le01/g;->a(Ld01/a0;Ld01/a0;)Z

    .line 354
    .line 355
    .line 356
    move-result p1

    .line 357
    if-nez p1, :cond_1a

    .line 358
    .line 359
    const-string p1, "Authorization"

    .line 360
    .line 361
    iget-object p2, p0, Ld01/j0;->c:Ld01/x;

    .line 362
    .line 363
    invoke-virtual {p2, p1}, Ld01/x;->o(Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    :cond_1a
    iput-object v1, p0, Ld01/j0;->a:Ld01/a0;

    .line 367
    .line 368
    new-instance p1, Ld01/k0;

    .line 369
    .line 370
    invoke-direct {p1, p0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 371
    .line 372
    .line 373
    return-object p1

    .line 374
    nop

    .line 375
    :pswitch_data_0
    .packed-switch 0x12c
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public b(Ljava/io/IOException;Lh01/o;Ld01/k0;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lk01/a;

    .line 2
    .line 3
    iget-object p0, p0, Lfl/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ld01/h0;

    .line 6
    .line 7
    iget-boolean p0, p0, Ld01/h0;->e:Z

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    goto :goto_2

    .line 12
    :cond_0
    if-nez v0, :cond_2

    .line 13
    .line 14
    iget-object p0, p3, Ld01/k0;->d:Ld01/r0;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Ld01/r0;->isOneShot()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_8

    .line 23
    .line 24
    :cond_1
    instance-of p0, p1, Ljava/io/FileNotFoundException;

    .line 25
    .line 26
    if-eqz p0, :cond_2

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_2
    instance-of p0, p1, Ljava/net/ProtocolException;

    .line 30
    .line 31
    if-eqz p0, :cond_3

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_3
    instance-of p0, p1, Ljava/io/InterruptedIOException;

    .line 35
    .line 36
    if-eqz p0, :cond_4

    .line 37
    .line 38
    instance-of p0, p1, Ljava/net/SocketTimeoutException;

    .line 39
    .line 40
    if-eqz p0, :cond_8

    .line 41
    .line 42
    if-eqz v0, :cond_8

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_4
    instance-of p0, p1, Ljavax/net/ssl/SSLHandshakeException;

    .line 46
    .line 47
    if-eqz p0, :cond_5

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    instance-of p0, p0, Ljava/security/cert/CertificateException;

    .line 54
    .line 55
    if-eqz p0, :cond_5

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_5
    instance-of p0, p1, Ljavax/net/ssl/SSLPeerUnverifiedException;

    .line 59
    .line 60
    if-eqz p0, :cond_6

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_6
    :goto_0
    iget-object p0, p2, Lh01/o;->u:Lh01/g;

    .line 64
    .line 65
    if-eqz p0, :cond_8

    .line 66
    .line 67
    iget-boolean p0, p0, Lh01/g;->e:Z

    .line 68
    .line 69
    const/4 p1, 0x1

    .line 70
    if-ne p0, p1, :cond_8

    .line 71
    .line 72
    iget-object p0, p2, Lh01/o;->k:Lh01/h;

    .line 73
    .line 74
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-interface {p0}, Lh01/h;->e()Lh01/r;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    iget-object p2, p2, Lh01/o;->u:Lh01/g;

    .line 82
    .line 83
    if-eqz p2, :cond_7

    .line 84
    .line 85
    invoke-virtual {p2}, Lh01/g;->c()Lh01/p;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    goto :goto_1

    .line 90
    :cond_7
    const/4 p2, 0x0

    .line 91
    :goto_1
    invoke-virtual {p0, p2}, Lh01/r;->a(Lh01/p;)Z

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    if-eqz p0, :cond_8

    .line 96
    .line 97
    return p1

    .line 98
    :cond_8
    :goto_2
    const/4 p0, 0x0

    .line 99
    return p0
.end method

.method public c(ZLi01/f;)Ld01/t0;
    .locals 18

    .line 1
    move-object/from16 v1, p2

    .line 2
    .line 3
    iget-object v2, v1, Li01/f;->e:Ld01/k0;

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    move-object/from16 v0, p0

    .line 7
    .line 8
    :try_start_0
    iget-object v0, v0, Lfl/b;->b:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lt10/k;

    .line 11
    .line 12
    invoke-static/range {p1 .. p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    invoke-virtual {v0, v4}, Lt10/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :catchall_0
    move-exception v0

    .line 24
    sget-object v4, Lgi/b;->h:Lgi/b;

    .line 25
    .line 26
    sget-object v5, Lgi/a;->d:Lgi/a;

    .line 27
    .line 28
    new-instance v6, Lf31/n;

    .line 29
    .line 30
    const/16 v7, 0xb

    .line 31
    .line 32
    invoke-direct {v6, v7}, Lf31/n;-><init>(I)V

    .line 33
    .line 34
    .line 35
    const-class v7, Lfl/b;

    .line 36
    .line 37
    invoke-virtual {v7}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v7

    .line 41
    const/16 v8, 0x24

    .line 42
    .line 43
    invoke-static {v7, v8}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v8

    .line 47
    const/16 v9, 0x2e

    .line 48
    .line 49
    invoke-static {v9, v8, v8}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v8

    .line 53
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v9

    .line 57
    if-nez v9, :cond_0

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    const-string v7, "Kt"

    .line 61
    .line 62
    invoke-static {v8, v7}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v7

    .line 66
    :goto_0
    invoke-static {v7, v5, v4, v0, v6}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 67
    .line 68
    .line 69
    move-object v0, v3

    .line 70
    :goto_1
    if-nez v0, :cond_3

    .line 71
    .line 72
    sget-object v0, Ld01/v0;->d:Ld01/u0;

    .line 73
    .line 74
    new-instance v0, Ljava/util/ArrayList;

    .line 75
    .line 76
    const/16 v1, 0x14

    .line 77
    .line 78
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 79
    .line 80
    .line 81
    const-string v1, "request"

    .line 82
    .line 83
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    move-object v1, v2

    .line 87
    sget-object v2, Ld01/i0;->i:Ld01/i0;

    .line 88
    .line 89
    invoke-static {v3}, Ljp/lg;->a(Ld01/d0;)Llx0/l;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    iget-object v4, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v4, Ljava/nio/charset/Charset;

    .line 96
    .line 97
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v3, Ld01/d0;

    .line 100
    .line 101
    new-instance v5, Lu01/f;

    .line 102
    .line 103
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 104
    .line 105
    .line 106
    const-string v6, "charset"

    .line 107
    .line 108
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    const-string v7, "string"

    .line 112
    .line 113
    const-string v8, "No tokens"

    .line 114
    .line 115
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    const/16 v7, 0x9

    .line 126
    .line 127
    if-gt v7, v6, :cond_2

    .line 128
    .line 129
    sget-object v6, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 130
    .line 131
    invoke-virtual {v4, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    const/4 v9, 0x0

    .line 136
    if-eqz v6, :cond_1

    .line 137
    .line 138
    invoke-virtual {v5, v9, v7, v8}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_1
    invoke-virtual {v8, v9, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    const-string v7, "substring(...)"

    .line 147
    .line 148
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v6, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    const-string v6, "getBytes(...)"

    .line 156
    .line 157
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    array-length v6, v4

    .line 161
    invoke-virtual {v5, v4, v9, v6}, Lu01/f;->write([BII)V

    .line 162
    .line 163
    .line 164
    :goto_2
    iget-wide v6, v5, Lu01/f;->e:J

    .line 165
    .line 166
    new-instance v4, Ld01/u0;

    .line 167
    .line 168
    invoke-direct {v4, v3, v6, v7, v5}, Ld01/u0;-><init>(Ld01/d0;JLu01/f;)V

    .line 169
    .line 170
    .line 171
    new-instance v6, Ld01/y;

    .line 172
    .line 173
    new-array v3, v9, [Ljava/lang/String;

    .line 174
    .line 175
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    check-cast v0, [Ljava/lang/String;

    .line 180
    .line 181
    invoke-direct {v6, v0}, Ld01/y;-><init>([Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    new-instance v0, Ld01/t0;

    .line 185
    .line 186
    const-string v3, "Failed to get HTTP token from host app"

    .line 187
    .line 188
    move-object v7, v4

    .line 189
    const/16 v4, 0x190

    .line 190
    .line 191
    const/4 v5, 0x0

    .line 192
    const/4 v8, 0x0

    .line 193
    const/4 v9, 0x0

    .line 194
    const/4 v10, 0x0

    .line 195
    const/4 v11, 0x0

    .line 196
    const-wide/16 v12, 0x0

    .line 197
    .line 198
    const-wide/16 v14, 0x0

    .line 199
    .line 200
    const/16 v16, 0x0

    .line 201
    .line 202
    sget-object v17, Ld01/y0;->v0:Ld01/r;

    .line 203
    .line 204
    invoke-direct/range {v0 .. v17}, Ld01/t0;-><init>(Ld01/k0;Ld01/i0;Ljava/lang/String;ILd01/w;Ld01/y;Ld01/v0;Lu01/g0;Ld01/t0;Ld01/t0;Ld01/t0;JJLh01/g;Ld01/y0;)V

    .line 205
    .line 206
    .line 207
    return-object v0

    .line 208
    :cond_2
    const-string v0, "endIndex > string.length: "

    .line 209
    .line 210
    const-string v1, " > "

    .line 211
    .line 212
    invoke-static {v0, v7, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 217
    .line 218
    .line 219
    move-result v1

    .line 220
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 228
    .line 229
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    throw v1

    .line 237
    :cond_3
    invoke-virtual {v2}, Ld01/k0;->b()Ld01/j0;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    const-string v3, "Bearer "

    .line 242
    .line 243
    invoke-virtual {v3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    const-string v3, "Authorization"

    .line 248
    .line 249
    invoke-virtual {v2, v3, v0}, Ld01/j0;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    new-instance v0, Ld01/k0;

    .line 253
    .line 254
    invoke-direct {v0, v2}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v1, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    return-object v0
.end method

.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 33

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lfl/b;->a:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v5, p1

    .line 9
    .line 10
    check-cast v5, Li01/f;

    .line 11
    .line 12
    iget-object v0, v5, Li01/f;->e:Ld01/k0;

    .line 13
    .line 14
    iget-object v6, v5, Li01/f;->a:Lh01/o;

    .line 15
    .line 16
    sget-object v7, Lmx0/s;->d:Lmx0/s;

    .line 17
    .line 18
    move-object v8, v7

    .line 19
    const/16 v19, 0x0

    .line 20
    .line 21
    const/16 v20, 0x0

    .line 22
    .line 23
    move-object v7, v0

    .line 24
    :goto_0
    const/4 v0, 0x1

    .line 25
    :goto_1
    const-string v9, "request"

    .line 26
    .line 27
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v9, v6, Lh01/o;->n:Lh01/g;

    .line 31
    .line 32
    if-nez v9, :cond_f

    .line 33
    .line 34
    monitor-enter v6

    .line 35
    :try_start_0
    iget-boolean v9, v6, Lh01/o;->p:Z

    .line 36
    .line 37
    if-nez v9, :cond_e

    .line 38
    .line 39
    iget-boolean v9, v6, Lh01/o;->o:Z

    .line 40
    .line 41
    if-nez v9, :cond_d

    .line 42
    .line 43
    iget-boolean v9, v6, Lh01/o;->r:Z

    .line 44
    .line 45
    if-nez v9, :cond_d

    .line 46
    .line 47
    iget-boolean v9, v6, Lh01/o;->q:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 48
    .line 49
    if-nez v9, :cond_d

    .line 50
    .line 51
    monitor-exit v6

    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    new-instance v0, Lh01/r;

    .line 55
    .line 56
    iget-object v9, v6, Lh01/o;->d:Ld01/h0;

    .line 57
    .line 58
    iget-object v10, v9, Ld01/h0;->D:Lg01/c;

    .line 59
    .line 60
    move-object v11, v8

    .line 61
    iget-object v8, v6, Lh01/o;->g:Lh01/q;

    .line 62
    .line 63
    iget v12, v9, Ld01/h0;->y:I

    .line 64
    .line 65
    move-object v13, v10

    .line 66
    iget v10, v9, Ld01/h0;->z:I

    .line 67
    .line 68
    move-object v14, v11

    .line 69
    iget v11, v5, Li01/f;->f:I

    .line 70
    .line 71
    move v15, v12

    .line 72
    iget v12, v5, Li01/f;->g:I

    .line 73
    .line 74
    move-object/from16 v16, v13

    .line 75
    .line 76
    iget-boolean v13, v9, Ld01/h0;->e:Z

    .line 77
    .line 78
    move-object/from16 v17, v14

    .line 79
    .line 80
    iget-boolean v14, v9, Ld01/h0;->f:Z

    .line 81
    .line 82
    iget-object v2, v7, Ld01/k0;->a:Ld01/a0;

    .line 83
    .line 84
    const-string v4, "url"

    .line 85
    .line 86
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v2}, Ld01/a0;->f()Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_1

    .line 94
    .line 95
    iget-object v4, v9, Ld01/h0;->p:Ljavax/net/ssl/SSLSocketFactory;

    .line 96
    .line 97
    if-eqz v4, :cond_0

    .line 98
    .line 99
    iget-object v3, v9, Ld01/h0;->t:Lr01/c;

    .line 100
    .line 101
    move-object/from16 p1, v0

    .line 102
    .line 103
    iget-object v0, v9, Ld01/h0;->u:Ld01/l;

    .line 104
    .line 105
    move-object/from16 v28, v0

    .line 106
    .line 107
    move-object/from16 v27, v3

    .line 108
    .line 109
    move-object/from16 v26, v4

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string v1, "CLEARTEXT-only client"

    .line 115
    .line 116
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw v0

    .line 120
    :cond_1
    move-object/from16 p1, v0

    .line 121
    .line 122
    const/16 v26, 0x0

    .line 123
    .line 124
    const/16 v27, 0x0

    .line 125
    .line 126
    const/16 v28, 0x0

    .line 127
    .line 128
    :goto_2
    new-instance v21, Ld01/a;

    .line 129
    .line 130
    iget-object v0, v2, Ld01/a0;->d:Ljava/lang/String;

    .line 131
    .line 132
    iget v2, v2, Ld01/a0;->e:I

    .line 133
    .line 134
    iget-object v3, v9, Ld01/h0;->l:Ld01/r;

    .line 135
    .line 136
    iget-object v4, v9, Ld01/h0;->o:Ljavax/net/SocketFactory;

    .line 137
    .line 138
    move-object/from16 v22, v0

    .line 139
    .line 140
    iget-object v0, v9, Ld01/h0;->n:Ld01/b;

    .line 141
    .line 142
    move-object/from16 v29, v0

    .line 143
    .line 144
    iget-object v0, v9, Ld01/h0;->s:Ljava/util/List;

    .line 145
    .line 146
    move-object/from16 v30, v0

    .line 147
    .line 148
    iget-object v0, v9, Ld01/h0;->r:Ljava/util/List;

    .line 149
    .line 150
    iget-object v9, v9, Ld01/h0;->m:Ljava/net/ProxySelector;

    .line 151
    .line 152
    move-object/from16 v31, v0

    .line 153
    .line 154
    move/from16 v23, v2

    .line 155
    .line 156
    move-object/from16 v24, v3

    .line 157
    .line 158
    move-object/from16 v25, v4

    .line 159
    .line 160
    move-object/from16 v32, v9

    .line 161
    .line 162
    invoke-direct/range {v21 .. v32}, Ld01/a;-><init>(Ljava/lang/String;ILd01/r;Ljavax/net/SocketFactory;Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/HostnameVerifier;Ld01/l;Ld01/b;Ljava/util/List;Ljava/util/List;Ljava/net/ProxySelector;)V

    .line 163
    .line 164
    .line 165
    iget-object v0, v6, Lh01/o;->d:Ld01/h0;

    .line 166
    .line 167
    iget-object v0, v0, Ld01/h0;->C:Lbu/c;

    .line 168
    .line 169
    move-object/from16 v18, v7

    .line 170
    .line 171
    move v9, v15

    .line 172
    move-object/from16 v7, v16

    .line 173
    .line 174
    move-object/from16 v2, v17

    .line 175
    .line 176
    move-object/from16 v15, v21

    .line 177
    .line 178
    move-object/from16 v16, v0

    .line 179
    .line 180
    move-object/from16 v17, v6

    .line 181
    .line 182
    move-object/from16 v6, p1

    .line 183
    .line 184
    invoke-direct/range {v6 .. v18}, Lh01/r;-><init>(Lg01/c;Lh01/q;IIIIZZLd01/a;Lbu/c;Lh01/o;Ld01/k0;)V

    .line 185
    .line 186
    .line 187
    move-object/from16 v3, v17

    .line 188
    .line 189
    move-object/from16 v7, v18

    .line 190
    .line 191
    iget-object v0, v3, Lh01/o;->d:Ld01/h0;

    .line 192
    .line 193
    iget-boolean v4, v0, Ld01/h0;->f:Z

    .line 194
    .line 195
    if-eqz v4, :cond_2

    .line 196
    .line 197
    new-instance v4, Lh01/k;

    .line 198
    .line 199
    iget-object v0, v0, Ld01/h0;->D:Lg01/c;

    .line 200
    .line 201
    invoke-direct {v4, v6, v0}, Lh01/k;-><init>(Lh01/r;Lg01/c;)V

    .line 202
    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_2
    new-instance v4, Laq/a;

    .line 206
    .line 207
    const/16 v0, 0x1c

    .line 208
    .line 209
    invoke-direct {v4, v6, v0}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 210
    .line 211
    .line 212
    :goto_3
    iput-object v4, v3, Lh01/o;->k:Lh01/h;

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_3
    move-object v3, v6

    .line 216
    move-object v2, v8

    .line 217
    :goto_4
    :try_start_1
    iget-boolean v0, v3, Lh01/o;->t:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 218
    .line 219
    if-nez v0, :cond_c

    .line 220
    .line 221
    :try_start_2
    invoke-virtual {v5, v7}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 222
    .line 223
    .line 224
    move-result-object v0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 225
    :try_start_3
    invoke-virtual {v0}, Ld01/t0;->d()Ld01/s0;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    iput-object v7, v0, Ld01/s0;->a:Ld01/k0;

    .line 230
    .line 231
    if-eqz v19, :cond_4

    .line 232
    .line 233
    invoke-static/range {v19 .. v19}, Ljp/qg;->b(Ld01/t0;)Ld01/t0;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    goto :goto_5

    .line 238
    :catchall_0
    move-exception v0

    .line 239
    const/4 v6, 0x1

    .line 240
    goto/16 :goto_9

    .line 241
    .line 242
    :cond_4
    const/4 v4, 0x0

    .line 243
    :goto_5
    iput-object v4, v0, Ld01/s0;->k:Ld01/t0;

    .line 244
    .line 245
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    iget-object v4, v3, Lh01/o;->n:Lh01/g;

    .line 250
    .line 251
    invoke-virtual {v1, v0, v4}, Lfl/b;->a(Ld01/t0;Lh01/g;)Ld01/k0;

    .line 252
    .line 253
    .line 254
    move-result-object v7

    .line 255
    if-nez v7, :cond_7

    .line 256
    .line 257
    if-eqz v4, :cond_5

    .line 258
    .line 259
    iget-boolean v1, v4, Lh01/g;->d:Z

    .line 260
    .line 261
    if-eqz v1, :cond_5

    .line 262
    .line 263
    iget-boolean v1, v3, Lh01/o;->m:Z

    .line 264
    .line 265
    if-nez v1, :cond_6

    .line 266
    .line 267
    const/4 v1, 0x1

    .line 268
    iput-boolean v1, v3, Lh01/o;->m:Z

    .line 269
    .line 270
    iget-object v1, v3, Lh01/o;->h:Lh01/n;

    .line 271
    .line 272
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 273
    .line 274
    .line 275
    :cond_5
    const/4 v4, 0x0

    .line 276
    goto :goto_6

    .line 277
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 278
    .line 279
    const-string v1, "Check failed."

    .line 280
    .line 281
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 285
    :goto_6
    invoke-virtual {v3, v4}, Lh01/o;->d(Z)V

    .line 286
    .line 287
    .line 288
    goto :goto_7

    .line 289
    :cond_7
    const/4 v4, 0x0

    .line 290
    :try_start_4
    iget-object v6, v7, Ld01/k0;->d:Ld01/r0;

    .line 291
    .line 292
    if-eqz v6, :cond_8

    .line 293
    .line 294
    invoke-virtual {v6}, Ld01/r0;->isOneShot()Z

    .line 295
    .line 296
    .line 297
    move-result v6

    .line 298
    if-eqz v6, :cond_8

    .line 299
    .line 300
    goto :goto_6

    .line 301
    :goto_7
    return-object v0

    .line 302
    :cond_8
    iget-object v4, v0, Ld01/t0;->j:Ld01/v0;

    .line 303
    .line 304
    invoke-static {v4}, Le01/e;->b(Ljava/io/Closeable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 305
    .line 306
    .line 307
    add-int/lit8 v4, v20, 0x1

    .line 308
    .line 309
    const/16 v6, 0x14

    .line 310
    .line 311
    if-gt v4, v6, :cond_9

    .line 312
    .line 313
    const/4 v6, 0x1

    .line 314
    invoke-virtual {v3, v6}, Lh01/o;->d(Z)V

    .line 315
    .line 316
    .line 317
    move-object/from16 v19, v0

    .line 318
    .line 319
    move-object v8, v2

    .line 320
    move-object v6, v3

    .line 321
    move/from16 v20, v4

    .line 322
    .line 323
    goto/16 :goto_0

    .line 324
    .line 325
    :cond_9
    :try_start_5
    new-instance v0, Ljava/net/ProtocolException;

    .line 326
    .line 327
    new-instance v1, Ljava/lang/StringBuilder;

    .line 328
    .line 329
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 330
    .line 331
    .line 332
    const-string v2, "Too many follow-up requests: "

    .line 333
    .line 334
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    invoke-direct {v0, v1}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    throw v0

    .line 348
    :catch_0
    move-exception v0

    .line 349
    invoke-virtual {v1, v0, v3, v7}, Lfl/b;->b(Ljava/io/IOException;Lh01/o;Ld01/k0;)Z

    .line 350
    .line 351
    .line 352
    move-result v4

    .line 353
    if-nez v4, :cond_b

    .line 354
    .line 355
    sget-object v1, Le01/e;->a:[B

    .line 356
    .line 357
    const-string v1, "suppressed"

    .line 358
    .line 359
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 367
    .line 368
    .line 369
    move-result v2

    .line 370
    if-eqz v2, :cond_a

    .line 371
    .line 372
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v2

    .line 376
    check-cast v2, Ljava/lang/Exception;

    .line 377
    .line 378
    invoke-static {v0, v2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 379
    .line 380
    .line 381
    goto :goto_8

    .line 382
    :cond_a
    throw v0

    .line 383
    :cond_b
    move-object v8, v2

    .line 384
    check-cast v8, Ljava/util/Collection;

    .line 385
    .line 386
    invoke-static {v8, v0}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 387
    .line 388
    .line 389
    move-result-object v8
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 390
    const/4 v6, 0x1

    .line 391
    invoke-virtual {v3, v6}, Lh01/o;->d(Z)V

    .line 392
    .line 393
    .line 394
    move-object v6, v3

    .line 395
    const/4 v0, 0x0

    .line 396
    goto/16 :goto_1

    .line 397
    .line 398
    :cond_c
    :try_start_6
    new-instance v0, Ljava/io/IOException;

    .line 399
    .line 400
    const-string v1, "Canceled"

    .line 401
    .line 402
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 406
    :goto_9
    invoke-virtual {v3, v6}, Lh01/o;->d(Z)V

    .line 407
    .line 408
    .line 409
    throw v0

    .line 410
    :cond_d
    move-object v3, v6

    .line 411
    goto :goto_a

    .line 412
    :catchall_1
    move-exception v0

    .line 413
    move-object v3, v6

    .line 414
    goto :goto_b

    .line 415
    :goto_a
    :try_start_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 416
    .line 417
    const-string v1, "Check failed."

    .line 418
    .line 419
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    throw v0

    .line 423
    :catchall_2
    move-exception v0

    .line 424
    goto :goto_b

    .line 425
    :cond_e
    move-object v3, v6

    .line 426
    const-string v0, "cannot make a new request because the previous response is still open: please call response.close()"

    .line 427
    .line 428
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 429
    .line 430
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 431
    .line 432
    .line 433
    throw v1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 434
    :goto_b
    monitor-exit v3

    .line 435
    throw v0

    .line 436
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 437
    .line 438
    const-string v1, "Check failed."

    .line 439
    .line 440
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    throw v0

    .line 444
    :pswitch_0
    move-object/from16 v0, p1

    .line 445
    .line 446
    check-cast v0, Li01/f;

    .line 447
    .line 448
    iget-object v2, v0, Li01/f;->e:Ld01/k0;

    .line 449
    .line 450
    invoke-virtual {v2}, Ld01/k0;->b()Ld01/j0;

    .line 451
    .line 452
    .line 453
    move-result-object v2

    .line 454
    iget-object v1, v1, Lfl/b;->b:Ljava/lang/Object;

    .line 455
    .line 456
    check-cast v1, Lfl/h;

    .line 457
    .line 458
    invoke-virtual {v1, v2}, Lfl/h;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    new-instance v1, Ld01/k0;

    .line 462
    .line 463
    invoke-direct {v1, v2}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 464
    .line 465
    .line 466
    invoke-virtual {v0, v1}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 467
    .line 468
    .line 469
    move-result-object v0

    .line 470
    return-object v0

    .line 471
    :pswitch_1
    const-string v2, "Kt"

    .line 472
    .line 473
    const-class v3, Lfl/b;

    .line 474
    .line 475
    sget-object v0, Lgi/b;->d:Lgi/b;

    .line 476
    .line 477
    sget-object v4, Lgi/a;->d:Lgi/a;

    .line 478
    .line 479
    new-instance v5, Lfl/a;

    .line 480
    .line 481
    move-object/from16 v6, p1

    .line 482
    .line 483
    check-cast v6, Li01/f;

    .line 484
    .line 485
    const/4 v7, 0x0

    .line 486
    invoke-direct {v5, v6, v7}, Lfl/a;-><init>(Li01/f;I)V

    .line 487
    .line 488
    .line 489
    const/16 v7, 0x2e

    .line 490
    .line 491
    const/16 v8, 0x24

    .line 492
    .line 493
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 494
    .line 495
    .line 496
    move-result-object v9

    .line 497
    invoke-static {v9, v8}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 498
    .line 499
    .line 500
    move-result-object v10

    .line 501
    invoke-static {v7, v10, v10}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 502
    .line 503
    .line 504
    move-result-object v10

    .line 505
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 506
    .line 507
    .line 508
    move-result v11

    .line 509
    if-nez v11, :cond_10

    .line 510
    .line 511
    :goto_c
    const/4 v10, 0x0

    .line 512
    goto :goto_d

    .line 513
    :cond_10
    invoke-static {v10, v2}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 514
    .line 515
    .line 516
    move-result-object v9

    .line 517
    goto :goto_c

    .line 518
    :goto_d
    invoke-static {v9, v4, v0, v10, v5}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 519
    .line 520
    .line 521
    const/4 v4, 0x0

    .line 522
    invoke-virtual {v1, v4, v6}, Lfl/b;->c(ZLi01/f;)Ld01/t0;

    .line 523
    .line 524
    .line 525
    move-result-object v0

    .line 526
    iget v4, v0, Ld01/t0;->g:I

    .line 527
    .line 528
    const/16 v5, 0x191

    .line 529
    .line 530
    if-ne v4, v5, :cond_12

    .line 531
    .line 532
    :try_start_8
    invoke-virtual {v0}, Ld01/t0;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 533
    .line 534
    .line 535
    goto :goto_e

    .line 536
    :catchall_3
    move-exception v0

    .line 537
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 538
    .line 539
    .line 540
    :goto_e
    sget-object v0, Lgi/b;->g:Lgi/b;

    .line 541
    .line 542
    sget-object v4, Lgi/a;->d:Lgi/a;

    .line 543
    .line 544
    new-instance v5, Lfl/a;

    .line 545
    .line 546
    const/4 v9, 0x1

    .line 547
    invoke-direct {v5, v6, v9}, Lfl/a;-><init>(Li01/f;I)V

    .line 548
    .line 549
    .line 550
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 551
    .line 552
    .line 553
    move-result-object v3

    .line 554
    invoke-static {v3, v8}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 555
    .line 556
    .line 557
    move-result-object v8

    .line 558
    invoke-static {v7, v8, v8}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 559
    .line 560
    .line 561
    move-result-object v7

    .line 562
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 563
    .line 564
    .line 565
    move-result v8

    .line 566
    if-nez v8, :cond_11

    .line 567
    .line 568
    :goto_f
    const/4 v10, 0x0

    .line 569
    goto :goto_10

    .line 570
    :cond_11
    invoke-static {v7, v2}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 571
    .line 572
    .line 573
    move-result-object v3

    .line 574
    goto :goto_f

    .line 575
    :goto_10
    invoke-static {v3, v4, v0, v10, v5}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 576
    .line 577
    .line 578
    invoke-virtual {v1, v9, v6}, Lfl/b;->c(ZLi01/f;)Ld01/t0;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    :cond_12
    return-object v0

    .line 583
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
