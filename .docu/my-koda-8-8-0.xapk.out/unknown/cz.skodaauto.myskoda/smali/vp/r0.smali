.class public final Lvp/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/net/URL;

.field public final f:[B

.field public final g:Ljava/lang/String;

.field public final h:Ljava/util/Map;

.field public final i:Ljava/lang/Object;

.field public final synthetic j:Lap0/o;


# direct methods
.method public constructor <init>(Lvp/n2;Ljava/lang/String;Ljava/net/URL;[BLjava/util/HashMap;Lvp/l2;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/r0;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/r0;->j:Lap0/o;

    .line 6
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    iput-object p3, p0, Lvp/r0;->e:Ljava/net/URL;

    iput-object p4, p0, Lvp/r0;->f:[B

    iput-object p6, p0, Lvp/r0;->i:Ljava/lang/Object;

    iput-object p2, p0, Lvp/r0;->g:Ljava/lang/String;

    iput-object p5, p0, Lvp/r0;->h:Ljava/util/Map;

    return-void
.end method

.method public constructor <init>(Lvp/s0;Ljava/lang/String;Ljava/net/URL;[BLjava/util/Map;Lvp/q0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/r0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/r0;->j:Lap0/o;

    .line 2
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 3
    invoke-static {p3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 4
    iput-object p3, p0, Lvp/r0;->e:Ljava/net/URL;

    iput-object p4, p0, Lvp/r0;->f:[B

    iput-object p6, p0, Lvp/r0;->i:Ljava/lang/Object;

    iput-object p2, p0, Lvp/r0;->g:Ljava/lang/String;

    iput-object p5, p0, Lvp/r0;->h:Ljava/util/Map;

    return-void
.end method


# virtual methods
.method public a(ILjava/io/IOException;[BLjava/util/Map;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lvp/r0;->j:Lap0/o;

    .line 2
    .line 3
    check-cast v0, Lvp/n2;

    .line 4
    .line 5
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lvp/g1;

    .line 8
    .line 9
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 10
    .line 11
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lvp/m2;

    .line 15
    .line 16
    move-object v2, p0

    .line 17
    move v3, p1

    .line 18
    move-object v4, p2

    .line 19
    move-object v5, p3

    .line 20
    move-object v6, p4

    .line 21
    invoke-direct/range {v1 .. v6}, Lvp/m2;-><init>(Lvp/r0;ILjava/lang/Exception;[BLjava/util/Map;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final run()V
    .locals 14

    .line 1
    iget v0, p0, Lvp/r0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v1, "Error closing HTTP compressed POST connection output stream. appId"

    .line 7
    .line 8
    iget-object v2, p0, Lvp/r0;->g:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p0, Lvp/r0;->j:Lap0/o;

    .line 11
    .line 12
    check-cast v0, Lvp/n2;

    .line 13
    .line 14
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, Lvp/g1;

    .line 17
    .line 18
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lvp/g1;

    .line 22
    .line 23
    iget-object v0, v3, Lvp/g1;->j:Lvp/e1;

    .line 24
    .line 25
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Lvp/e1;->e0()V

    .line 29
    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    :try_start_0
    iget-object v0, p0, Lvp/r0;->e:Ljava/net/URL;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    instance-of v6, v0, Ljava/net/HttpURLConnection;

    .line 40
    .line 41
    if-eqz v6, :cond_4

    .line 42
    .line 43
    move-object v6, v0

    .line 44
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 45
    .line 46
    invoke-virtual {v6, v3}, Ljava/net/URLConnection;->setDefaultUseCaches(Z)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const v0, 0xea60

    .line 53
    .line 54
    .line 55
    invoke-virtual {v6, v0}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 56
    .line 57
    .line 58
    const v0, 0xee48

    .line 59
    .line 60
    .line 61
    invoke-virtual {v6, v0}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v6, v3}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 65
    .line 66
    .line 67
    const/4 v0, 0x1

    .line 68
    invoke-virtual {v6, v0}, Ljava/net/URLConnection;->setDoInput(Z)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_5
    .catchall {:try_start_0 .. :try_end_0} :catchall_6

    .line 69
    .line 70
    .line 71
    :try_start_1
    iget-object v7, p0, Lvp/r0;->h:Ljava/util/Map;

    .line 72
    .line 73
    if-eqz v7, :cond_0

    .line 74
    .line 75
    invoke-interface {v7}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 76
    .line 77
    .line 78
    move-result-object v7

    .line 79
    invoke-interface {v7}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    if-eqz v8, :cond_0

    .line 88
    .line 89
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    check-cast v8, Ljava/util/Map$Entry;

    .line 94
    .line 95
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v9

    .line 99
    check-cast v9, Ljava/lang/String;

    .line 100
    .line 101
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    check-cast v8, Ljava/lang/String;

    .line 106
    .line 107
    invoke-virtual {v6, v9, v8}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :catchall_0
    move-exception v0

    .line 112
    goto/16 :goto_a

    .line 113
    .line 114
    :catch_0
    move-exception v0

    .line 115
    goto/16 :goto_c

    .line 116
    .line 117
    :cond_0
    iget-object v7, p0, Lvp/r0;->f:[B
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 118
    .line 119
    if-eqz v7, :cond_1

    .line 120
    .line 121
    :try_start_2
    new-instance v8, Ljava/io/ByteArrayOutputStream;

    .line 122
    .line 123
    invoke-direct {v8}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 124
    .line 125
    .line 126
    new-instance v9, Ljava/util/zip/GZIPOutputStream;

    .line 127
    .line 128
    invoke-direct {v9, v8}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v9, v7}, Ljava/io/OutputStream;->write([B)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v9}, Ljava/io/OutputStream;->close()V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v8}, Ljava/io/ByteArrayOutputStream;->close()V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v8}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 141
    .line 142
    .line 143
    move-result-object v7
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 144
    :try_start_3
    iget-object v8, v4, Lvp/g1;->i:Lvp/p0;

    .line 145
    .line 146
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 147
    .line 148
    .line 149
    iget-object v8, v8, Lvp/p0;->r:Lvp/n0;

    .line 150
    .line 151
    const-string v9, "Uploading data. size"

    .line 152
    .line 153
    array-length v10, v7

    .line 154
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 155
    .line 156
    .line 157
    move-result-object v11

    .line 158
    invoke-virtual {v8, v11, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v6, v0}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 162
    .line 163
    .line 164
    const-string v0, "Content-Encoding"

    .line 165
    .line 166
    const-string v8, "gzip"

    .line 167
    .line 168
    invoke-virtual {v6, v0, v8}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v6, v10}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(I)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v6}, Ljava/net/URLConnection;->connect()V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v6}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 178
    .line 179
    .line 180
    move-result-object v8
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 181
    :try_start_4
    invoke-virtual {v8, v7}, Ljava/io/OutputStream;->write([B)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v8}, Ljava/io/OutputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 185
    .line 186
    .line 187
    goto :goto_5

    .line 188
    :catchall_1
    move-exception v0

    .line 189
    goto :goto_1

    .line 190
    :catch_1
    move-exception v0

    .line 191
    goto :goto_3

    .line 192
    :goto_1
    move v7, v3

    .line 193
    move-object v9, v5

    .line 194
    :goto_2
    move-object v3, v0

    .line 195
    goto/16 :goto_f

    .line 196
    .line 197
    :goto_3
    move v7, v3

    .line 198
    move-object v9, v5

    .line 199
    :goto_4
    move-object v3, v0

    .line 200
    goto/16 :goto_12

    .line 201
    .line 202
    :catch_2
    move-exception v0

    .line 203
    :try_start_5
    iget-object v7, v4, Lvp/g1;->i:Lvp/p0;

    .line 204
    .line 205
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 206
    .line 207
    .line 208
    iget-object v7, v7, Lvp/p0;->j:Lvp/n0;

    .line 209
    .line 210
    const-string v8, "Failed to gzip post request content"

    .line 211
    .line 212
    invoke-virtual {v7, v0, v8}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw v0

    .line 216
    :cond_1
    :goto_5
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 217
    .line 218
    .line 219
    move-result v7
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 220
    :try_start_6
    invoke-virtual {v6}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 221
    .line 222
    .line 223
    move-result-object v8
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_4
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 224
    :try_start_7
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 225
    .line 226
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v6}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 230
    .line 231
    .line 232
    move-result-object v9
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 233
    const/16 v10, 0x400

    .line 234
    .line 235
    :try_start_8
    new-array v10, v10, [B

    .line 236
    .line 237
    :goto_6
    invoke-virtual {v9, v10}, Ljava/io/InputStream;->read([B)I

    .line 238
    .line 239
    .line 240
    move-result v11

    .line 241
    if-lez v11, :cond_2

    .line 242
    .line 243
    invoke-virtual {v0, v10, v3, v11}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 244
    .line 245
    .line 246
    goto :goto_6

    .line 247
    :catchall_2
    move-exception v0

    .line 248
    goto :goto_7

    .line 249
    :cond_2
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 250
    .line 251
    .line 252
    move-result-object v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 253
    :try_start_9
    invoke-virtual {v9}, Ljava/io/InputStream;->close()V
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_3
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 254
    .line 255
    .line 256
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 257
    .line 258
    .line 259
    invoke-virtual {p0, v7, v5, v0, v8}, Lvp/r0;->a(ILjava/io/IOException;[BLjava/util/Map;)V

    .line 260
    .line 261
    .line 262
    goto/16 :goto_14

    .line 263
    .line 264
    :catchall_3
    move-exception v0

    .line 265
    goto :goto_8

    .line 266
    :catch_3
    move-exception v0

    .line 267
    goto :goto_9

    .line 268
    :catchall_4
    move-exception v0

    .line 269
    move-object v9, v5

    .line 270
    :goto_7
    if-eqz v9, :cond_3

    .line 271
    .line 272
    :try_start_a
    invoke-virtual {v9}, Ljava/io/InputStream;->close()V

    .line 273
    .line 274
    .line 275
    :cond_3
    throw v0
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_3
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 276
    :goto_8
    move-object v3, v0

    .line 277
    move-object v9, v8

    .line 278
    move-object v8, v5

    .line 279
    goto :goto_f

    .line 280
    :goto_9
    move-object v3, v0

    .line 281
    move-object v9, v8

    .line 282
    move-object v8, v5

    .line 283
    goto :goto_12

    .line 284
    :catchall_5
    move-exception v0

    .line 285
    move-object v3, v0

    .line 286
    move-object v8, v5

    .line 287
    move-object v9, v8

    .line 288
    goto :goto_f

    .line 289
    :catch_4
    move-exception v0

    .line 290
    move-object v3, v0

    .line 291
    move-object v8, v5

    .line 292
    move-object v9, v8

    .line 293
    goto :goto_12

    .line 294
    :goto_a
    move v7, v3

    .line 295
    move-object v8, v5

    .line 296
    :goto_b
    move-object v9, v8

    .line 297
    goto :goto_2

    .line 298
    :goto_c
    move v7, v3

    .line 299
    move-object v8, v5

    .line 300
    :goto_d
    move-object v9, v8

    .line 301
    goto :goto_4

    .line 302
    :catchall_6
    move-exception v0

    .line 303
    goto :goto_e

    .line 304
    :catch_5
    move-exception v0

    .line 305
    goto :goto_11

    .line 306
    :cond_4
    :try_start_b
    new-instance v0, Ljava/io/IOException;

    .line 307
    .line 308
    const-string v6, "Failed to obtain HTTP connection"

    .line 309
    .line 310
    invoke-direct {v0, v6}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    throw v0
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_5
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 314
    :goto_e
    move v7, v3

    .line 315
    move-object v6, v5

    .line 316
    move-object v8, v6

    .line 317
    goto :goto_b

    .line 318
    :goto_f
    if-eqz v8, :cond_5

    .line 319
    .line 320
    :try_start_c
    invoke-virtual {v8}, Ljava/io/OutputStream;->close()V
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_6

    .line 321
    .line 322
    .line 323
    goto :goto_10

    .line 324
    :catch_6
    move-exception v0

    .line 325
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 326
    .line 327
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 328
    .line 329
    .line 330
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 331
    .line 332
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    invoke-virtual {v4, v2, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    :cond_5
    :goto_10
    if-eqz v6, :cond_6

    .line 340
    .line 341
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 342
    .line 343
    .line 344
    :cond_6
    invoke-virtual {p0, v7, v5, v5, v9}, Lvp/r0;->a(ILjava/io/IOException;[BLjava/util/Map;)V

    .line 345
    .line 346
    .line 347
    throw v3

    .line 348
    :goto_11
    move v7, v3

    .line 349
    move-object v6, v5

    .line 350
    move-object v8, v6

    .line 351
    goto :goto_d

    .line 352
    :goto_12
    if-eqz v8, :cond_7

    .line 353
    .line 354
    :try_start_d
    invoke-virtual {v8}, Ljava/io/OutputStream;->close()V
    :try_end_d
    .catch Ljava/io/IOException; {:try_start_d .. :try_end_d} :catch_7

    .line 355
    .line 356
    .line 357
    goto :goto_13

    .line 358
    :catch_7
    move-exception v0

    .line 359
    iget-object v4, v4, Lvp/g1;->i:Lvp/p0;

    .line 360
    .line 361
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 362
    .line 363
    .line 364
    iget-object v4, v4, Lvp/p0;->j:Lvp/n0;

    .line 365
    .line 366
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    invoke-virtual {v4, v2, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    :cond_7
    :goto_13
    if-eqz v6, :cond_8

    .line 374
    .line 375
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 376
    .line 377
    .line 378
    :cond_8
    invoke-virtual {p0, v7, v3, v5, v9}, Lvp/r0;->a(ILjava/io/IOException;[BLjava/util/Map;)V

    .line 379
    .line 380
    .line 381
    :goto_14
    return-void

    .line 382
    :pswitch_0
    const-string v1, "Error closing HTTP compressed POST connection output stream. appId"

    .line 383
    .line 384
    iget-object v2, p0, Lvp/r0;->g:Ljava/lang/String;

    .line 385
    .line 386
    iget-object v0, p0, Lvp/r0;->j:Lap0/o;

    .line 387
    .line 388
    check-cast v0, Lvp/s0;

    .line 389
    .line 390
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v3, Lvp/g1;

    .line 393
    .line 394
    iget-object v4, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v4, Lvp/g1;

    .line 397
    .line 398
    iget-object v3, v3, Lvp/g1;->j:Lvp/e1;

    .line 399
    .line 400
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v3}, Lvp/e1;->e0()V

    .line 404
    .line 405
    .line 406
    const/4 v3, 0x0

    .line 407
    const/4 v5, 0x0

    .line 408
    :try_start_e
    iget-object v6, p0, Lvp/r0;->e:Ljava/net/URL;

    .line 409
    .line 410
    invoke-virtual {v6}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 411
    .line 412
    .line 413
    move-result-object v6

    .line 414
    instance-of v7, v6, Ljava/net/HttpURLConnection;

    .line 415
    .line 416
    if-eqz v7, :cond_d

    .line 417
    .line 418
    check-cast v6, Ljava/net/HttpURLConnection;

    .line 419
    .line 420
    invoke-virtual {v6, v3}, Ljava/net/URLConnection;->setDefaultUseCaches(Z)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 424
    .line 425
    .line 426
    const v7, 0xea60

    .line 427
    .line 428
    .line 429
    invoke-virtual {v6, v7}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 430
    .line 431
    .line 432
    const v7, 0xee48

    .line 433
    .line 434
    .line 435
    invoke-virtual {v6, v7}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v6, v3}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 439
    .line 440
    .line 441
    const/4 v7, 0x1

    .line 442
    invoke-virtual {v6, v7}, Ljava/net/URLConnection;->setDoInput(Z)V
    :try_end_e
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_c
    .catchall {:try_start_e .. :try_end_e} :catchall_d

    .line 443
    .line 444
    .line 445
    :try_start_f
    iget-object v8, p0, Lvp/r0;->h:Ljava/util/Map;

    .line 446
    .line 447
    if-eqz v8, :cond_9

    .line 448
    .line 449
    invoke-interface {v8}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 450
    .line 451
    .line 452
    move-result-object v8

    .line 453
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 454
    .line 455
    .line 456
    move-result-object v8

    .line 457
    :goto_15
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 458
    .line 459
    .line 460
    move-result v9

    .line 461
    if-eqz v9, :cond_9

    .line 462
    .line 463
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v9

    .line 467
    check-cast v9, Ljava/util/Map$Entry;

    .line 468
    .line 469
    invoke-interface {v9}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v10

    .line 473
    check-cast v10, Ljava/lang/String;

    .line 474
    .line 475
    invoke-interface {v9}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 476
    .line 477
    .line 478
    move-result-object v9

    .line 479
    check-cast v9, Ljava/lang/String;

    .line 480
    .line 481
    invoke-virtual {v6, v10, v9}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 482
    .line 483
    .line 484
    goto :goto_15

    .line 485
    :catchall_7
    move-exception v0

    .line 486
    goto/16 :goto_1f

    .line 487
    .line 488
    :catch_8
    move-exception v0

    .line 489
    goto/16 :goto_20

    .line 490
    .line 491
    :cond_9
    iget-object v8, p0, Lvp/r0;->f:[B

    .line 492
    .line 493
    if-eqz v8, :cond_a

    .line 494
    .line 495
    iget-object v0, v0, Lvp/q3;->f:Lvp/z3;

    .line 496
    .line 497
    iget-object v0, v0, Lvp/z3;->j:Lvp/s0;

    .line 498
    .line 499
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 500
    .line 501
    .line 502
    invoke-virtual {v0, v8}, Lvp/s0;->M0([B)[B

    .line 503
    .line 504
    .line 505
    move-result-object v0

    .line 506
    iget-object v8, v4, Lvp/g1;->i:Lvp/p0;

    .line 507
    .line 508
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 509
    .line 510
    .line 511
    iget-object v8, v8, Lvp/p0;->r:Lvp/n0;

    .line 512
    .line 513
    const-string v9, "Uploading data. size"

    .line 514
    .line 515
    array-length v10, v0

    .line 516
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 517
    .line 518
    .line 519
    move-result-object v11

    .line 520
    invoke-virtual {v8, v11, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v6, v7}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 524
    .line 525
    .line 526
    const-string v7, "Content-Encoding"

    .line 527
    .line 528
    const-string v8, "gzip"

    .line 529
    .line 530
    invoke-virtual {v6, v7, v8}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v6, v10}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(I)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v6}, Ljava/net/URLConnection;->connect()V

    .line 537
    .line 538
    .line 539
    invoke-virtual {v6}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 540
    .line 541
    .line 542
    move-result-object v7
    :try_end_f
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_8
    .catchall {:try_start_f .. :try_end_f} :catchall_7

    .line 543
    :try_start_10
    invoke-virtual {v7, v0}, Ljava/io/OutputStream;->write([B)V

    .line 544
    .line 545
    .line 546
    invoke-virtual {v7}, Ljava/io/OutputStream;->close()V
    :try_end_10
    .catch Ljava/io/IOException; {:try_start_10 .. :try_end_10} :catch_9
    .catchall {:try_start_10 .. :try_end_10} :catchall_8

    .line 547
    .line 548
    .line 549
    goto :goto_19

    .line 550
    :catchall_8
    move-exception v0

    .line 551
    goto :goto_16

    .line 552
    :catch_9
    move-exception v0

    .line 553
    goto :goto_18

    .line 554
    :goto_16
    move v8, v3

    .line 555
    move-object v11, v5

    .line 556
    move-object v5, v7

    .line 557
    :goto_17
    move-object v3, v0

    .line 558
    goto/16 :goto_22

    .line 559
    .line 560
    :goto_18
    move-object v10, v0

    .line 561
    move v9, v3

    .line 562
    move-object v12, v5

    .line 563
    move-object v5, v7

    .line 564
    goto/16 :goto_25

    .line 565
    .line 566
    :cond_a
    :goto_19
    :try_start_11
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 567
    .line 568
    .line 569
    move-result v10
    :try_end_11
    .catch Ljava/io/IOException; {:try_start_11 .. :try_end_11} :catch_8
    .catchall {:try_start_11 .. :try_end_11} :catchall_7

    .line 570
    :try_start_12
    invoke-virtual {v6}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 571
    .line 572
    .line 573
    move-result-object v13
    :try_end_12
    .catch Ljava/io/IOException; {:try_start_12 .. :try_end_12} :catch_b
    .catchall {:try_start_12 .. :try_end_12} :catchall_c

    .line 574
    :try_start_13
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 575
    .line 576
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 577
    .line 578
    .line 579
    invoke-virtual {v6}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 580
    .line 581
    .line 582
    move-result-object v7
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_b

    .line 583
    const/16 v8, 0x400

    .line 584
    .line 585
    :try_start_14
    new-array v8, v8, [B

    .line 586
    .line 587
    :goto_1a
    invoke-virtual {v7, v8}, Ljava/io/InputStream;->read([B)I

    .line 588
    .line 589
    .line 590
    move-result v9

    .line 591
    if-lez v9, :cond_b

    .line 592
    .line 593
    invoke-virtual {v0, v8, v3, v9}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 594
    .line 595
    .line 596
    goto :goto_1a

    .line 597
    :catchall_9
    move-exception v0

    .line 598
    goto :goto_1b

    .line 599
    :cond_b
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 600
    .line 601
    .line 602
    move-result-object v12
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_9

    .line 603
    :try_start_15
    invoke-virtual {v7}, Ljava/io/InputStream;->close()V
    :try_end_15
    .catch Ljava/io/IOException; {:try_start_15 .. :try_end_15} :catch_a
    .catchall {:try_start_15 .. :try_end_15} :catchall_a

    .line 604
    .line 605
    .line 606
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 607
    .line 608
    .line 609
    iget-object v0, p0, Lvp/r0;->i:Ljava/lang/Object;

    .line 610
    .line 611
    move-object v9, v0

    .line 612
    check-cast v9, Lvp/q0;

    .line 613
    .line 614
    iget-object v0, v4, Lvp/g1;->j:Lvp/e1;

    .line 615
    .line 616
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 617
    .line 618
    .line 619
    new-instance v7, Lvp/m0;

    .line 620
    .line 621
    const/4 v11, 0x0

    .line 622
    iget-object v8, p0, Lvp/r0;->g:Ljava/lang/String;

    .line 623
    .line 624
    invoke-direct/range {v7 .. v13}, Lvp/m0;-><init>(Ljava/lang/String;Lvp/q0;ILjava/io/IOException;[BLjava/util/Map;)V

    .line 625
    .line 626
    .line 627
    invoke-virtual {v0, v7}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 628
    .line 629
    .line 630
    goto/16 :goto_27

    .line 631
    .line 632
    :catchall_a
    move-exception v0

    .line 633
    goto :goto_1c

    .line 634
    :catch_a
    move-exception v0

    .line 635
    goto :goto_1d

    .line 636
    :catchall_b
    move-exception v0

    .line 637
    move-object v7, v5

    .line 638
    :goto_1b
    if-eqz v7, :cond_c

    .line 639
    .line 640
    :try_start_16
    invoke-virtual {v7}, Ljava/io/InputStream;->close()V

    .line 641
    .line 642
    .line 643
    :cond_c
    throw v0
    :try_end_16
    .catch Ljava/io/IOException; {:try_start_16 .. :try_end_16} :catch_a
    .catchall {:try_start_16 .. :try_end_16} :catchall_a

    .line 644
    :goto_1c
    move-object v3, v0

    .line 645
    move v8, v10

    .line 646
    move-object v11, v13

    .line 647
    goto :goto_22

    .line 648
    :goto_1d
    move v9, v10

    .line 649
    move-object v12, v13

    .line 650
    :goto_1e
    move-object v10, v0

    .line 651
    goto/16 :goto_25

    .line 652
    .line 653
    :catchall_c
    move-exception v0

    .line 654
    move-object v3, v0

    .line 655
    move-object v11, v5

    .line 656
    move v8, v10

    .line 657
    goto :goto_22

    .line 658
    :catch_b
    move-exception v0

    .line 659
    move-object v12, v5

    .line 660
    move v9, v10

    .line 661
    goto :goto_1e

    .line 662
    :goto_1f
    move v8, v3

    .line 663
    move-object v11, v5

    .line 664
    goto :goto_17

    .line 665
    :goto_20
    move-object v10, v0

    .line 666
    move v9, v3

    .line 667
    move-object v12, v5

    .line 668
    goto :goto_25

    .line 669
    :catchall_d
    move-exception v0

    .line 670
    goto :goto_21

    .line 671
    :catch_c
    move-exception v0

    .line 672
    goto :goto_24

    .line 673
    :cond_d
    :try_start_17
    new-instance v0, Ljava/io/IOException;

    .line 674
    .line 675
    const-string v6, "Failed to obtain HTTP connection"

    .line 676
    .line 677
    invoke-direct {v0, v6}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 678
    .line 679
    .line 680
    throw v0
    :try_end_17
    .catch Ljava/io/IOException; {:try_start_17 .. :try_end_17} :catch_c
    .catchall {:try_start_17 .. :try_end_17} :catchall_d

    .line 681
    :goto_21
    move v8, v3

    .line 682
    move-object v6, v5

    .line 683
    move-object v11, v6

    .line 684
    goto :goto_17

    .line 685
    :goto_22
    if-eqz v5, :cond_e

    .line 686
    .line 687
    :try_start_18
    invoke-virtual {v5}, Ljava/io/OutputStream;->close()V
    :try_end_18
    .catch Ljava/io/IOException; {:try_start_18 .. :try_end_18} :catch_d

    .line 688
    .line 689
    .line 690
    goto :goto_23

    .line 691
    :catch_d
    move-exception v0

    .line 692
    iget-object v5, v4, Lvp/g1;->i:Lvp/p0;

    .line 693
    .line 694
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 695
    .line 696
    .line 697
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 698
    .line 699
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 700
    .line 701
    .line 702
    move-result-object v2

    .line 703
    invoke-virtual {v5, v2, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 704
    .line 705
    .line 706
    :cond_e
    :goto_23
    if-eqz v6, :cond_f

    .line 707
    .line 708
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 709
    .line 710
    .line 711
    :cond_f
    iget-object v0, p0, Lvp/r0;->i:Ljava/lang/Object;

    .line 712
    .line 713
    move-object v7, v0

    .line 714
    check-cast v7, Lvp/q0;

    .line 715
    .line 716
    iget-object v0, v4, Lvp/g1;->j:Lvp/e1;

    .line 717
    .line 718
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 719
    .line 720
    .line 721
    new-instance v5, Lvp/m0;

    .line 722
    .line 723
    const/4 v9, 0x0

    .line 724
    const/4 v10, 0x0

    .line 725
    iget-object v6, p0, Lvp/r0;->g:Ljava/lang/String;

    .line 726
    .line 727
    invoke-direct/range {v5 .. v11}, Lvp/m0;-><init>(Ljava/lang/String;Lvp/q0;ILjava/io/IOException;[BLjava/util/Map;)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v0, v5}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 731
    .line 732
    .line 733
    throw v3

    .line 734
    :goto_24
    move-object v10, v0

    .line 735
    move v9, v3

    .line 736
    move-object v6, v5

    .line 737
    move-object v12, v6

    .line 738
    :goto_25
    if-eqz v5, :cond_10

    .line 739
    .line 740
    :try_start_19
    invoke-virtual {v5}, Ljava/io/OutputStream;->close()V
    :try_end_19
    .catch Ljava/io/IOException; {:try_start_19 .. :try_end_19} :catch_e

    .line 741
    .line 742
    .line 743
    goto :goto_26

    .line 744
    :catch_e
    move-exception v0

    .line 745
    iget-object v3, v4, Lvp/g1;->i:Lvp/p0;

    .line 746
    .line 747
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 748
    .line 749
    .line 750
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 751
    .line 752
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 753
    .line 754
    .line 755
    move-result-object v2

    .line 756
    invoke-virtual {v3, v2, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    :cond_10
    :goto_26
    if-eqz v6, :cond_11

    .line 760
    .line 761
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 762
    .line 763
    .line 764
    :cond_11
    iget-object v0, p0, Lvp/r0;->i:Ljava/lang/Object;

    .line 765
    .line 766
    move-object v8, v0

    .line 767
    check-cast v8, Lvp/q0;

    .line 768
    .line 769
    iget-object v0, v4, Lvp/g1;->j:Lvp/e1;

    .line 770
    .line 771
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 772
    .line 773
    .line 774
    new-instance v6, Lvp/m0;

    .line 775
    .line 776
    const/4 v11, 0x0

    .line 777
    iget-object v7, p0, Lvp/r0;->g:Ljava/lang/String;

    .line 778
    .line 779
    invoke-direct/range {v6 .. v12}, Lvp/m0;-><init>(Ljava/lang/String;Lvp/q0;ILjava/io/IOException;[BLjava/util/Map;)V

    .line 780
    .line 781
    .line 782
    invoke-virtual {v0, v6}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 783
    .line 784
    .line 785
    :goto_27
    return-void

    .line 786
    nop

    .line 787
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
