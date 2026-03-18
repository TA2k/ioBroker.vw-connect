.class public final synthetic Lgr/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt01/b;
.implements Ly4/i;
.implements Lio/opentelemetry/internal/shaded/jctools/queues/MessagePassingQueue$Consumer;
.implements Lgs/e;
.implements Lj8/l;
.implements Lgt/a;
.implements Lw7/f;
.implements Laq/b;
.implements La6/f;
.implements Laq/g;
.implements Laq/f;
.implements Laq/e;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Lil/g;)Lcom/google/crypto/tink/shaded/protobuf/d;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lgr/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lpn/b;

    .line 8
    .line 9
    iget-object v2, v1, Lil/g;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Ljava/net/URL;

    .line 12
    .line 13
    const-string v3, "TRuntime."

    .line 14
    .line 15
    const-string v4, "CctTransportBackend"

    .line 16
    .line 17
    invoke-virtual {v3, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    const/4 v6, 0x4

    .line 22
    invoke-static {v5, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 23
    .line 24
    .line 25
    move-result v7

    .line 26
    if-eqz v7, :cond_0

    .line 27
    .line 28
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    const-string v8, "Making request to: %s"

    .line 33
    .line 34
    invoke-static {v8, v7}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    invoke-static {v5, v7}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    :cond_0
    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Ljava/net/HttpURLConnection;

    .line 46
    .line 47
    const/16 v5, 0x7530

    .line 48
    .line 49
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 50
    .line 51
    .line 52
    iget v5, v0, Lpn/b;->g:I

    .line 53
    .line 54
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 55
    .line 56
    .line 57
    const/4 v5, 0x1

    .line 58
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 59
    .line 60
    .line 61
    const/4 v5, 0x0

    .line 62
    invoke-virtual {v2, v5}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 63
    .line 64
    .line 65
    const-string v5, "POST"

    .line 66
    .line 67
    invoke-virtual {v2, v5}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v5, "User-Agent"

    .line 71
    .line 72
    const-string v7, "datatransport/3.3.0 android/"

    .line 73
    .line 74
    invoke-virtual {v2, v5, v7}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v5, "Content-Encoding"

    .line 78
    .line 79
    const-string v7, "gzip"

    .line 80
    .line 81
    invoke-virtual {v2, v5, v7}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const-string v8, "application/json"

    .line 85
    .line 86
    const-string v9, "Content-Type"

    .line 87
    .line 88
    invoke-virtual {v2, v9, v8}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const-string v8, "Accept-Encoding"

    .line 92
    .line 93
    invoke-virtual {v2, v8, v7}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    iget-object v8, v1, Lil/g;->g:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v8, Ljava/lang/String;

    .line 99
    .line 100
    if-eqz v8, :cond_1

    .line 101
    .line 102
    const-string v10, "X-Goog-Api-Key"

    .line 103
    .line 104
    invoke-virtual {v2, v10, v8}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    :cond_1
    :try_start_0
    invoke-virtual {v2}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 108
    .line 109
    .line 110
    move-result-object v12
    :try_end_0
    .catch Ljava/net/ConnectException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/net/UnknownHostException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Lzs/b; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 111
    :try_start_1
    new-instance v13, Ljava/util/zip/GZIPOutputStream;

    .line 112
    .line 113
    invoke-direct {v13, v12}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 114
    .line 115
    .line 116
    :try_start_2
    iget-object v0, v0, Lpn/b;->a:Lbu/c;

    .line 117
    .line 118
    iget-object v1, v1, Lil/g;->f:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v1, Lqn/m;

    .line 121
    .line 122
    new-instance v15, Ljava/io/BufferedWriter;

    .line 123
    .line 124
    new-instance v14, Ljava/io/OutputStreamWriter;

    .line 125
    .line 126
    invoke-direct {v14, v13}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;)V

    .line 127
    .line 128
    .line 129
    invoke-direct {v15, v14}, Ljava/io/BufferedWriter;-><init>(Ljava/io/Writer;)V

    .line 130
    .line 131
    .line 132
    new-instance v14, Lbt/e;

    .line 133
    .line 134
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Lbt/d;

    .line 137
    .line 138
    iget-object v8, v0, Lbt/d;->d:Ljava/util/HashMap;

    .line 139
    .line 140
    iget-object v10, v0, Lbt/d;->e:Ljava/util/HashMap;

    .line 141
    .line 142
    iget-object v11, v0, Lbt/d;->f:Lbt/a;

    .line 143
    .line 144
    iget-boolean v0, v0, Lbt/d;->g:Z

    .line 145
    .line 146
    move/from16 v19, v0

    .line 147
    .line 148
    move-object/from16 v16, v8

    .line 149
    .line 150
    move-object/from16 v17, v10

    .line 151
    .line 152
    move-object/from16 v18, v11

    .line 153
    .line 154
    invoke-direct/range {v14 .. v19}, Lbt/e;-><init>(Ljava/io/Writer;Ljava/util/Map;Ljava/util/Map;Lzs/d;Z)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v14, v1}, Lbt/e;->h(Ljava/lang/Object;)Lbt/e;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v14}, Lbt/e;->j()V

    .line 161
    .line 162
    .line 163
    iget-object v0, v14, Lbt/e;->b:Landroid/util/JsonWriter;

    .line 164
    .line 165
    invoke-virtual {v0}, Landroid/util/JsonWriter;->flush()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 166
    .line 167
    .line 168
    :try_start_3
    invoke-virtual {v13}, Ljava/io/OutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_4

    .line 169
    .line 170
    .line 171
    if-eqz v12, :cond_2

    .line 172
    .line 173
    :try_start_4
    invoke-virtual {v12}, Ljava/io/OutputStream;->close()V
    :try_end_4
    .catch Ljava/net/ConnectException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Ljava/net/UnknownHostException; {:try_start_4 .. :try_end_4} :catch_1
    .catch Lzs/b; {:try_start_4 .. :try_end_4} :catch_0
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 174
    .line 175
    .line 176
    goto :goto_0

    .line 177
    :catch_0
    move-exception v0

    .line 178
    goto/16 :goto_c

    .line 179
    .line 180
    :catch_1
    move-exception v0

    .line 181
    const-wide/16 v2, 0x0

    .line 182
    .line 183
    const/4 v6, 0x0

    .line 184
    goto/16 :goto_d

    .line 185
    .line 186
    :cond_2
    :goto_0
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-virtual {v3, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    invoke-static {v3, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 199
    .line 200
    .line 201
    move-result v6

    .line 202
    if-eqz v6, :cond_3

    .line 203
    .line 204
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    const-string v6, "Status Code: %d"

    .line 209
    .line 210
    invoke-static {v6, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    invoke-static {v3, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 215
    .line 216
    .line 217
    :cond_3
    const-string v1, "Content-Type: %s"

    .line 218
    .line 219
    invoke-virtual {v2, v9}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    invoke-static {v3, v4, v1}, Llp/wb;->b(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string v1, "Content-Encoding: %s"

    .line 227
    .line 228
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    invoke-static {v3, v4, v1}, Llp/wb;->b(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    const/16 v1, 0x12e

    .line 236
    .line 237
    if-eq v0, v1, :cond_b

    .line 238
    .line 239
    const/16 v1, 0x12d

    .line 240
    .line 241
    if-eq v0, v1, :cond_b

    .line 242
    .line 243
    const/16 v1, 0x133

    .line 244
    .line 245
    if-ne v0, v1, :cond_4

    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_4
    const/16 v1, 0xc8

    .line 249
    .line 250
    if-eq v0, v1, :cond_5

    .line 251
    .line 252
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 253
    .line 254
    const-wide/16 v2, 0x0

    .line 255
    .line 256
    const/4 v4, 0x0

    .line 257
    invoke-direct {v1, v0, v4, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(ILjava/net/URL;J)V

    .line 258
    .line 259
    .line 260
    return-object v1

    .line 261
    :cond_5
    invoke-virtual {v2}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 262
    .line 263
    .line 264
    move-result-object v1

    .line 265
    :try_start_5
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v2

    .line 269
    invoke-virtual {v7, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v2

    .line 273
    if-eqz v2, :cond_6

    .line 274
    .line 275
    new-instance v2, Ljava/util/zip/GZIPInputStream;

    .line 276
    .line 277
    invoke-direct {v2, v1}, Ljava/util/zip/GZIPInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 278
    .line 279
    .line 280
    goto :goto_1

    .line 281
    :cond_6
    move-object v2, v1

    .line 282
    :goto_1
    :try_start_6
    new-instance v3, Ljava/io/BufferedReader;

    .line 283
    .line 284
    new-instance v4, Ljava/io/InputStreamReader;

    .line 285
    .line 286
    invoke-direct {v4, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 287
    .line 288
    .line 289
    invoke-direct {v3, v4}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 290
    .line 291
    .line 292
    invoke-static {v3}, Lqn/v;->a(Ljava/io/BufferedReader;)Lqn/v;

    .line 293
    .line 294
    .line 295
    move-result-object v3

    .line 296
    iget-wide v3, v3, Lqn/v;->a:J

    .line 297
    .line 298
    new-instance v5, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 299
    .line 300
    const/4 v6, 0x0

    .line 301
    invoke-direct {v5, v0, v6, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(ILjava/net/URL;J)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 302
    .line 303
    .line 304
    if-eqz v2, :cond_7

    .line 305
    .line 306
    :try_start_7
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 307
    .line 308
    .line 309
    goto :goto_2

    .line 310
    :catchall_0
    move-exception v0

    .line 311
    move-object v2, v0

    .line 312
    goto :goto_4

    .line 313
    :cond_7
    :goto_2
    if-eqz v1, :cond_8

    .line 314
    .line 315
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    .line 316
    .line 317
    .line 318
    :cond_8
    return-object v5

    .line 319
    :catchall_1
    move-exception v0

    .line 320
    move-object v3, v0

    .line 321
    if-eqz v2, :cond_9

    .line 322
    .line 323
    :try_start_8
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 324
    .line 325
    .line 326
    goto :goto_3

    .line 327
    :catchall_2
    move-exception v0

    .line 328
    :try_start_9
    invoke-virtual {v3, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 329
    .line 330
    .line 331
    :cond_9
    :goto_3
    throw v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 332
    :goto_4
    if-eqz v1, :cond_a

    .line 333
    .line 334
    :try_start_a
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 335
    .line 336
    .line 337
    goto :goto_5

    .line 338
    :catchall_3
    move-exception v0

    .line 339
    invoke-virtual {v2, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 340
    .line 341
    .line 342
    :cond_a
    :goto_5
    throw v2

    .line 343
    :cond_b
    :goto_6
    const-string v1, "Location"

    .line 344
    .line 345
    invoke-virtual {v2, v1}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    new-instance v2, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 350
    .line 351
    new-instance v3, Ljava/net/URL;

    .line 352
    .line 353
    invoke-direct {v3, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    const-wide/16 v4, 0x0

    .line 357
    .line 358
    invoke-direct {v2, v0, v3, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(ILjava/net/URL;J)V

    .line 359
    .line 360
    .line 361
    return-object v2

    .line 362
    :catchall_4
    move-exception v0

    .line 363
    move-object v1, v0

    .line 364
    goto :goto_a

    .line 365
    :goto_7
    move-object v1, v0

    .line 366
    goto :goto_8

    .line 367
    :catchall_5
    move-exception v0

    .line 368
    goto :goto_7

    .line 369
    :goto_8
    :try_start_b
    invoke-virtual {v13}, Ljava/io/OutputStream;->close()V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 370
    .line 371
    .line 372
    goto :goto_9

    .line 373
    :catchall_6
    move-exception v0

    .line 374
    :try_start_c
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 375
    .line 376
    .line 377
    :goto_9
    throw v1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_4

    .line 378
    :goto_a
    if-eqz v12, :cond_c

    .line 379
    .line 380
    :try_start_d
    invoke-virtual {v12}, Ljava/io/OutputStream;->close()V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_7

    .line 381
    .line 382
    .line 383
    goto :goto_b

    .line 384
    :catchall_7
    move-exception v0

    .line 385
    :try_start_e
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 386
    .line 387
    .line 388
    :cond_c
    :goto_b
    throw v1
    :try_end_e
    .catch Ljava/net/ConnectException; {:try_start_e .. :try_end_e} :catch_1
    .catch Ljava/net/UnknownHostException; {:try_start_e .. :try_end_e} :catch_1
    .catch Lzs/b; {:try_start_e .. :try_end_e} :catch_0
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_0

    .line 389
    :goto_c
    const-string v1, "Couldn\'t encode request, returning with 400"

    .line 390
    .line 391
    invoke-static {v4, v1, v0}, Llp/wb;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Exception;)V

    .line 392
    .line 393
    .line 394
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 395
    .line 396
    const/16 v1, 0x190

    .line 397
    .line 398
    const-wide/16 v2, 0x0

    .line 399
    .line 400
    const/4 v6, 0x0

    .line 401
    invoke-direct {v0, v1, v6, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(ILjava/net/URL;J)V

    .line 402
    .line 403
    .line 404
    goto :goto_e

    .line 405
    :goto_d
    const-string v1, "Couldn\'t open connection, returning with 500"

    .line 406
    .line 407
    invoke-static {v4, v1, v0}, Llp/wb;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Exception;)V

    .line 408
    .line 409
    .line 410
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 411
    .line 412
    const/16 v1, 0x1f4

    .line 413
    .line 414
    invoke-direct {v0, v1, v6, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/d;-><init>(ILjava/net/URL;J)V

    .line 415
    .line 416
    .line 417
    :goto_e
    return-object v0
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lhr/e0;

    .line 9
    .line 10
    check-cast p1, Ll9/a;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p0, Ljava/util/function/Consumer;

    .line 17
    .line 18
    invoke-interface {p0, p1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lgt/b;)V
    .locals 4

    .line 1
    iget v0, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljs/b;

    .line 9
    .line 10
    invoke-interface {p1}, Lgt/b;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Lfu/a;

    .line 15
    .line 16
    const-string v0, "firebase"

    .line 17
    .line 18
    check-cast p1, Lcu/j;

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Lcu/j;->a(Ljava/lang/String;)Lcu/b;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget-object p1, p1, Lcu/b;->k:Lcom/google/firebase/messaging/w;

    .line 25
    .line 26
    iget-object v0, p1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Ljava/util/Set;

    .line 29
    .line 30
    invoke-interface {v0, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    iget-object v0, p1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Ldu/c;

    .line 36
    .line 37
    invoke-virtual {v0}, Ldu/c;->b()Laq/j;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-object v1, p1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Ljava/util/concurrent/Executor;

    .line 44
    .line 45
    new-instance v2, Lbb/i;

    .line 46
    .line 47
    const/4 v3, 0x6

    .line 48
    invoke-direct {v2, p1, v0, p0, v3}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0, v1, v2}, Laq/j;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 52
    .line 53
    .line 54
    const-string p0, "FirebaseCrashlytics"

    .line 55
    .line 56
    const/4 p1, 0x3

    .line 57
    invoke-static {p0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-eqz p1, :cond_0

    .line 62
    .line 63
    const-string p1, "Registering RemoteConfig Rollouts subscriber"

    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    invoke-static {p0, p1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 67
    .line 68
    .line 69
    :cond_0
    return-void

    .line 70
    :pswitch_0
    check-cast p0, Ljs/a;

    .line 71
    .line 72
    const-string v0, "FirebaseCrashlytics"

    .line 73
    .line 74
    const/4 v1, 0x3

    .line 75
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_1

    .line 80
    .line 81
    const-string v1, "Crashlytics native component now available."

    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static {v0, v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 85
    .line 86
    .line 87
    :cond_1
    iget-object p0, p0, Ljs/a;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 88
    .line 89
    invoke-interface {p1}, Lgt/b;->get()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    check-cast p1, Ljs/a;

    .line 94
    .line 95
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_0
    .end packed-switch
.end method

.method public c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lpg/m;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lpg/m;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public d(ILt7/q0;[I)Lhr/x0;
    .locals 6

    .line 1
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v4, p0

    .line 4
    check-cast v4, Lj8/i;

    .line 5
    .line 6
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const/4 v0, 0x0

    .line 11
    move v3, v0

    .line 12
    :goto_0
    iget v0, p2, Lt7/q0;->a:I

    .line 13
    .line 14
    if-ge v3, v0, :cond_0

    .line 15
    .line 16
    new-instance v0, Lj8/f;

    .line 17
    .line 18
    aget v5, p3, v3

    .line 19
    .line 20
    move v1, p1

    .line 21
    move-object v2, p2

    .line 22
    invoke-direct/range {v0 .. v5}, Lj8/f;-><init>(ILt7/q0;ILj8/i;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {p0}, Lhr/e0;->i()Lhr/x0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 53

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lgr/k;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;

    .line 8
    .line 9
    sget v2, Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;->d:I

    .line 10
    .line 11
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    const-class v4, Lsr/f;

    .line 16
    .line 17
    invoke-virtual {v1, v4}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    move-object v6, v4

    .line 22
    check-cast v6, Lsr/f;

    .line 23
    .line 24
    const-class v4, Lht/d;

    .line 25
    .line 26
    invoke-virtual {v1, v4}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    check-cast v4, Lht/d;

    .line 31
    .line 32
    const-class v5, Ljs/a;

    .line 33
    .line 34
    invoke-virtual {v1, v5}, Lin/z1;->H(Ljava/lang/Class;)Lgs/q;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    const-class v7, Lwr/b;

    .line 39
    .line 40
    invoke-virtual {v1, v7}, Lin/z1;->H(Ljava/lang/Class;)Lgs/q;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    const-class v8, Lfu/a;

    .line 45
    .line 46
    invoke-virtual {v1, v8}, Lin/z1;->H(Ljava/lang/Class;)Lgs/q;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    iget-object v9, v0, Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;->a:Lgs/s;

    .line 51
    .line 52
    invoke-virtual {v1, v9}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    check-cast v9, Ljava/util/concurrent/ExecutorService;

    .line 57
    .line 58
    iget-object v10, v0, Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;->b:Lgs/s;

    .line 59
    .line 60
    invoke-virtual {v1, v10}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v10

    .line 64
    check-cast v10, Ljava/util/concurrent/ExecutorService;

    .line 65
    .line 66
    iget-object v0, v0, Lcom/google/firebase/crashlytics/CrashlyticsRegistrar;->c:Lgs/s;

    .line 67
    .line 68
    invoke-virtual {v1, v0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast v0, Ljava/util/concurrent/ExecutorService;

    .line 73
    .line 74
    const-string v1, ""

    .line 75
    .line 76
    const-string v11, "FirebaseCrashlytics"

    .line 77
    .line 78
    invoke-virtual {v6}, Lsr/f;->a()V

    .line 79
    .line 80
    .line 81
    iget-object v12, v6, Lsr/f;->a:Landroid/content/Context;

    .line 82
    .line 83
    invoke-virtual {v12}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v13

    .line 87
    new-instance v14, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v15, "Initializing Firebase Crashlytics 20.0.3 for "

    .line 90
    .line 91
    invoke-direct {v14, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v14, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v14

    .line 101
    const/4 v15, 0x0

    .line 102
    invoke-static {v11, v14, v15}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 103
    .line 104
    .line 105
    new-instance v14, Lns/d;

    .line 106
    .line 107
    invoke-direct {v14, v9, v10}, Lns/d;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/ExecutorService;)V

    .line 108
    .line 109
    .line 110
    new-instance v9, Lss/b;

    .line 111
    .line 112
    invoke-direct {v9, v12}, Lss/b;-><init>(Landroid/content/Context;)V

    .line 113
    .line 114
    .line 115
    new-instance v10, Lh8/o;

    .line 116
    .line 117
    invoke-direct {v10, v6}, Lh8/o;-><init>(Lsr/f;)V

    .line 118
    .line 119
    .line 120
    new-instance v15, Lms/u;

    .line 121
    .line 122
    invoke-direct {v15, v12, v13, v4, v10}, Lms/u;-><init>(Landroid/content/Context;Ljava/lang/String;Lht/d;Lh8/o;)V

    .line 123
    .line 124
    .line 125
    new-instance v4, Ljs/a;

    .line 126
    .line 127
    invoke-direct {v4, v5}, Ljs/a;-><init>(Lgs/q;)V

    .line 128
    .line 129
    .line 130
    new-instance v5, Lis/b;

    .line 131
    .line 132
    invoke-direct {v5, v7}, Lis/b;-><init>(Lgs/q;)V

    .line 133
    .line 134
    .line 135
    new-instance v13, Lms/i;

    .line 136
    .line 137
    invoke-direct {v13, v10, v9}, Lms/i;-><init>(Lh8/o;Lss/b;)V

    .line 138
    .line 139
    .line 140
    sget-object v7, Liu/c;->a:Liu/c;

    .line 141
    .line 142
    const-string v7, "Subscriber "

    .line 143
    .line 144
    move-wide/from16 v26, v2

    .line 145
    .line 146
    const-string v2, "FirebaseSessions"

    .line 147
    .line 148
    sget-object v3, Liu/d;->d:Liu/d;

    .line 149
    .line 150
    sget-object v16, Liu/c;->a:Liu/c;

    .line 151
    .line 152
    move-object/from16 p1, v4

    .line 153
    .line 154
    invoke-static {v3}, Liu/c;->a(Liu/d;)Liu/a;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    move-object/from16 v16, v6

    .line 159
    .line 160
    iget-object v6, v4, Liu/a;->b:Lms/i;

    .line 161
    .line 162
    if-eqz v6, :cond_0

    .line 163
    .line 164
    new-instance v4, Ljava/lang/StringBuilder;

    .line 165
    .line 166
    invoke-direct {v4, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    const-string v3, " already registered."

    .line 173
    .line 174
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    invoke-static {v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    const/4 v3, 0x0

    .line 185
    :goto_0
    move-object/from16 v21, v15

    .line 186
    .line 187
    move-object v15, v14

    .line 188
    goto :goto_1

    .line 189
    :cond_0
    iput-object v13, v4, Liu/a;->b:Lms/i;

    .line 190
    .line 191
    new-instance v6, Ljava/lang/StringBuilder;

    .line 192
    .line 193
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    const-string v3, " registered."

    .line 200
    .line 201
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    invoke-static {v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 209
    .line 210
    .line 211
    iget-object v2, v4, Liu/a;->a:Lez0/c;

    .line 212
    .line 213
    const/4 v3, 0x0

    .line 214
    invoke-virtual {v2, v3}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    goto :goto_0

    .line 218
    :goto_1
    new-instance v14, Lhu/q;

    .line 219
    .line 220
    const/16 v2, 0x8

    .line 221
    .line 222
    invoke-direct {v14, v8, v2}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    new-instance v2, Lms/p;

    .line 226
    .line 227
    move-object v4, v12

    .line 228
    move-object v12, v9

    .line 229
    move-object v9, v10

    .line 230
    new-instance v10, Lis/a;

    .line 231
    .line 232
    invoke-direct {v10, v5}, Lis/a;-><init>(Lis/b;)V

    .line 233
    .line 234
    .line 235
    move-object v6, v11

    .line 236
    new-instance v11, Lis/a;

    .line 237
    .line 238
    invoke-direct {v11, v5}, Lis/a;-><init>(Lis/b;)V

    .line 239
    .line 240
    .line 241
    move-object/from16 v8, p1

    .line 242
    .line 243
    move-object v5, v2

    .line 244
    move-object v2, v6

    .line 245
    move-object/from16 v6, v16

    .line 246
    .line 247
    move-object/from16 v7, v21

    .line 248
    .line 249
    invoke-direct/range {v5 .. v15}, Lms/p;-><init>(Lsr/f;Lms/u;Ljs/a;Lh8/o;Lis/a;Lis/a;Lss/b;Lms/i;Lhu/q;Lns/d;)V

    .line 250
    .line 251
    .line 252
    iget-object v7, v5, Lms/p;->p:Lns/d;

    .line 253
    .line 254
    invoke-virtual {v6}, Lsr/f;->a()V

    .line 255
    .line 256
    .line 257
    iget-object v6, v6, Lsr/f;->c:Lsr/i;

    .line 258
    .line 259
    iget-object v6, v6, Lsr/i;->b:Ljava/lang/String;

    .line 260
    .line 261
    const-string v8, "com.google.firebase.crashlytics.mapping_file_id"

    .line 262
    .line 263
    const-string v10, "string"

    .line 264
    .line 265
    invoke-static {v4, v8, v10}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    move-result v8

    .line 269
    if-nez v8, :cond_1

    .line 270
    .line 271
    const-string v8, "com.crashlytics.android.build_id"

    .line 272
    .line 273
    invoke-static {v4, v8, v10}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 274
    .line 275
    .line 276
    move-result v8

    .line 277
    :cond_1
    if-eqz v8, :cond_2

    .line 278
    .line 279
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 280
    .line 281
    .line 282
    move-result-object v10

    .line 283
    invoke-virtual {v10, v8}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v8

    .line 287
    goto :goto_2

    .line 288
    :cond_2
    move-object v8, v3

    .line 289
    :goto_2
    new-instance v10, Ljava/util/ArrayList;

    .line 290
    .line 291
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 292
    .line 293
    .line 294
    const-string v11, "com.google.firebase.crashlytics.build_ids_lib"

    .line 295
    .line 296
    const-string v13, "array"

    .line 297
    .line 298
    invoke-static {v4, v11, v13}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 299
    .line 300
    .line 301
    move-result v11

    .line 302
    const-string v14, "com.google.firebase.crashlytics.build_ids_arch"

    .line 303
    .line 304
    invoke-static {v4, v14, v13}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 305
    .line 306
    .line 307
    move-result v14

    .line 308
    const-string v3, "com.google.firebase.crashlytics.build_ids_build_id"

    .line 309
    .line 310
    invoke-static {v4, v3, v13}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 311
    .line 312
    .line 313
    move-result v3

    .line 314
    if-eqz v11, :cond_3

    .line 315
    .line 316
    if-eqz v14, :cond_3

    .line 317
    .line 318
    if-nez v3, :cond_4

    .line 319
    .line 320
    :cond_3
    move-object/from16 v38, v5

    .line 321
    .line 322
    move-object/from16 v29, v6

    .line 323
    .line 324
    move-object/from16 v37, v7

    .line 325
    .line 326
    goto/16 :goto_6

    .line 327
    .line 328
    :cond_4
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 329
    .line 330
    .line 331
    move-result-object v13

    .line 332
    invoke-virtual {v13, v11}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v11

    .line 336
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 337
    .line 338
    .line 339
    move-result-object v13

    .line 340
    invoke-virtual {v13, v14}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v13

    .line 344
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 345
    .line 346
    .line 347
    move-result-object v14

    .line 348
    invoke-virtual {v14, v3}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object v3

    .line 352
    array-length v14, v11

    .line 353
    move-object/from16 v29, v6

    .line 354
    .line 355
    array-length v6, v3

    .line 356
    if-ne v14, v6, :cond_5

    .line 357
    .line 358
    array-length v6, v13

    .line 359
    array-length v14, v3

    .line 360
    if-eq v6, v14, :cond_6

    .line 361
    .line 362
    :cond_5
    move-object/from16 v38, v5

    .line 363
    .line 364
    move-object/from16 v37, v7

    .line 365
    .line 366
    goto :goto_5

    .line 367
    :cond_6
    const/4 v6, 0x0

    .line 368
    :goto_3
    array-length v14, v3

    .line 369
    if-ge v6, v14, :cond_7

    .line 370
    .line 371
    new-instance v14, Lms/c;

    .line 372
    .line 373
    move/from16 v16, v6

    .line 374
    .line 375
    aget-object v6, v11, v16

    .line 376
    .line 377
    move-object/from16 v37, v7

    .line 378
    .line 379
    aget-object v7, v13, v16

    .line 380
    .line 381
    move-object/from16 v38, v5

    .line 382
    .line 383
    aget-object v5, v3, v16

    .line 384
    .line 385
    invoke-direct {v14, v6, v7, v5}, Lms/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v10, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    add-int/lit8 v6, v16, 0x1

    .line 392
    .line 393
    move-object/from16 v7, v37

    .line 394
    .line 395
    move-object/from16 v5, v38

    .line 396
    .line 397
    goto :goto_3

    .line 398
    :cond_7
    move-object/from16 v38, v5

    .line 399
    .line 400
    move-object/from16 v37, v7

    .line 401
    .line 402
    :cond_8
    :goto_4
    const/4 v5, 0x3

    .line 403
    :cond_9
    const/4 v6, 0x0

    .line 404
    goto :goto_7

    .line 405
    :goto_5
    const-string v5, "Lengths did not match: %d %d %d"

    .line 406
    .line 407
    array-length v6, v11

    .line 408
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    array-length v7, v13

    .line 413
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 414
    .line 415
    .line 416
    move-result-object v7

    .line 417
    array-length v3, v3

    .line 418
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 419
    .line 420
    .line 421
    move-result-object v3

    .line 422
    filled-new-array {v6, v7, v3}, [Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v3

    .line 426
    invoke-static {v5, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v3

    .line 430
    const/4 v5, 0x3

    .line 431
    invoke-static {v2, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 432
    .line 433
    .line 434
    move-result v6

    .line 435
    if-eqz v6, :cond_8

    .line 436
    .line 437
    const/4 v5, 0x0

    .line 438
    invoke-static {v2, v3, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 439
    .line 440
    .line 441
    goto :goto_4

    .line 442
    :goto_6
    const-string v5, "Could not find resources: %d %d %d"

    .line 443
    .line 444
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 445
    .line 446
    .line 447
    move-result-object v6

    .line 448
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 449
    .line 450
    .line 451
    move-result-object v7

    .line 452
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 453
    .line 454
    .line 455
    move-result-object v3

    .line 456
    filled-new-array {v6, v7, v3}, [Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v3

    .line 460
    invoke-static {v5, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 461
    .line 462
    .line 463
    move-result-object v3

    .line 464
    const/4 v5, 0x3

    .line 465
    invoke-static {v2, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 466
    .line 467
    .line 468
    move-result v6

    .line 469
    if-eqz v6, :cond_9

    .line 470
    .line 471
    const/4 v6, 0x0

    .line 472
    invoke-static {v2, v3, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 473
    .line 474
    .line 475
    :goto_7
    const-string v3, "Mapping file ID is: "

    .line 476
    .line 477
    invoke-static {v3, v8}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 478
    .line 479
    .line 480
    move-result-object v3

    .line 481
    invoke-static {v2, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 482
    .line 483
    .line 484
    move-result v7

    .line 485
    if-eqz v7, :cond_a

    .line 486
    .line 487
    invoke-static {v2, v3, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 488
    .line 489
    .line 490
    :cond_a
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 491
    .line 492
    .line 493
    move-result-object v3

    .line 494
    :cond_b
    :goto_8
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 495
    .line 496
    .line 497
    move-result v5

    .line 498
    if-eqz v5, :cond_c

    .line 499
    .line 500
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v5

    .line 504
    check-cast v5, Lms/c;

    .line 505
    .line 506
    iget-object v6, v5, Lms/c;->a:Ljava/lang/String;

    .line 507
    .line 508
    iget-object v7, v5, Lms/c;->b:Ljava/lang/String;

    .line 509
    .line 510
    iget-object v5, v5, Lms/c;->c:Ljava/lang/String;

    .line 511
    .line 512
    const-string v11, "Build id for "

    .line 513
    .line 514
    const-string v13, " on "

    .line 515
    .line 516
    const-string v14, ": "

    .line 517
    .line 518
    invoke-static {v11, v6, v13, v7, v14}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 519
    .line 520
    .line 521
    move-result-object v6

    .line 522
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 523
    .line 524
    .line 525
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 526
    .line 527
    .line 528
    move-result-object v5

    .line 529
    const/4 v6, 0x3

    .line 530
    invoke-static {v2, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 531
    .line 532
    .line 533
    move-result v7

    .line 534
    if-eqz v7, :cond_b

    .line 535
    .line 536
    const/4 v6, 0x0

    .line 537
    invoke-static {v2, v5, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 538
    .line 539
    .line 540
    goto :goto_8

    .line 541
    :cond_c
    new-instance v3, Lb81/d;

    .line 542
    .line 543
    const/16 v5, 0xa

    .line 544
    .line 545
    invoke-direct {v3, v4, v5}, Lb81/d;-><init>(Landroid/content/Context;I)V

    .line 546
    .line 547
    .line 548
    :try_start_0
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 549
    .line 550
    .line 551
    move-result-object v5

    .line 552
    invoke-virtual/range {v21 .. v21}, Lms/u;->d()Ljava/lang/String;

    .line 553
    .line 554
    .line 555
    move-result-object v32

    .line 556
    invoke-virtual {v4}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 557
    .line 558
    .line 559
    move-result-object v6

    .line 560
    const/4 v7, 0x0

    .line 561
    invoke-virtual {v6, v5, v7}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 562
    .line 563
    .line 564
    move-result-object v6

    .line 565
    invoke-virtual {v6}, Landroid/content/pm/PackageInfo;->getLongVersionCode()J

    .line 566
    .line 567
    .line 568
    move-result-wide v13

    .line 569
    invoke-static {v13, v14}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 570
    .line 571
    .line 572
    move-result-object v34

    .line 573
    iget-object v6, v6, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;

    .line 574
    .line 575
    if-nez v6, :cond_d

    .line 576
    .line 577
    const-string v6, "0.0"

    .line 578
    .line 579
    :cond_d
    move-object/from16 v35, v6

    .line 580
    .line 581
    new-instance v45, Lcom/google/android/material/datepicker/d;

    .line 582
    .line 583
    move-object/from16 v36, v3

    .line 584
    .line 585
    move-object/from16 v33, v5

    .line 586
    .line 587
    move-object/from16 v30, v8

    .line 588
    .line 589
    move-object/from16 v31, v10

    .line 590
    .line 591
    move-object/from16 v28, v45

    .line 592
    .line 593
    invoke-direct/range {v28 .. v36}, Lcom/google/android/material/datepicker/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lb81/d;)V
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_2

    .line 594
    .line 595
    .line 596
    move-object/from16 v8, v28

    .line 597
    .line 598
    move-object/from16 v3, v29

    .line 599
    .line 600
    move-object/from16 v5, v32

    .line 601
    .line 602
    move-object/from16 v6, v34

    .line 603
    .line 604
    move-object/from16 v7, v35

    .line 605
    .line 606
    const-string v10, "Installer package name is: "

    .line 607
    .line 608
    invoke-static {v10, v5}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 609
    .line 610
    .line 611
    move-result-object v5

    .line 612
    const/4 v10, 0x2

    .line 613
    invoke-static {v2, v10}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 614
    .line 615
    .line 616
    move-result v11

    .line 617
    if-eqz v11, :cond_e

    .line 618
    .line 619
    const/4 v11, 0x0

    .line 620
    invoke-static {v2, v5, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 621
    .line 622
    .line 623
    :cond_e
    new-instance v5, Lwq/f;

    .line 624
    .line 625
    const/16 v11, 0xc

    .line 626
    .line 627
    invoke-direct {v5, v11}, Lwq/f;-><init>(I)V

    .line 628
    .line 629
    .line 630
    invoke-virtual/range {v21 .. v21}, Lms/u;->d()Ljava/lang/String;

    .line 631
    .line 632
    .line 633
    move-result-object v11

    .line 634
    new-instance v13, Lwe0/b;

    .line 635
    .line 636
    const/16 v14, 0x9

    .line 637
    .line 638
    invoke-direct {v13, v14}, Lwe0/b;-><init>(I)V

    .line 639
    .line 640
    .line 641
    new-instance v14, Lro/f;

    .line 642
    .line 643
    const/4 v10, 0x4

    .line 644
    invoke-direct {v14, v13, v10}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 645
    .line 646
    .line 647
    new-instance v10, Lpv/g;

    .line 648
    .line 649
    invoke-direct {v10, v12}, Lpv/g;-><init>(Lss/b;)V

    .line 650
    .line 651
    .line 652
    sget-object v12, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 653
    .line 654
    const-string v12, "https://firebase-settings.crashlytics.com/spi/v2/platforms/android/gmp/"

    .line 655
    .line 656
    move-object/from16 v16, v11

    .line 657
    .line 658
    const-string v11, "/settings"

    .line 659
    .line 660
    invoke-static {v12, v3, v11}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 661
    .line 662
    .line 663
    move-result-object v11

    .line 664
    new-instance v12, Lj51/i;

    .line 665
    .line 666
    invoke-direct {v12, v11, v5}, Lj51/i;-><init>(Ljava/lang/String;Lwq/f;)V

    .line 667
    .line 668
    .line 669
    sget-object v5, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 670
    .line 671
    sget-object v11, Lms/u;->h:Ljava/lang/String;

    .line 672
    .line 673
    move-object/from16 v30, v2

    .line 674
    .line 675
    const-string v2, ""

    .line 676
    .line 677
    invoke-virtual {v5, v11, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 678
    .line 679
    .line 680
    move-result-object v2

    .line 681
    sget-object v5, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 682
    .line 683
    move-object/from16 v42, v8

    .line 684
    .line 685
    const-string v8, ""

    .line 686
    .line 687
    invoke-virtual {v5, v11, v8}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 688
    .line 689
    .line 690
    move-result-object v5

    .line 691
    const-string v8, "/"

    .line 692
    .line 693
    invoke-static {v2, v8, v5}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 694
    .line 695
    .line 696
    move-result-object v18

    .line 697
    sget-object v2, Landroid/os/Build$VERSION;->INCREMENTAL:Ljava/lang/String;

    .line 698
    .line 699
    const-string v5, ""

    .line 700
    .line 701
    invoke-virtual {v2, v11, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v19

    .line 705
    sget-object v2, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 706
    .line 707
    const-string v5, ""

    .line 708
    .line 709
    invoke-virtual {v2, v11, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 710
    .line 711
    .line 712
    move-result-object v20

    .line 713
    const-string v2, "com.google.firebase.crashlytics.mapping_file_id"

    .line 714
    .line 715
    const-string v5, "string"

    .line 716
    .line 717
    invoke-static {v4, v2, v5}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 718
    .line 719
    .line 720
    move-result v2

    .line 721
    if-nez v2, :cond_f

    .line 722
    .line 723
    const-string v2, "com.crashlytics.android.build_id"

    .line 724
    .line 725
    invoke-static {v4, v2, v5}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 726
    .line 727
    .line 728
    move-result v2

    .line 729
    :cond_f
    if-eqz v2, :cond_10

    .line 730
    .line 731
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 732
    .line 733
    .line 734
    move-result-object v5

    .line 735
    invoke-virtual {v5, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 736
    .line 737
    .line 738
    move-result-object v2

    .line 739
    goto :goto_9

    .line 740
    :cond_10
    const/4 v2, 0x0

    .line 741
    :goto_9
    filled-new-array {v2, v3, v7, v6}, [Ljava/lang/String;

    .line 742
    .line 743
    .line 744
    move-result-object v2

    .line 745
    new-instance v5, Ljava/util/ArrayList;

    .line 746
    .line 747
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 748
    .line 749
    .line 750
    const/4 v8, 0x0

    .line 751
    :goto_a
    const/4 v11, 0x4

    .line 752
    if-ge v8, v11, :cond_12

    .line 753
    .line 754
    aget-object v11, v2, v8

    .line 755
    .line 756
    move-object/from16 v17, v2

    .line 757
    .line 758
    if-eqz v11, :cond_11

    .line 759
    .line 760
    const-string v2, "-"

    .line 761
    .line 762
    invoke-virtual {v11, v2, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 763
    .line 764
    .line 765
    move-result-object v2

    .line 766
    sget-object v11, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 767
    .line 768
    invoke-virtual {v2, v11}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 769
    .line 770
    .line 771
    move-result-object v2

    .line 772
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 773
    .line 774
    .line 775
    :cond_11
    add-int/lit8 v8, v8, 0x1

    .line 776
    .line 777
    move-object/from16 v2, v17

    .line 778
    .line 779
    goto :goto_a

    .line 780
    :cond_12
    invoke-static {v5}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 781
    .line 782
    .line 783
    new-instance v2, Ljava/lang/StringBuilder;

    .line 784
    .line 785
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 786
    .line 787
    .line 788
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 789
    .line 790
    .line 791
    move-result-object v5

    .line 792
    :goto_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 793
    .line 794
    .line 795
    move-result v8

    .line 796
    if-eqz v8, :cond_13

    .line 797
    .line 798
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 799
    .line 800
    .line 801
    move-result-object v8

    .line 802
    check-cast v8, Ljava/lang/String;

    .line 803
    .line 804
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 805
    .line 806
    .line 807
    goto :goto_b

    .line 808
    :cond_13
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 809
    .line 810
    .line 811
    move-result-object v2

    .line 812
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 813
    .line 814
    .line 815
    move-result v5

    .line 816
    if-lez v5, :cond_14

    .line 817
    .line 818
    invoke-static {v2}, Lms/f;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 819
    .line 820
    .line 821
    move-result-object v2

    .line 822
    move-object/from16 v22, v2

    .line 823
    .line 824
    goto :goto_c

    .line 825
    :cond_14
    const/16 v22, 0x0

    .line 826
    .line 827
    :goto_c
    const/4 v11, 0x1

    .line 828
    if-eqz v16, :cond_15

    .line 829
    .line 830
    const/4 v2, 0x4

    .line 831
    goto :goto_d

    .line 832
    :cond_15
    move v2, v11

    .line 833
    :goto_d
    invoke-static {v2}, Lkx/a;->a(I)I

    .line 834
    .line 835
    .line 836
    move-result v25

    .line 837
    new-instance v16, Lus/c;

    .line 838
    .line 839
    move-object/from16 v17, v3

    .line 840
    .line 841
    move-object/from16 v24, v6

    .line 842
    .line 843
    move-object/from16 v23, v7

    .line 844
    .line 845
    invoke-direct/range {v16 .. v25}, Lus/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lms/u;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 846
    .line 847
    .line 848
    move-object/from16 v2, v16

    .line 849
    .line 850
    new-instance v3, Lqn/s;

    .line 851
    .line 852
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 853
    .line 854
    .line 855
    new-instance v5, Ljava/util/concurrent/atomic/AtomicReference;

    .line 856
    .line 857
    invoke-direct {v5}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 858
    .line 859
    .line 860
    iput-object v5, v3, Lqn/s;->h:Ljava/lang/Object;

    .line 861
    .line 862
    new-instance v6, Ljava/util/concurrent/atomic/AtomicReference;

    .line 863
    .line 864
    new-instance v7, Laq/k;

    .line 865
    .line 866
    invoke-direct {v7}, Laq/k;-><init>()V

    .line 867
    .line 868
    .line 869
    invoke-direct {v6, v7}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 870
    .line 871
    .line 872
    iput-object v6, v3, Lqn/s;->i:Ljava/lang/Object;

    .line 873
    .line 874
    iput-object v4, v3, Lqn/s;->a:Ljava/lang/Object;

    .line 875
    .line 876
    iput-object v2, v3, Lqn/s;->b:Ljava/lang/Object;

    .line 877
    .line 878
    iput-object v13, v3, Lqn/s;->d:Ljava/lang/Object;

    .line 879
    .line 880
    iput-object v14, v3, Lqn/s;->c:Ljava/lang/Object;

    .line 881
    .line 882
    iput-object v10, v3, Lqn/s;->e:Ljava/lang/Object;

    .line 883
    .line 884
    iput-object v12, v3, Lqn/s;->f:Ljava/lang/Object;

    .line 885
    .line 886
    iput-object v9, v3, Lqn/s;->g:Ljava/lang/Object;

    .line 887
    .line 888
    invoke-static {v13}, La61/a;->o(Lwe0/b;)Lus/a;

    .line 889
    .line 890
    .line 891
    move-result-object v2

    .line 892
    invoke-virtual {v5, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 893
    .line 894
    .line 895
    iget-object v2, v3, Lqn/s;->i:Ljava/lang/Object;

    .line 896
    .line 897
    check-cast v2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 898
    .line 899
    iget-object v4, v3, Lqn/s;->h:Ljava/lang/Object;

    .line 900
    .line 901
    check-cast v4, Ljava/util/concurrent/atomic/AtomicReference;

    .line 902
    .line 903
    iget-object v5, v3, Lqn/s;->a:Ljava/lang/Object;

    .line 904
    .line 905
    check-cast v5, Landroid/content/Context;

    .line 906
    .line 907
    const-string v6, "com.google.firebase.crashlytics"

    .line 908
    .line 909
    const/4 v7, 0x0

    .line 910
    invoke-virtual {v5, v6, v7}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 911
    .line 912
    .line 913
    move-result-object v5

    .line 914
    const-string v6, "existing_instance_identifier"

    .line 915
    .line 916
    invoke-interface {v5, v6, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 917
    .line 918
    .line 919
    move-result-object v1

    .line 920
    iget-object v5, v3, Lqn/s;->b:Ljava/lang/Object;

    .line 921
    .line 922
    check-cast v5, Lus/c;

    .line 923
    .line 924
    iget-object v5, v5, Lus/c;->f:Ljava/lang/String;

    .line 925
    .line 926
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 927
    .line 928
    .line 929
    move-result v1

    .line 930
    if-eqz v1, :cond_16

    .line 931
    .line 932
    invoke-virtual {v3, v11}, Lqn/s;->a(I)Lus/a;

    .line 933
    .line 934
    .line 935
    move-result-object v1

    .line 936
    if-eqz v1, :cond_16

    .line 937
    .line 938
    invoke-virtual {v4, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 939
    .line 940
    .line 941
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    move-result-object v2

    .line 945
    check-cast v2, Laq/k;

    .line 946
    .line 947
    invoke-virtual {v2, v1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 948
    .line 949
    .line 950
    const/4 v6, 0x0

    .line 951
    invoke-static {v6}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 952
    .line 953
    .line 954
    move-result-object v1

    .line 955
    goto :goto_e

    .line 956
    :cond_16
    const/4 v5, 0x3

    .line 957
    invoke-virtual {v3, v5}, Lqn/s;->a(I)Lus/a;

    .line 958
    .line 959
    .line 960
    move-result-object v1

    .line 961
    if-eqz v1, :cond_17

    .line 962
    .line 963
    invoke-virtual {v4, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 964
    .line 965
    .line 966
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 967
    .line 968
    .line 969
    move-result-object v2

    .line 970
    check-cast v2, Laq/k;

    .line 971
    .line 972
    invoke-virtual {v2, v1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 973
    .line 974
    .line 975
    :cond_17
    iget-object v1, v3, Lqn/s;->g:Ljava/lang/Object;

    .line 976
    .line 977
    check-cast v1, Lh8/o;

    .line 978
    .line 979
    iget-object v2, v1, Lh8/o;->f:Ljava/lang/Object;

    .line 980
    .line 981
    check-cast v2, Laq/k;

    .line 982
    .line 983
    iget-object v2, v2, Laq/k;->a:Laq/t;

    .line 984
    .line 985
    iget-object v4, v1, Lh8/o;->c:Ljava/lang/Object;

    .line 986
    .line 987
    monitor-enter v4

    .line 988
    :try_start_1
    iget-object v1, v1, Lh8/o;->d:Ljava/lang/Object;

    .line 989
    .line 990
    check-cast v1, Laq/k;

    .line 991
    .line 992
    iget-object v1, v1, Laq/k;->a:Laq/t;

    .line 993
    .line 994
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 995
    invoke-static {v2, v1}, Lns/a;->a(Laq/j;Laq/j;)Laq/t;

    .line 996
    .line 997
    .line 998
    move-result-object v1

    .line 999
    iget-object v2, v15, Lns/d;->a:Lns/b;

    .line 1000
    .line 1001
    new-instance v4, Lb81/b;

    .line 1002
    .line 1003
    const/16 v5, 0x19

    .line 1004
    .line 1005
    const/4 v7, 0x0

    .line 1006
    invoke-direct {v4, v3, v15, v7, v5}, Lb81/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 1007
    .line 1008
    .line 1009
    invoke-virtual {v1, v2, v4}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v1

    .line 1013
    :goto_e
    new-instance v2, Lf3/d;

    .line 1014
    .line 1015
    const/16 v4, 0x1d

    .line 1016
    .line 1017
    invoke-direct {v2, v4}, Lf3/d;-><init>(I)V

    .line 1018
    .line 1019
    .line 1020
    invoke-virtual {v1, v0, v2}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 1021
    .line 1022
    .line 1023
    move-object/from16 v5, v38

    .line 1024
    .line 1025
    iget-object v0, v5, Lms/p;->j:Lss/b;

    .line 1026
    .line 1027
    const-string v1, "The Crashlytics build ID is missing. This occurs when the Crashlytics Gradle plugin is missing from your app\'s build configuration. Please review the Firebase Crashlytics onboarding instructions at https://firebase.google.com/docs/crashlytics/get-started?platform=android#add-plugin"

    .line 1028
    .line 1029
    iget-object v2, v5, Lms/p;->a:Landroid/content/Context;

    .line 1030
    .line 1031
    const-string v4, "com.crashlytics.RequireBuildId"

    .line 1032
    .line 1033
    if-eqz v2, :cond_19

    .line 1034
    .line 1035
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v6

    .line 1039
    if-eqz v6, :cond_19

    .line 1040
    .line 1041
    const-string v7, "bool"

    .line 1042
    .line 1043
    invoke-static {v2, v4, v7}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 1044
    .line 1045
    .line 1046
    move-result v7

    .line 1047
    if-lez v7, :cond_18

    .line 1048
    .line 1049
    invoke-virtual {v6, v7}, Landroid/content/res/Resources;->getBoolean(I)Z

    .line 1050
    .line 1051
    .line 1052
    move-result v4

    .line 1053
    :goto_f
    move-object/from16 v8, v42

    .line 1054
    .line 1055
    goto :goto_10

    .line 1056
    :cond_18
    const-string v6, "string"

    .line 1057
    .line 1058
    invoke-static {v2, v4, v6}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    .line 1059
    .line 1060
    .line 1061
    move-result v4

    .line 1062
    if-lez v4, :cond_19

    .line 1063
    .line 1064
    invoke-virtual {v2, v4}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v4

    .line 1068
    invoke-static {v4}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 1069
    .line 1070
    .line 1071
    move-result v4

    .line 1072
    goto :goto_f

    .line 1073
    :cond_19
    move v4, v11

    .line 1074
    goto :goto_f

    .line 1075
    :goto_10
    iget-object v6, v8, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 1076
    .line 1077
    check-cast v6, Ljava/lang/String;

    .line 1078
    .line 1079
    const-string v7, "."

    .line 1080
    .line 1081
    const-string v9, ".     |  |"

    .line 1082
    .line 1083
    if-nez v4, :cond_1a

    .line 1084
    .line 1085
    const-string v1, "Configured not to require a build ID."

    .line 1086
    .line 1087
    move-object/from16 v10, v30

    .line 1088
    .line 1089
    const/4 v4, 0x2

    .line 1090
    invoke-static {v10, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1091
    .line 1092
    .line 1093
    move-result v4

    .line 1094
    if-eqz v4, :cond_1b

    .line 1095
    .line 1096
    const/4 v6, 0x0

    .line 1097
    invoke-static {v10, v1, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1098
    .line 1099
    .line 1100
    goto :goto_11

    .line 1101
    :cond_1a
    move-object/from16 v10, v30

    .line 1102
    .line 1103
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1104
    .line 1105
    .line 1106
    move-result v4

    .line 1107
    if-nez v4, :cond_20

    .line 1108
    .line 1109
    :cond_1b
    :goto_11
    new-instance v1, Lms/d;

    .line 1110
    .line 1111
    invoke-direct {v1}, Lms/d;-><init>()V

    .line 1112
    .line 1113
    .line 1114
    iget-object v1, v1, Lms/d;->a:Ljava/lang/String;

    .line 1115
    .line 1116
    :try_start_2
    new-instance v4, Lb81/c;

    .line 1117
    .line 1118
    const-string v6, "crash_marker"

    .line 1119
    .line 1120
    const/16 v7, 0x12

    .line 1121
    .line 1122
    invoke-direct {v4, v7, v6, v0}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1123
    .line 1124
    .line 1125
    iput-object v4, v5, Lms/p;->f:Lb81/c;

    .line 1126
    .line 1127
    new-instance v4, Lb81/c;

    .line 1128
    .line 1129
    const-string v6, "initialization_marker"

    .line 1130
    .line 1131
    invoke-direct {v4, v7, v6, v0}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1132
    .line 1133
    .line 1134
    iput-object v4, v5, Lms/p;->e:Lb81/c;

    .line 1135
    .line 1136
    new-instance v4, Lss/b;

    .line 1137
    .line 1138
    move-object/from16 v6, v37

    .line 1139
    .line 1140
    invoke-direct {v4, v1, v0, v6}, Lss/b;-><init>(Ljava/lang/String;Lss/b;Lns/d;)V

    .line 1141
    .line 1142
    .line 1143
    new-instance v7, Los/f;

    .line 1144
    .line 1145
    invoke-direct {v7, v0}, Los/f;-><init>(Lss/b;)V

    .line 1146
    .line 1147
    .line 1148
    new-instance v0, Lvp/y1;

    .line 1149
    .line 1150
    new-instance v9, Lwq/f;

    .line 1151
    .line 1152
    const/16 v12, 0x18

    .line 1153
    .line 1154
    invoke-direct {v9, v12}, Lwq/f;-><init>(I)V

    .line 1155
    .line 1156
    .line 1157
    new-array v11, v11, [Lvs/a;

    .line 1158
    .line 1159
    const/4 v12, 0x0

    .line 1160
    aput-object v9, v11, v12

    .line 1161
    .line 1162
    invoke-direct {v0, v11}, Lvp/y1;-><init>([Lvs/a;)V

    .line 1163
    .line 1164
    .line 1165
    iget-object v9, v5, Lms/p;->o:Lhu/q;

    .line 1166
    .line 1167
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1168
    .line 1169
    .line 1170
    new-instance v11, Ljs/b;

    .line 1171
    .line 1172
    invoke-direct {v11, v4}, Ljs/b;-><init>(Lss/b;)V

    .line 1173
    .line 1174
    .line 1175
    iget-object v9, v9, Lhu/q;->e:Ljava/lang/Object;

    .line 1176
    .line 1177
    check-cast v9, Lgs/q;

    .line 1178
    .line 1179
    new-instance v12, Lgr/k;

    .line 1180
    .line 1181
    const/16 v13, 0xb

    .line 1182
    .line 1183
    invoke-direct {v12, v11, v13}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 1184
    .line 1185
    .line 1186
    invoke-virtual {v9, v12}, Lgs/q;->a(Lgt/a;)V

    .line 1187
    .line 1188
    .line 1189
    iget-object v9, v5, Lms/p;->a:Landroid/content/Context;

    .line 1190
    .line 1191
    iget-object v11, v5, Lms/p;->i:Lms/u;

    .line 1192
    .line 1193
    iget-object v12, v5, Lms/p;->j:Lss/b;

    .line 1194
    .line 1195
    iget-object v13, v5, Lms/p;->c:Lb81/d;

    .line 1196
    .line 1197
    iget-object v14, v5, Lms/p;->m:Lms/i;

    .line 1198
    .line 1199
    iget-object v15, v5, Lms/p;->p:Lns/d;

    .line 1200
    .line 1201
    move-object/from16 v45, v0

    .line 1202
    .line 1203
    move-object/from16 v46, v3

    .line 1204
    .line 1205
    move-object/from16 v44, v4

    .line 1206
    .line 1207
    move-object/from16 v43, v7

    .line 1208
    .line 1209
    move-object/from16 v42, v8

    .line 1210
    .line 1211
    move-object/from16 v39, v9

    .line 1212
    .line 1213
    move-object/from16 v40, v11

    .line 1214
    .line 1215
    move-object/from16 v41, v12

    .line 1216
    .line 1217
    move-object/from16 v47, v13

    .line 1218
    .line 1219
    move-object/from16 v48, v14

    .line 1220
    .line 1221
    move-object/from16 v49, v15

    .line 1222
    .line 1223
    invoke-static/range {v39 .. v49}, Lss/b;->f(Landroid/content/Context;Lms/u;Lss/b;Lcom/google/android/material/datepicker/d;Los/f;Lss/b;Lvp/y1;Lqn/s;Lb81/d;Lms/i;Lns/d;)Lss/b;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v48

    .line 1227
    move-object/from16 v8, v42

    .line 1228
    .line 1229
    move-object/from16 v47, v43

    .line 1230
    .line 1231
    move-object/from16 v0, v46

    .line 1232
    .line 1233
    move-object/from16 v46, v44

    .line 1234
    .line 1235
    new-instance v39, Lms/l;

    .line 1236
    .line 1237
    iget-object v3, v5, Lms/p;->a:Landroid/content/Context;

    .line 1238
    .line 1239
    iget-object v4, v5, Lms/p;->i:Lms/u;

    .line 1240
    .line 1241
    iget-object v7, v5, Lms/p;->b:Lh8/o;

    .line 1242
    .line 1243
    iget-object v9, v5, Lms/p;->j:Lss/b;

    .line 1244
    .line 1245
    iget-object v11, v5, Lms/p;->f:Lb81/c;

    .line 1246
    .line 1247
    iget-object v12, v5, Lms/p;->n:Ljs/a;

    .line 1248
    .line 1249
    iget-object v13, v5, Lms/p;->l:Lis/a;

    .line 1250
    .line 1251
    iget-object v14, v5, Lms/p;->m:Lms/i;

    .line 1252
    .line 1253
    iget-object v15, v5, Lms/p;->p:Lns/d;

    .line 1254
    .line 1255
    move-object/from16 v40, v3

    .line 1256
    .line 1257
    move-object/from16 v41, v4

    .line 1258
    .line 1259
    move-object/from16 v42, v7

    .line 1260
    .line 1261
    move-object/from16 v45, v8

    .line 1262
    .line 1263
    move-object/from16 v43, v9

    .line 1264
    .line 1265
    move-object/from16 v44, v11

    .line 1266
    .line 1267
    move-object/from16 v49, v12

    .line 1268
    .line 1269
    move-object/from16 v50, v13

    .line 1270
    .line 1271
    move-object/from16 v51, v14

    .line 1272
    .line 1273
    move-object/from16 v52, v15

    .line 1274
    .line 1275
    invoke-direct/range {v39 .. v52}, Lms/l;-><init>(Landroid/content/Context;Lms/u;Lh8/o;Lss/b;Lb81/c;Lcom/google/android/material/datepicker/d;Lss/b;Los/f;Lss/b;Ljs/a;Lks/a;Lms/i;Lns/d;)V

    .line 1276
    .line 1277
    .line 1278
    move-object/from16 v3, v39

    .line 1279
    .line 1280
    iput-object v3, v5, Lms/p;->h:Lms/l;

    .line 1281
    .line 1282
    iget-object v3, v5, Lms/p;->e:Lb81/c;

    .line 1283
    .line 1284
    iget-object v4, v3, Lb81/c;->f:Ljava/lang/Object;

    .line 1285
    .line 1286
    check-cast v4, Lss/b;

    .line 1287
    .line 1288
    iget-object v3, v3, Lb81/c;->e:Ljava/lang/Object;

    .line 1289
    .line 1290
    check-cast v3, Ljava/lang/String;

    .line 1291
    .line 1292
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1293
    .line 1294
    .line 1295
    new-instance v7, Ljava/io/File;

    .line 1296
    .line 1297
    iget-object v4, v4, Lss/b;->g:Ljava/lang/Object;

    .line 1298
    .line 1299
    check-cast v4, Ljava/io/File;

    .line 1300
    .line 1301
    invoke-direct {v7, v4, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 1302
    .line 1303
    .line 1304
    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    .line 1305
    .line 1306
    .line 1307
    move-result v3

    .line 1308
    iget-object v4, v6, Lns/d;->a:Lns/b;

    .line 1309
    .line 1310
    iget-object v4, v4, Lns/b;->d:Ljava/util/concurrent/ExecutorService;

    .line 1311
    .line 1312
    new-instance v7, Lbm/x;

    .line 1313
    .line 1314
    const/4 v11, 0x4

    .line 1315
    invoke-direct {v7, v5, v11}, Lbm/x;-><init>(Ljava/lang/Object;I)V

    .line 1316
    .line 1317
    .line 1318
    invoke-interface {v4, v7}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v4
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 1322
    :try_start_3
    sget-object v7, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 1323
    .line 1324
    const-wide/16 v8, 0x3

    .line 1325
    .line 1326
    invoke-interface {v4, v8, v9, v7}, Ljava/util/concurrent/Future;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v4

    .line 1330
    check-cast v4, Ljava/lang/Boolean;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 1331
    .line 1332
    :try_start_4
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1333
    .line 1334
    invoke-virtual {v7, v4}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 1335
    .line 1336
    .line 1337
    move-result v4

    .line 1338
    iput-boolean v4, v5, Lms/p;->g:Z

    .line 1339
    .line 1340
    goto :goto_12

    .line 1341
    :catch_0
    const/4 v7, 0x0

    .line 1342
    iput-boolean v7, v5, Lms/p;->g:Z

    .line 1343
    .line 1344
    :goto_12
    iget-object v4, v5, Lms/p;->h:Lms/l;

    .line 1345
    .line 1346
    invoke-static {}, Ljava/lang/Thread;->getDefaultUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    .line 1347
    .line 1348
    .line 1349
    move-result-object v7

    .line 1350
    iget-object v8, v4, Lms/l;->e:Lns/d;

    .line 1351
    .line 1352
    iget-object v8, v8, Lns/d;->a:Lns/b;

    .line 1353
    .line 1354
    new-instance v9, Lh0/h0;

    .line 1355
    .line 1356
    const/16 v11, 0x16

    .line 1357
    .line 1358
    invoke-direct {v9, v11, v4, v1}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1359
    .line 1360
    .line 1361
    invoke-virtual {v8, v9}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 1362
    .line 1363
    .line 1364
    new-instance v1, Lh6/e;

    .line 1365
    .line 1366
    const/16 v8, 0x17

    .line 1367
    .line 1368
    invoke-direct {v1, v4, v8}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 1369
    .line 1370
    .line 1371
    new-instance v8, Lms/r;

    .line 1372
    .line 1373
    iget-object v9, v4, Lms/l;->j:Ljs/a;

    .line 1374
    .line 1375
    invoke-direct {v8, v1, v0, v7, v9}, Lms/r;-><init>(Lh6/e;Lqn/s;Ljava/lang/Thread$UncaughtExceptionHandler;Ljs/a;)V

    .line 1376
    .line 1377
    .line 1378
    iput-object v8, v4, Lms/l;->n:Lms/r;

    .line 1379
    .line 1380
    invoke-static {v8}, Ljava/lang/Thread;->setDefaultUncaughtExceptionHandler(Ljava/lang/Thread$UncaughtExceptionHandler;)V

    .line 1381
    .line 1382
    .line 1383
    if-eqz v3, :cond_1e

    .line 1384
    .line 1385
    const-string v1, "android.permission.ACCESS_NETWORK_STATE"

    .line 1386
    .line 1387
    invoke-virtual {v2, v1}, Landroid/content/Context;->checkCallingOrSelfPermission(Ljava/lang/String;)I

    .line 1388
    .line 1389
    .line 1390
    move-result v1

    .line 1391
    if-nez v1, :cond_1c

    .line 1392
    .line 1393
    const-string v1, "connectivity"

    .line 1394
    .line 1395
    invoke-virtual {v2, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v1

    .line 1399
    check-cast v1, Landroid/net/ConnectivityManager;

    .line 1400
    .line 1401
    invoke-virtual {v1}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 1402
    .line 1403
    .line 1404
    move-result-object v1

    .line 1405
    if-eqz v1, :cond_1e

    .line 1406
    .line 1407
    invoke-virtual {v1}, Landroid/net/NetworkInfo;->isConnectedOrConnecting()Z

    .line 1408
    .line 1409
    .line 1410
    move-result v1

    .line 1411
    if-eqz v1, :cond_1e

    .line 1412
    .line 1413
    :cond_1c
    const-string v1, "Crashlytics did not finish previous background initialization. Initializing synchronously."

    .line 1414
    .line 1415
    const/4 v6, 0x3

    .line 1416
    invoke-static {v10, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1417
    .line 1418
    .line 1419
    move-result v2

    .line 1420
    if-eqz v2, :cond_1d

    .line 1421
    .line 1422
    const/4 v6, 0x0

    .line 1423
    invoke-static {v10, v1, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1424
    .line 1425
    .line 1426
    :cond_1d
    invoke-virtual {v5, v0}, Lms/p;->b(Lqn/s;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    .line 1427
    .line 1428
    .line 1429
    goto :goto_14

    .line 1430
    :catch_1
    move-exception v0

    .line 1431
    goto :goto_13

    .line 1432
    :cond_1e
    const-string v1, "Successfully configured exception handler."

    .line 1433
    .line 1434
    const/4 v2, 0x3

    .line 1435
    invoke-static {v10, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1436
    .line 1437
    .line 1438
    move-result v3

    .line 1439
    if-eqz v3, :cond_1f

    .line 1440
    .line 1441
    const/4 v3, 0x0

    .line 1442
    invoke-static {v10, v1, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1443
    .line 1444
    .line 1445
    :cond_1f
    iget-object v1, v6, Lns/d;->a:Lns/b;

    .line 1446
    .line 1447
    new-instance v2, Lms/m;

    .line 1448
    .line 1449
    const/4 v7, 0x0

    .line 1450
    invoke-direct {v2, v5, v0, v7}, Lms/m;-><init>(Lms/p;Lqn/s;I)V

    .line 1451
    .line 1452
    .line 1453
    invoke-virtual {v1, v2}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 1454
    .line 1455
    .line 1456
    goto :goto_14

    .line 1457
    :goto_13
    const-string v1, "Crashlytics was not started due to an exception during initialization"

    .line 1458
    .line 1459
    invoke-static {v10, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1460
    .line 1461
    .line 1462
    const/4 v6, 0x0

    .line 1463
    iput-object v6, v5, Lms/p;->h:Lms/l;

    .line 1464
    .line 1465
    :goto_14
    new-instance v15, Lis/c;

    .line 1466
    .line 1467
    invoke-direct {v15, v5}, Lis/c;-><init>(Lms/p;)V

    .line 1468
    .line 1469
    .line 1470
    goto :goto_15

    .line 1471
    :cond_20
    invoke-static {v10, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1472
    .line 1473
    .line 1474
    const-string v0, ".     |  | "

    .line 1475
    .line 1476
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1477
    .line 1478
    .line 1479
    invoke-static {v10, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1480
    .line 1481
    .line 1482
    invoke-static {v10, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1483
    .line 1484
    .line 1485
    const-string v0, ".   \\ |  | /"

    .line 1486
    .line 1487
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1488
    .line 1489
    .line 1490
    const-string v0, ".    \\    /"

    .line 1491
    .line 1492
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1493
    .line 1494
    .line 1495
    const-string v0, ".     \\  /"

    .line 1496
    .line 1497
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1498
    .line 1499
    .line 1500
    const-string v0, ".      \\/"

    .line 1501
    .line 1502
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1503
    .line 1504
    .line 1505
    invoke-static {v10, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1506
    .line 1507
    .line 1508
    invoke-static {v10, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1509
    .line 1510
    .line 1511
    invoke-static {v10, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1512
    .line 1513
    .line 1514
    const-string v0, ".      /\\"

    .line 1515
    .line 1516
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1517
    .line 1518
    .line 1519
    const-string v0, ".     /  \\"

    .line 1520
    .line 1521
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1522
    .line 1523
    .line 1524
    const-string v0, ".    /    \\"

    .line 1525
    .line 1526
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1527
    .line 1528
    .line 1529
    const-string v0, ".   / |  | \\"

    .line 1530
    .line 1531
    invoke-static {v10, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1532
    .line 1533
    .line 1534
    invoke-static {v10, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1535
    .line 1536
    .line 1537
    invoke-static {v10, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1538
    .line 1539
    .line 1540
    invoke-static {v10, v9}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1541
    .line 1542
    .line 1543
    invoke-static {v10, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 1544
    .line 1545
    .line 1546
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1547
    .line 1548
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1549
    .line 1550
    .line 1551
    throw v0

    .line 1552
    :catchall_0
    move-exception v0

    .line 1553
    :try_start_5
    monitor-exit v4
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 1554
    throw v0

    .line 1555
    :catch_2
    move-exception v0

    .line 1556
    move-object v10, v2

    .line 1557
    const-string v1, "Error retrieving app package info."

    .line 1558
    .line 1559
    invoke-static {v10, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1560
    .line 1561
    .line 1562
    const/4 v15, 0x0

    .line 1563
    :goto_15
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1564
    .line 1565
    .line 1566
    move-result-wide v0

    .line 1567
    sub-long v0, v0, v26

    .line 1568
    .line 1569
    const-wide/16 v2, 0x10

    .line 1570
    .line 1571
    cmp-long v2, v0, v2

    .line 1572
    .line 1573
    if-lez v2, :cond_21

    .line 1574
    .line 1575
    const-string v2, "Initializing Crashlytics blocked main for "

    .line 1576
    .line 1577
    const-string v3, " ms"

    .line 1578
    .line 1579
    invoke-static {v0, v1, v2, v3}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1580
    .line 1581
    .line 1582
    move-result-object v0

    .line 1583
    const/4 v5, 0x3

    .line 1584
    invoke-static {v10, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1585
    .line 1586
    .line 1587
    move-result v1

    .line 1588
    if-eqz v1, :cond_21

    .line 1589
    .line 1590
    const/4 v6, 0x0

    .line 1591
    invoke-static {v10, v0, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 1592
    .line 1593
    .line 1594
    :cond_21
    return-object v15
.end method

.method public f(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget v0, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcz/myskoda/api/bff_consents/v2/infrastructure/ApiClient;

    .line 9
    .line 10
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_consents/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_consents/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :sswitch_0
    check-cast p0, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;

    .line 15
    .line 16
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;->c(Lcz/myskoda/api/bff_common/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :sswitch_1
    check-cast p0, Lcz/myskoda/api/bff_car_configurator/v3/infrastructure/ApiClient;

    .line 21
    .line 22
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_car_configurator/v3/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_car_configurator/v3/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :sswitch_2
    check-cast p0, Lcz/myskoda/api/bff_air_conditioning/v2/infrastructure/ApiClient;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_air_conditioning/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_air_conditioning/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :sswitch_3
    check-cast p0, Lcz/myskoda/api/bff_ai_assistant/v2/infrastructure/ApiClient;

    .line 33
    .line 34
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_ai_assistant/v2/infrastructure/ApiClient;->a(Lcz/myskoda/api/bff_ai_assistant/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :sswitch_4
    check-cast p0, Lcz/myskoda/api/bff/v1/infrastructure/ApiClient;

    .line 39
    .line 40
    invoke-static {p0, p1}, Lcz/myskoda/api/bff/v1/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff/v1/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :sswitch_5
    check-cast p0, Lcz/myskoda/api/vas/infrastructure/ApiClient;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lcz/myskoda/api/vas/infrastructure/ApiClient;->c(Lcz/myskoda/api/vas/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :sswitch_6
    check-cast p0, Lcz/myskoda/api/idk/infrastructure/ApiClient;

    .line 51
    .line 52
    invoke-static {p0, p1}, Lcz/myskoda/api/idk/infrastructure/ApiClient;->e(Lcz/myskoda/api/idk/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    nop

    .line 57
    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_6
        0x5 -> :sswitch_5
        0xd -> :sswitch_4
        0x10 -> :sswitch_3
        0x13 -> :sswitch_2
        0x15 -> :sswitch_1
        0x19 -> :sswitch_0
    .end sparse-switch
.end method

.method public g()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lny/i0;

    .line 4
    .line 5
    iget-object p0, p0, Lny/i0;->a:Liy/a;

    .line 6
    .line 7
    iget-object p0, p0, Liy/a;->b:Lyy0/l1;

    .line 8
    .line 9
    iget-object p0, p0, Lyy0/l1;->d:Lyy0/a2;

    .line 10
    .line 11
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    xor-int/lit8 p0, p0, 0x1

    .line 22
    .line 23
    return p0
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lp0/l;

    .line 9
    .line 10
    iput-object p1, p0, Lp0/l;->o:Ly4/h;

    .line 11
    .line 12
    const-string p0, "SurfaceOutputImpl close future complete"

    .line 13
    .line 14
    return-object p0

    .line 15
    :sswitch_0
    check-cast p0, Lp0/j;

    .line 16
    .line 17
    iput-object p1, p0, Lp0/j;->p:Ly4/h;

    .line 18
    .line 19
    new-instance p1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v0, "SettableFuture hashCode: "

    .line 22
    .line 23
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :sswitch_1
    check-cast p0, Lh0/i0;

    .line 39
    .line 40
    iget-object v0, p0, Lh0/i0;->a:Ljava/lang/Object;

    .line 41
    .line 42
    monitor-enter v0

    .line 43
    :try_start_0
    iput-object p1, p0, Lh0/i0;->e:Ly4/h;

    .line 44
    .line 45
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    const-string p0, "CameraRepository-deinit"

    .line 47
    .line 48
    return-object p0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    throw p0

    .line 52
    nop

    .line 53
    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_1
        0x16 -> :sswitch_0
    .end sparse-switch
.end method

.method public onComplete(Laq/j;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lr1/b;

    .line 4
    .line 5
    const-string v0, "it"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lr1/b;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lrb/a;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lrb/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p1, p0, Lgr/k;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lgr/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    :pswitch_0
    check-cast p0, Ljava/lang/Runnable;

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_1
    check-cast p0, Lms/j;

    .line 20
    .line 21
    invoke-virtual {p0}, Lms/j;->call()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Laq/j;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_2
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0xf
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method
