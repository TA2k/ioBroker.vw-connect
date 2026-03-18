.class public final Ly7/o;
.super Ly7/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:I

.field public final i:I

.field public final j:Lb81/d;

.field public final k:Lb81/d;

.field public l:Ly7/j;

.field public m:Ljava/net/HttpURLConnection;

.field public n:Ljava/io/InputStream;

.field public o:Z

.field public p:I

.field public q:J

.field public r:J


# direct methods
.method public constructor <init>(IILb81/d;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0}, Ly7/c;-><init>(Z)V

    .line 3
    .line 4
    .line 5
    iput p1, p0, Ly7/o;->h:I

    .line 6
    .line 7
    iput p2, p0, Ly7/o;->i:I

    .line 8
    .line 9
    iput-object p3, p0, Ly7/o;->j:Lb81/d;

    .line 10
    .line 11
    new-instance p1, Lb81/d;

    .line 12
    .line 13
    const/16 p2, 0x1c

    .line 14
    .line 15
    invoke-direct {p1, p2}, Lb81/d;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Ly7/o;->k:Lb81/d;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x0

    .line 3
    :try_start_0
    iget-object v2, p0, Ly7/o;->n:Ljava/io/InputStream;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 4
    .line 5
    if-eqz v2, :cond_0

    .line 6
    .line 7
    :try_start_1
    invoke-virtual {v2}, Ljava/io/InputStream;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :catchall_0
    move-exception v2

    .line 12
    goto :goto_1

    .line 13
    :catch_0
    move-exception v2

    .line 14
    :try_start_2
    new-instance v3, Ly7/s;

    .line 15
    .line 16
    sget-object v4, Lw7/w;->a:Ljava/lang/String;

    .line 17
    .line 18
    const/16 v4, 0x7d0

    .line 19
    .line 20
    const/4 v5, 0x3

    .line 21
    invoke-direct {v3, v2, v4, v5}, Ly7/s;-><init>(Ljava/io/IOException;II)V

    .line 22
    .line 23
    .line 24
    throw v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 25
    :cond_0
    :goto_0
    iput-object v1, p0, Ly7/o;->n:Ljava/io/InputStream;

    .line 26
    .line 27
    invoke-virtual {p0}, Ly7/o;->r()V

    .line 28
    .line 29
    .line 30
    iget-boolean v2, p0, Ly7/o;->o:Z

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    iput-boolean v0, p0, Ly7/o;->o:Z

    .line 35
    .line 36
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 37
    .line 38
    .line 39
    :cond_1
    iput-object v1, p0, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 40
    .line 41
    iput-object v1, p0, Ly7/o;->l:Ly7/j;

    .line 42
    .line 43
    return-void

    .line 44
    :goto_1
    iput-object v1, p0, Ly7/o;->n:Ljava/io/InputStream;

    .line 45
    .line 46
    invoke-virtual {p0}, Ly7/o;->r()V

    .line 47
    .line 48
    .line 49
    iget-boolean v3, p0, Ly7/o;->o:Z

    .line 50
    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    iput-boolean v0, p0, Ly7/o;->o:Z

    .line 54
    .line 55
    invoke-virtual {p0}, Ly7/c;->m()V

    .line 56
    .line 57
    .line 58
    :cond_2
    iput-object v1, p0, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 59
    .line 60
    iput-object v1, p0, Ly7/o;->l:Ly7/j;

    .line 61
    .line 62
    throw v2
.end method

.method public final d()Ljava/util/Map;
    .locals 1

    .line 1
    iget-object p0, p0, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lhr/c1;->j:Lhr/c1;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ly7/n;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-direct {v0, p0}, Ly7/n;-><init>(Ljava/util/Map;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final g(Ly7/j;)J
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    iput-object v0, v1, Ly7/o;->l:Ly7/j;

    .line 6
    .line 7
    const-wide/16 v12, 0x0

    .line 8
    .line 9
    iput-wide v12, v1, Ly7/o;->r:J

    .line 10
    .line 11
    iput-wide v12, v1, Ly7/o;->q:J

    .line 12
    .line 13
    invoke-virtual {v1}, Ly7/c;->p()V

    .line 14
    .line 15
    .line 16
    const/4 v14, 0x1

    .line 17
    :try_start_0
    new-instance v2, Ljava/net/URL;

    .line 18
    .line 19
    iget-object v3, v0, Ly7/j;->a:Landroid/net/Uri;

    .line 20
    .line 21
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-direct {v2, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget v3, v0, Ly7/j;->b:I

    .line 29
    .line 30
    iget-object v4, v0, Ly7/j;->c:[B

    .line 31
    .line 32
    iget-wide v5, v0, Ly7/j;->e:J

    .line 33
    .line 34
    iget-wide v7, v0, Ly7/j;->f:J

    .line 35
    .line 36
    iget v9, v0, Ly7/j;->g:I

    .line 37
    .line 38
    and-int/2addr v9, v14

    .line 39
    if-ne v9, v14, :cond_0

    .line 40
    .line 41
    move v9, v14

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const/4 v9, 0x0

    .line 44
    :goto_0
    iget-object v11, v0, Ly7/j;->d:Ljava/util/Map;

    .line 45
    .line 46
    const/4 v10, 0x1

    .line 47
    invoke-virtual/range {v1 .. v11}, Ly7/o;->s(Ljava/net/URL;I[BJJZZLjava/util/Map;)Ljava/net/HttpURLConnection;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-wide v3, v0, Ly7/j;->e:J

    .line 52
    .line 53
    iget-wide v5, v0, Ly7/j;->f:J

    .line 54
    .line 55
    iput-object v2, v1, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    iput v7, v1, Ly7/o;->p:I

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseMessage()Ljava/lang/String;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_6

    .line 64
    .line 65
    .line 66
    iget v7, v1, Ly7/o;->p:I

    .line 67
    .line 68
    const-string v8, "Content-Range"

    .line 69
    .line 70
    const/16 v9, 0xc8

    .line 71
    .line 72
    const-wide/16 v10, -0x1

    .line 73
    .line 74
    if-lt v7, v9, :cond_1

    .line 75
    .line 76
    const/16 v15, 0x12b

    .line 77
    .line 78
    if-le v7, v15, :cond_2

    .line 79
    .line 80
    :cond_1
    move-wide/from16 v16, v10

    .line 81
    .line 82
    move-wide/from16 v18, v12

    .line 83
    .line 84
    goto/16 :goto_8

    .line 85
    .line 86
    :cond_2
    invoke-virtual {v2}, Ljava/net/URLConnection;->getContentType()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    iget v7, v1, Ly7/o;->p:I

    .line 90
    .line 91
    if-ne v7, v9, :cond_3

    .line 92
    .line 93
    cmp-long v7, v3, v12

    .line 94
    .line 95
    if-eqz v7, :cond_3

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_3
    move-wide v3, v12

    .line 99
    :goto_1
    const-string v7, "Content-Encoding"

    .line 100
    .line 101
    invoke-virtual {v2, v7}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    const-string v9, "gzip"

    .line 106
    .line 107
    invoke-virtual {v9, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 108
    .line 109
    .line 110
    move-result v7

    .line 111
    if-nez v7, :cond_9

    .line 112
    .line 113
    cmp-long v9, v5, v10

    .line 114
    .line 115
    if-eqz v9, :cond_4

    .line 116
    .line 117
    iput-wide v5, v1, Ly7/o;->q:J

    .line 118
    .line 119
    goto/16 :goto_5

    .line 120
    .line 121
    :cond_4
    const-string v5, "Content-Length"

    .line 122
    .line 123
    invoke-virtual {v2, v5}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    invoke-virtual {v2, v8}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    sget-object v8, Ly7/v;->a:Ljava/util/regex/Pattern;

    .line 132
    .line 133
    const-string v8, "Inconsistent headers ["

    .line 134
    .line 135
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 136
    .line 137
    .line 138
    move-result v9

    .line 139
    const-string v15, "]"

    .line 140
    .line 141
    move-wide/from16 v16, v10

    .line 142
    .line 143
    const-string v10, "HttpUtil"

    .line 144
    .line 145
    if-nez v9, :cond_5

    .line 146
    .line 147
    :try_start_1
    invoke-static {v5}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 148
    .line 149
    .line 150
    move-result-wide v18
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0

    .line 151
    move-wide/from16 v24, v18

    .line 152
    .line 153
    move-wide/from16 v18, v12

    .line 154
    .line 155
    move-wide/from16 v12, v24

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :catch_0
    new-instance v9, Ljava/lang/StringBuilder;

    .line 159
    .line 160
    const-string v11, "Unexpected Content-Length ["

    .line 161
    .line 162
    invoke-direct {v9, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v9, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v9

    .line 175
    invoke-static {v10, v9}, Lw7/a;->o(Ljava/lang/String;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    :cond_5
    move-wide/from16 v18, v12

    .line 179
    .line 180
    move-wide/from16 v12, v16

    .line 181
    .line 182
    :goto_2
    invoke-static {v6}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 183
    .line 184
    .line 185
    move-result v9

    .line 186
    if-nez v9, :cond_7

    .line 187
    .line 188
    sget-object v9, Ly7/v;->a:Ljava/util/regex/Pattern;

    .line 189
    .line 190
    invoke-virtual {v9, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 191
    .line 192
    .line 193
    move-result-object v9

    .line 194
    invoke-virtual {v9}, Ljava/util/regex/Matcher;->matches()Z

    .line 195
    .line 196
    .line 197
    move-result v11

    .line 198
    if-eqz v11, :cond_7

    .line 199
    .line 200
    const/4 v11, 0x2

    .line 201
    :try_start_2
    invoke-virtual {v9, v11}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v11

    .line 205
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    invoke-static {v11}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 209
    .line 210
    .line 211
    move-result-wide v20

    .line 212
    invoke-virtual {v9, v14}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v9

    .line 216
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    invoke-static {v9}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 220
    .line 221
    .line 222
    move-result-wide v22
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_1

    .line 223
    sub-long v20, v20, v22

    .line 224
    .line 225
    const-wide/16 v22, 0x1

    .line 226
    .line 227
    move-object v11, v15

    .line 228
    add-long v14, v20, v22

    .line 229
    .line 230
    cmp-long v18, v12, v18

    .line 231
    .line 232
    if-gez v18, :cond_6

    .line 233
    .line 234
    move-wide v12, v14

    .line 235
    goto :goto_3

    .line 236
    :cond_6
    cmp-long v18, v12, v14

    .line 237
    .line 238
    if-eqz v18, :cond_7

    .line 239
    .line 240
    :try_start_3
    new-instance v9, Ljava/lang/StringBuilder;

    .line 241
    .line 242
    invoke-direct {v9, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    const-string v5, "] ["

    .line 249
    .line 250
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v5

    .line 263
    invoke-static {v10, v5}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    invoke-static {v12, v13, v14, v15}, Ljava/lang/Math;->max(JJ)J

    .line 267
    .line 268
    .line 269
    move-result-wide v12
    :try_end_3
    .catch Ljava/lang/NumberFormatException; {:try_start_3 .. :try_end_3} :catch_2

    .line 270
    goto :goto_3

    .line 271
    :catch_1
    move-object v11, v15

    .line 272
    :catch_2
    new-instance v5, Ljava/lang/StringBuilder;

    .line 273
    .line 274
    const-string v8, "Unexpected Content-Range ["

    .line 275
    .line 276
    invoke-direct {v5, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 280
    .line 281
    .line 282
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 283
    .line 284
    .line 285
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v5

    .line 289
    invoke-static {v10, v5}, Lw7/a;->o(Ljava/lang/String;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    :cond_7
    :goto_3
    cmp-long v5, v12, v16

    .line 293
    .line 294
    if-eqz v5, :cond_8

    .line 295
    .line 296
    sub-long v10, v12, v3

    .line 297
    .line 298
    goto :goto_4

    .line 299
    :cond_8
    move-wide/from16 v10, v16

    .line 300
    .line 301
    :goto_4
    iput-wide v10, v1, Ly7/o;->q:J

    .line 302
    .line 303
    goto :goto_5

    .line 304
    :cond_9
    iput-wide v5, v1, Ly7/o;->q:J

    .line 305
    .line 306
    :goto_5
    const/16 v5, 0x7d0

    .line 307
    .line 308
    :try_start_4
    invoke-virtual {v2}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 309
    .line 310
    .line 311
    move-result-object v2

    .line 312
    iput-object v2, v1, Ly7/o;->n:Ljava/io/InputStream;

    .line 313
    .line 314
    if-eqz v7, :cond_a

    .line 315
    .line 316
    new-instance v2, Ljava/util/zip/GZIPInputStream;

    .line 317
    .line 318
    iget-object v6, v1, Ly7/o;->n:Ljava/io/InputStream;

    .line 319
    .line 320
    invoke-direct {v2, v6}, Ljava/util/zip/GZIPInputStream;-><init>(Ljava/io/InputStream;)V

    .line 321
    .line 322
    .line 323
    iput-object v2, v1, Ly7/o;->n:Ljava/io/InputStream;
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3

    .line 324
    .line 325
    :cond_a
    const/4 v9, 0x1

    .line 326
    goto :goto_6

    .line 327
    :catch_3
    move-exception v0

    .line 328
    const/4 v9, 0x1

    .line 329
    goto :goto_7

    .line 330
    :goto_6
    iput-boolean v9, v1, Ly7/o;->o:Z

    .line 331
    .line 332
    invoke-virtual/range {p0 .. p1}, Ly7/c;->q(Ly7/j;)V

    .line 333
    .line 334
    .line 335
    :try_start_5
    invoke-virtual {v1, v3, v4}, Ly7/o;->t(J)V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_4

    .line 336
    .line 337
    .line 338
    iget-wide v0, v1, Ly7/o;->q:J

    .line 339
    .line 340
    return-wide v0

    .line 341
    :catch_4
    move-exception v0

    .line 342
    invoke-virtual {v1}, Ly7/o;->r()V

    .line 343
    .line 344
    .line 345
    instance-of v1, v0, Ly7/s;

    .line 346
    .line 347
    if-eqz v1, :cond_b

    .line 348
    .line 349
    check-cast v0, Ly7/s;

    .line 350
    .line 351
    throw v0

    .line 352
    :cond_b
    new-instance v1, Ly7/s;

    .line 353
    .line 354
    const/4 v9, 0x1

    .line 355
    invoke-direct {v1, v0, v5, v9}, Ly7/s;-><init>(Ljava/io/IOException;II)V

    .line 356
    .line 357
    .line 358
    throw v1

    .line 359
    :goto_7
    invoke-virtual {v1}, Ly7/o;->r()V

    .line 360
    .line 361
    .line 362
    new-instance v1, Ly7/s;

    .line 363
    .line 364
    invoke-direct {v1, v0, v5, v9}, Ly7/s;-><init>(Ljava/io/IOException;II)V

    .line 365
    .line 366
    .line 367
    throw v1

    .line 368
    :goto_8
    invoke-virtual {v2}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 369
    .line 370
    .line 371
    move-result-object v7

    .line 372
    iget v10, v1, Ly7/o;->p:I

    .line 373
    .line 374
    const/16 v11, 0x1a0

    .line 375
    .line 376
    if-ne v10, v11, :cond_f

    .line 377
    .line 378
    invoke-virtual {v2, v8}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v8

    .line 382
    sget-object v10, Ly7/v;->a:Ljava/util/regex/Pattern;

    .line 383
    .line 384
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 385
    .line 386
    .line 387
    move-result v10

    .line 388
    if-eqz v10, :cond_c

    .line 389
    .line 390
    move-wide/from16 v12, v16

    .line 391
    .line 392
    const/4 v9, 0x1

    .line 393
    goto :goto_9

    .line 394
    :cond_c
    sget-object v10, Ly7/v;->b:Ljava/util/regex/Pattern;

    .line 395
    .line 396
    invoke-virtual {v10, v8}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 397
    .line 398
    .line 399
    move-result-object v8

    .line 400
    invoke-virtual {v8}, Ljava/util/regex/Matcher;->matches()Z

    .line 401
    .line 402
    .line 403
    move-result v10

    .line 404
    const/4 v9, 0x1

    .line 405
    if-eqz v10, :cond_d

    .line 406
    .line 407
    invoke-virtual {v8, v9}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object v8

    .line 411
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 412
    .line 413
    .line 414
    invoke-static {v8}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 415
    .line 416
    .line 417
    move-result-wide v12

    .line 418
    goto :goto_9

    .line 419
    :cond_d
    move-wide/from16 v12, v16

    .line 420
    .line 421
    :goto_9
    cmp-long v3, v3, v12

    .line 422
    .line 423
    if-nez v3, :cond_f

    .line 424
    .line 425
    iput-boolean v9, v1, Ly7/o;->o:Z

    .line 426
    .line 427
    invoke-virtual/range {p0 .. p1}, Ly7/c;->q(Ly7/j;)V

    .line 428
    .line 429
    .line 430
    cmp-long v0, v5, v16

    .line 431
    .line 432
    if-eqz v0, :cond_e

    .line 433
    .line 434
    return-wide v5

    .line 435
    :cond_e
    return-wide v18

    .line 436
    :cond_f
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    if-eqz v0, :cond_10

    .line 441
    .line 442
    :try_start_6
    invoke-static {v0}, Lir/b;->b(Ljava/io/InputStream;)[B

    .line 443
    .line 444
    .line 445
    goto :goto_a

    .line 446
    :cond_10
    sget-object v0, Lw7/w;->a:Ljava/lang/String;
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_5

    .line 447
    .line 448
    goto :goto_a

    .line 449
    :catch_5
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 450
    .line 451
    :goto_a
    invoke-virtual {v1}, Ly7/o;->r()V

    .line 452
    .line 453
    .line 454
    iget v0, v1, Ly7/o;->p:I

    .line 455
    .line 456
    if-ne v0, v11, :cond_11

    .line 457
    .line 458
    new-instance v0, Ly7/i;

    .line 459
    .line 460
    const/16 v2, 0x7d8

    .line 461
    .line 462
    invoke-direct {v0, v2}, Ly7/i;-><init>(I)V

    .line 463
    .line 464
    .line 465
    goto :goto_b

    .line 466
    :cond_11
    const/4 v0, 0x0

    .line 467
    :goto_b
    new-instance v2, Ly7/u;

    .line 468
    .line 469
    iget v1, v1, Ly7/o;->p:I

    .line 470
    .line 471
    invoke-direct {v2, v1, v0, v7}, Ly7/u;-><init>(ILy7/i;Ljava/util/Map;)V

    .line 472
    .line 473
    .line 474
    throw v2

    .line 475
    :catch_6
    move-exception v0

    .line 476
    invoke-virtual {v1}, Ly7/o;->r()V

    .line 477
    .line 478
    .line 479
    const/4 v9, 0x1

    .line 480
    invoke-static {v0, v9}, Ly7/s;->a(Ljava/io/IOException;I)Ly7/s;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    throw v0
.end method

.method public final getUri()Landroid/net/Uri;
    .locals 1

    .line 1
    iget-object v0, p0, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/net/URLConnection;->getURL()Ljava/net/URL;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Ly7/o;->l:Ly7/j;

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    iget-object p0, p0, Ly7/j;->a:Landroid/net/Uri;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public final r()V
    .locals 2

    .line 1
    iget-object p0, p0, Ly7/o;->m:Ljava/net/HttpURLConnection;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->disconnect()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :catch_0
    move-exception p0

    .line 10
    const-string v0, "DefaultHttpDataSource"

    .line 11
    .line 12
    const-string v1, "Unexpected error while disconnecting"

    .line 13
    .line 14
    invoke-static {v0, v1, p0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final read([BII)I
    .locals 6

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    :try_start_0
    iget-wide v0, p0, Ly7/o;->q:J

    .line 6
    .line 7
    const-wide/16 v2, -0x1

    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    const/4 v3, -0x1

    .line 12
    if-eqz v2, :cond_2

    .line 13
    .line 14
    iget-wide v4, p0, Ly7/o;->r:J

    .line 15
    .line 16
    sub-long/2addr v0, v4

    .line 17
    const-wide/16 v4, 0x0

    .line 18
    .line 19
    cmp-long v2, v0, v4

    .line 20
    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    int-to-long v4, p3

    .line 25
    invoke-static {v4, v5, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    long-to-int p3, v0

    .line 30
    :cond_2
    iget-object v0, p0, Ly7/o;->n:Ljava/io/InputStream;

    .line 31
    .line 32
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v0, p1, p2, p3}, Ljava/io/InputStream;->read([BII)I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-ne p1, v3, :cond_3

    .line 39
    .line 40
    :goto_0
    return v3

    .line 41
    :cond_3
    iget-wide p2, p0, Ly7/o;->r:J

    .line 42
    .line 43
    int-to-long v0, p1

    .line 44
    add-long/2addr p2, v0

    .line 45
    iput-wide p2, p0, Ly7/o;->r:J

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Ly7/c;->c(I)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    return p1

    .line 51
    :catch_0
    move-exception p0

    .line 52
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 53
    .line 54
    const/4 p1, 0x2

    .line 55
    invoke-static {p0, p1}, Ly7/s;->a(Ljava/io/IOException;I)Ly7/s;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    throw p0
.end method

.method public final s(Ljava/net/URL;I[BJJZZLjava/util/Map;)Ljava/net/HttpURLConnection;
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Ljava/net/URLConnection;

    .line 10
    .line 11
    check-cast p1, Ljava/net/HttpURLConnection;

    .line 12
    .line 13
    iget v0, p0, Ly7/o;->h:I

    .line 14
    .line 15
    invoke-virtual {p1, v0}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 16
    .line 17
    .line 18
    iget v0, p0, Ly7/o;->i:I

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Ljava/net/URLConnection;->setReadTimeout(I)V

    .line 21
    .line 22
    .line 23
    new-instance v0, Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ly7/o;->j:Lb81/d;

    .line 29
    .line 30
    if-eqz v1, :cond_0

    .line 31
    .line 32
    invoke-virtual {v1}, Lb81/d;->m()Ljava/util/Map;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 37
    .line 38
    .line 39
    :cond_0
    iget-object p0, p0, Ly7/o;->k:Lb81/d;

    .line 40
    .line 41
    invoke-virtual {p0}, Lb81/d;->m()Ljava/util/Map;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {v0, p0}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, p10}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result p10

    .line 63
    if-eqz p10, :cond_1

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p10

    .line 69
    check-cast p10, Ljava/util/Map$Entry;

    .line 70
    .line 71
    invoke-interface {p10}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    check-cast v0, Ljava/lang/String;

    .line 76
    .line 77
    invoke-interface {p10}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p10

    .line 81
    check-cast p10, Ljava/lang/String;

    .line 82
    .line 83
    invoke-virtual {p1, v0, p10}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    sget-object p0, Ly7/v;->a:Ljava/util/regex/Pattern;

    .line 88
    .line 89
    const-wide/16 v0, 0x0

    .line 90
    .line 91
    cmp-long p0, p4, v0

    .line 92
    .line 93
    const-wide/16 v0, -0x1

    .line 94
    .line 95
    if-nez p0, :cond_2

    .line 96
    .line 97
    cmp-long p0, p6, v0

    .line 98
    .line 99
    if-nez p0, :cond_2

    .line 100
    .line 101
    const/4 p0, 0x0

    .line 102
    goto :goto_1

    .line 103
    :cond_2
    const-string p0, "bytes="

    .line 104
    .line 105
    const-string p10, "-"

    .line 106
    .line 107
    invoke-static {p4, p5, p0, p10}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    cmp-long p10, p6, v0

    .line 112
    .line 113
    if-eqz p10, :cond_3

    .line 114
    .line 115
    add-long/2addr p4, p6

    .line 116
    const-wide/16 p6, 0x1

    .line 117
    .line 118
    sub-long/2addr p4, p6

    .line 119
    invoke-virtual {p0, p4, p5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    :cond_3
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    :goto_1
    if-eqz p0, :cond_4

    .line 127
    .line 128
    const-string p4, "Range"

    .line 129
    .line 130
    invoke-virtual {p1, p4, p0}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    :cond_4
    if-eqz p8, :cond_5

    .line 134
    .line 135
    const-string p0, "gzip"

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_5
    const-string p0, "identity"

    .line 139
    .line 140
    :goto_2
    const-string p4, "Accept-Encoding"

    .line 141
    .line 142
    invoke-virtual {p1, p4, p0}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1, p9}, Ljava/net/HttpURLConnection;->setInstanceFollowRedirects(Z)V

    .line 146
    .line 147
    .line 148
    const/4 p0, 0x1

    .line 149
    if-eqz p3, :cond_6

    .line 150
    .line 151
    move p4, p0

    .line 152
    goto :goto_3

    .line 153
    :cond_6
    const/4 p4, 0x0

    .line 154
    :goto_3
    invoke-virtual {p1, p4}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 155
    .line 156
    .line 157
    sget p4, Ly7/j;->h:I

    .line 158
    .line 159
    if-eq p2, p0, :cond_9

    .line 160
    .line 161
    const/4 p0, 0x2

    .line 162
    if-eq p2, p0, :cond_8

    .line 163
    .line 164
    const/4 p0, 0x3

    .line 165
    if-ne p2, p0, :cond_7

    .line 166
    .line 167
    const-string p0, "HEAD"

    .line 168
    .line 169
    goto :goto_4

    .line 170
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :cond_8
    const-string p0, "POST"

    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_9
    const-string p0, "GET"

    .line 180
    .line 181
    :goto_4
    invoke-virtual {p1, p0}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    if-eqz p3, :cond_a

    .line 185
    .line 186
    array-length p0, p3

    .line 187
    invoke-virtual {p1, p0}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {p1}, Ljava/net/URLConnection;->connect()V

    .line 191
    .line 192
    .line 193
    invoke-virtual {p1}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    invoke-virtual {p0, p3}, Ljava/io/OutputStream;->write([B)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p0}, Ljava/io/OutputStream;->close()V

    .line 201
    .line 202
    .line 203
    return-object p1

    .line 204
    :cond_a
    invoke-virtual {p1}, Ljava/net/URLConnection;->connect()V

    .line 205
    .line 206
    .line 207
    return-object p1
.end method

.method public final t(J)V
    .locals 7

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-nez v2, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    const/16 v2, 0x1000

    .line 9
    .line 10
    new-array v3, v2, [B

    .line 11
    .line 12
    :goto_0
    cmp-long v4, p1, v0

    .line 13
    .line 14
    if-lez v4, :cond_3

    .line 15
    .line 16
    int-to-long v4, v2

    .line 17
    invoke-static {p1, p2, v4, v5}, Ljava/lang/Math;->min(JJ)J

    .line 18
    .line 19
    .line 20
    move-result-wide v4

    .line 21
    long-to-int v4, v4

    .line 22
    iget-object v5, p0, Ly7/o;->n:Ljava/io/InputStream;

    .line 23
    .line 24
    sget-object v6, Lw7/w;->a:Ljava/lang/String;

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    invoke-virtual {v5, v3, v6, v4}, Ljava/io/InputStream;->read([BII)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    invoke-virtual {v5}, Ljava/lang/Thread;->isInterrupted()Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    if-nez v5, :cond_2

    .line 40
    .line 41
    const/4 v5, -0x1

    .line 42
    if-eq v4, v5, :cond_1

    .line 43
    .line 44
    int-to-long v5, v4

    .line 45
    sub-long/2addr p1, v5

    .line 46
    invoke-virtual {p0, v4}, Ly7/c;->c(I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    new-instance p0, Ly7/s;

    .line 51
    .line 52
    invoke-direct {p0}, Ly7/s;-><init>()V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    new-instance p0, Ly7/s;

    .line 57
    .line 58
    new-instance p1, Ljava/io/InterruptedIOException;

    .line 59
    .line 60
    invoke-direct {p1}, Ljava/io/InterruptedIOException;-><init>()V

    .line 61
    .line 62
    .line 63
    const/16 p2, 0x7d0

    .line 64
    .line 65
    const/4 v0, 0x1

    .line 66
    invoke-direct {p0, p1, p2, v0}, Ly7/s;-><init>(Ljava/io/IOException;II)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_3
    :goto_1
    return-void
.end method
