.class public abstract Lum/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/HashMap;

.field public static final b:Ljava/util/HashSet;

.field public static final c:[B

.field public static final d:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lum/d;->a:Ljava/util/HashMap;

    .line 7
    .line 8
    new-instance v0, Ljava/util/HashSet;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lum/d;->b:Ljava/util/HashSet;

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    new-array v0, v0, [B

    .line 17
    .line 18
    fill-array-data v0, :array_0

    .line 19
    .line 20
    .line 21
    sput-object v0, Lum/d;->c:[B

    .line 22
    .line 23
    const/4 v0, 0x3

    .line 24
    new-array v0, v0, [B

    .line 25
    .line 26
    fill-array-data v0, :array_1

    .line 27
    .line 28
    .line 29
    sput-object v0, Lum/d;->d:[B

    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :array_0
    .array-data 1
        0x50t
        0x4bt
        0x3t
        0x4t
    .end array-data

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    :array_1
    .array-data 1
        0x1ft
        -0x75t
        0x8t
    .end array-data
.end method

.method public static a(Lfn/b;Ljava/lang/String;Z)Lum/n;
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    :try_start_0
    sget-object v0, Lan/e;->b:Lan/e;

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Lan/e;->a(Ljava/lang/String;)Lum/a;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :goto_0
    if-eqz v0, :cond_2

    .line 12
    .line 13
    new-instance p1, Lum/n;

    .line 14
    .line 15
    invoke-direct {p1, v0}, Lum/n;-><init>(Lum/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    if-eqz p2, :cond_1

    .line 19
    .line 20
    invoke-static {p0}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    return-object p1

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    goto :goto_2

    .line 26
    :catch_0
    move-exception p1

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    :try_start_1
    invoke-static {p0}, Len/r;->a(Lfn/b;)Lum/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz p1, :cond_3

    .line 33
    .line 34
    sget-object v1, Lan/e;->b:Lan/e;

    .line 35
    .line 36
    iget-object v1, v1, Lan/e;->a:Landroidx/collection/w;

    .line 37
    .line 38
    invoke-virtual {v1, p1, v0}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    :cond_3
    new-instance p1, Lum/n;

    .line 42
    .line 43
    invoke-direct {p1, v0}, Lum/n;-><init>(Lum/a;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 44
    .line 45
    .line 46
    if-eqz p2, :cond_4

    .line 47
    .line 48
    invoke-static {p0}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 49
    .line 50
    .line 51
    :cond_4
    return-object p1

    .line 52
    :goto_1
    :try_start_2
    new-instance v0, Lum/n;

    .line 53
    .line 54
    invoke-direct {v0, p1}, Lum/n;-><init>(Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 55
    .line 56
    .line 57
    if-eqz p2, :cond_5

    .line 58
    .line 59
    invoke-static {p0}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 60
    .line 61
    .line 62
    :cond_5
    return-object v0

    .line 63
    :goto_2
    if-eqz p2, :cond_6

    .line 64
    .line 65
    invoke-static {p0}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 66
    .line 67
    .line 68
    :cond_6
    throw p1
.end method

.method public static b(Landroid/content/Context;Ljava/util/zip/ZipInputStream;Ljava/lang/String;)Lum/n;
    .locals 13

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/HashMap;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez p2, :cond_0

    .line 13
    .line 14
    move-object v3, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    :try_start_0
    sget-object v3, Lan/e;->b:Lan/e;

    .line 17
    .line 18
    invoke-virtual {v3, p2}, Lan/e;->a(Ljava/lang/String;)Lum/a;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    :goto_0
    if-eqz v3, :cond_1

    .line 23
    .line 24
    new-instance p0, Lum/n;

    .line 25
    .line 26
    invoke-direct {p0, v3}, Lum/n;-><init>(Lum/a;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    move-object v4, v2

    .line 35
    :goto_1
    const/4 v5, 0x1

    .line 36
    const/4 v6, 0x0

    .line 37
    if-eqz v3, :cond_c

    .line 38
    .line 39
    invoke-virtual {v3}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    const-string v8, "__MACOSX"

    .line 44
    .line 45
    invoke-virtual {v7, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 46
    .line 47
    .line 48
    move-result v8

    .line 49
    if-eqz v8, :cond_2

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->closeEntry()V

    .line 52
    .line 53
    .line 54
    goto/16 :goto_b

    .line 55
    .line 56
    :cond_2
    invoke-virtual {v3}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    const-string v9, "manifest.json"

    .line 61
    .line 62
    invoke-virtual {v8, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-eqz v8, :cond_3

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->closeEntry()V

    .line 69
    .line 70
    .line 71
    goto/16 :goto_b

    .line 72
    .line 73
    :cond_3
    invoke-virtual {v3}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    const-string v8, ".json"

    .line 78
    .line 79
    invoke-virtual {v3, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_4

    .line 84
    .line 85
    invoke-static {p1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    invoke-static {v3}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    sget-object v4, Lfn/a;->h:[Ljava/lang/String;

    .line 94
    .line 95
    new-instance v4, Lfn/b;

    .line 96
    .line 97
    invoke-direct {v4, v3}, Lfn/b;-><init>(Lu01/b0;)V

    .line 98
    .line 99
    .line 100
    invoke-static {v4, v2, v6}, Lum/d;->a(Lfn/b;Ljava/lang/String;Z)Lum/n;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    iget-object v4, v3, Lum/n;->a:Lum/a;

    .line 105
    .line 106
    goto/16 :goto_b

    .line 107
    .line 108
    :cond_4
    const-string v3, ".png"

    .line 109
    .line 110
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 111
    .line 112
    .line 113
    move-result v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 114
    const-string v8, "/"

    .line 115
    .line 116
    if-nez v3, :cond_b

    .line 117
    .line 118
    :try_start_1
    const-string v3, ".webp"

    .line 119
    .line 120
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-nez v3, :cond_b

    .line 125
    .line 126
    const-string v3, ".jpg"

    .line 127
    .line 128
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    if-nez v3, :cond_b

    .line 133
    .line 134
    const-string v3, ".jpeg"

    .line 135
    .line 136
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-eqz v3, :cond_5

    .line 141
    .line 142
    goto/16 :goto_a

    .line 143
    .line 144
    :cond_5
    const-string v3, ".ttf"

    .line 145
    .line 146
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    if-nez v3, :cond_7

    .line 151
    .line 152
    const-string v3, ".otf"

    .line 153
    .line 154
    invoke-virtual {v7, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    if-eqz v3, :cond_6

    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_6
    invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->closeEntry()V

    .line 162
    .line 163
    .line 164
    goto/16 :goto_b

    .line 165
    .line 166
    :cond_7
    :goto_2
    invoke-virtual {v7, v8}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v3

    .line 170
    array-length v7, v3

    .line 171
    sub-int/2addr v7, v5

    .line 172
    aget-object v3, v3, v7

    .line 173
    .line 174
    const-string v5, "\\."

    .line 175
    .line 176
    invoke-virtual {v3, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    aget-object v5, v5, v6

    .line 181
    .line 182
    if-nez p0, :cond_8

    .line 183
    .line 184
    new-instance p0, Lum/n;

    .line 185
    .line 186
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 187
    .line 188
    new-instance p2, Ljava/lang/StringBuilder;

    .line 189
    .line 190
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 191
    .line 192
    .line 193
    const-string v0, "Unable to extract font "

    .line 194
    .line 195
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    const-string v0, " please pass a non-null Context parameter"

    .line 202
    .line 203
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object p2

    .line 210
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-direct {p0, p1}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 214
    .line 215
    .line 216
    return-object p0

    .line 217
    :cond_8
    new-instance v7, Ljava/io/File;

    .line 218
    .line 219
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    .line 220
    .line 221
    .line 222
    move-result-object v8

    .line 223
    invoke-direct {v7, v8, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 224
    .line 225
    .line 226
    :try_start_2
    new-instance v8, Ljava/io/FileOutputStream;

    .line 227
    .line 228
    invoke-direct {v8, v7}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 229
    .line 230
    .line 231
    :try_start_3
    new-instance v9, Ljava/io/FileOutputStream;

    .line 232
    .line 233
    invoke-direct {v9, v7}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 234
    .line 235
    .line 236
    const/16 v10, 0x1000

    .line 237
    .line 238
    :try_start_4
    new-array v10, v10, [B

    .line 239
    .line 240
    :goto_3
    invoke-virtual {p1, v10}, Ljava/io/InputStream;->read([B)I

    .line 241
    .line 242
    .line 243
    move-result v11

    .line 244
    const/4 v12, -0x1

    .line 245
    if-eq v11, v12, :cond_9

    .line 246
    .line 247
    invoke-virtual {v9, v10, v6, v11}, Ljava/io/OutputStream;->write([BII)V

    .line 248
    .line 249
    .line 250
    goto :goto_3

    .line 251
    :catchall_0
    move-exception v6

    .line 252
    goto :goto_4

    .line 253
    :cond_9
    invoke-virtual {v9}, Ljava/io/OutputStream;->flush()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 254
    .line 255
    .line 256
    :try_start_5
    invoke-virtual {v9}, Ljava/io/OutputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 257
    .line 258
    .line 259
    :try_start_6
    invoke-virtual {v8}, Ljava/io/FileOutputStream;->close()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 260
    .line 261
    .line 262
    goto :goto_9

    .line 263
    :catchall_1
    move-exception v6

    .line 264
    goto :goto_8

    .line 265
    :catchall_2
    move-exception v6

    .line 266
    goto :goto_6

    .line 267
    :goto_4
    :try_start_7
    invoke-virtual {v9}, Ljava/io/OutputStream;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 268
    .line 269
    .line 270
    goto :goto_5

    .line 271
    :catchall_3
    move-exception v9

    .line 272
    :try_start_8
    invoke-virtual {v6, v9}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 273
    .line 274
    .line 275
    :goto_5
    throw v6
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 276
    :goto_6
    :try_start_9
    invoke-virtual {v8}, Ljava/io/FileOutputStream;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 277
    .line 278
    .line 279
    goto :goto_7

    .line 280
    :catchall_4
    move-exception v8

    .line 281
    :try_start_a
    invoke-virtual {v6, v8}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 282
    .line 283
    .line 284
    :goto_7
    throw v6
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 285
    :goto_8
    :try_start_b
    new-instance v8, Ljava/lang/StringBuilder;

    .line 286
    .line 287
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 288
    .line 289
    .line 290
    const-string v9, "Unable to save font "

    .line 291
    .line 292
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    const-string v9, " to the temporary file: "

    .line 299
    .line 300
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 301
    .line 302
    .line 303
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    const-string v3, ". "

    .line 307
    .line 308
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v3

    .line 315
    invoke-static {v3, v6}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 316
    .line 317
    .line 318
    :goto_9
    invoke-static {v7}, Landroid/graphics/Typeface;->createFromFile(Ljava/io/File;)Landroid/graphics/Typeface;

    .line 319
    .line 320
    .line 321
    move-result-object v3

    .line 322
    invoke-virtual {v7}, Ljava/io/File;->delete()Z

    .line 323
    .line 324
    .line 325
    move-result v6

    .line 326
    if-nez v6, :cond_a

    .line 327
    .line 328
    new-instance v6, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 331
    .line 332
    .line 333
    const-string v8, "Failed to delete temp font file "

    .line 334
    .line 335
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 336
    .line 337
    .line 338
    invoke-virtual {v7}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v7

    .line 342
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    const-string v7, "."

    .line 346
    .line 347
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 348
    .line 349
    .line 350
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 351
    .line 352
    .line 353
    move-result-object v6

    .line 354
    invoke-static {v6}, Lgn/c;->a(Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    :cond_a
    invoke-virtual {v1, v5, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    goto :goto_b

    .line 361
    :cond_b
    :goto_a
    invoke-virtual {v7, v8}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    array-length v6, v3

    .line 366
    sub-int/2addr v6, v5

    .line 367
    aget-object v3, v3, v6

    .line 368
    .line 369
    invoke-static {p1}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;)Landroid/graphics/Bitmap;

    .line 370
    .line 371
    .line 372
    move-result-object v5

    .line 373
    invoke-virtual {v0, v3, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    :goto_b
    invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;

    .line 377
    .line 378
    .line 379
    move-result-object v3
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_1

    .line 380
    goto/16 :goto_1

    .line 381
    .line 382
    :cond_c
    if-nez v4, :cond_d

    .line 383
    .line 384
    new-instance p0, Lum/n;

    .line 385
    .line 386
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 387
    .line 388
    const-string p2, "Unable to parse composition"

    .line 389
    .line 390
    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    invoke-direct {p0, p1}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 394
    .line 395
    .line 396
    return-object p0

    .line 397
    :cond_d
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 398
    .line 399
    .line 400
    move-result-object p0

    .line 401
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 402
    .line 403
    .line 404
    move-result-object p0

    .line 405
    :cond_e
    :goto_c
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 406
    .line 407
    .line 408
    move-result p1

    .line 409
    if-eqz p1, :cond_11

    .line 410
    .line 411
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object p1

    .line 415
    check-cast p1, Ljava/util/Map$Entry;

    .line 416
    .line 417
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    move-result-object v3

    .line 421
    check-cast v3, Ljava/lang/String;

    .line 422
    .line 423
    invoke-virtual {v4}, Lum/a;->c()Ljava/util/Map;

    .line 424
    .line 425
    .line 426
    move-result-object v7

    .line 427
    check-cast v7, Ljava/util/HashMap;

    .line 428
    .line 429
    invoke-virtual {v7}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 430
    .line 431
    .line 432
    move-result-object v7

    .line 433
    invoke-interface {v7}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 434
    .line 435
    .line 436
    move-result-object v7

    .line 437
    :cond_f
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 438
    .line 439
    .line 440
    move-result v8

    .line 441
    if-eqz v8, :cond_10

    .line 442
    .line 443
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    move-result-object v8

    .line 447
    check-cast v8, Lum/l;

    .line 448
    .line 449
    iget-object v9, v8, Lum/l;->d:Ljava/lang/String;

    .line 450
    .line 451
    invoke-virtual {v9, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 452
    .line 453
    .line 454
    move-result v9

    .line 455
    if-eqz v9, :cond_f

    .line 456
    .line 457
    goto :goto_d

    .line 458
    :cond_10
    move-object v8, v2

    .line 459
    :goto_d
    if-eqz v8, :cond_e

    .line 460
    .line 461
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    move-result-object p1

    .line 465
    check-cast p1, Landroid/graphics/Bitmap;

    .line 466
    .line 467
    iget v3, v8, Lum/l;->a:I

    .line 468
    .line 469
    iget v7, v8, Lum/l;->b:I

    .line 470
    .line 471
    invoke-static {p1, v3, v7}, Lgn/h;->d(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    .line 472
    .line 473
    .line 474
    move-result-object p1

    .line 475
    iput-object p1, v8, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 476
    .line 477
    goto :goto_c

    .line 478
    :cond_11
    invoke-virtual {v1}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 483
    .line 484
    .line 485
    move-result-object p0

    .line 486
    :cond_12
    :goto_e
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 487
    .line 488
    .line 489
    move-result p1

    .line 490
    if-eqz p1, :cond_15

    .line 491
    .line 492
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object p1

    .line 496
    check-cast p1, Ljava/util/Map$Entry;

    .line 497
    .line 498
    iget-object v1, v4, Lum/a;->f:Ljava/util/HashMap;

    .line 499
    .line 500
    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    move v3, v6

    .line 509
    :cond_13
    :goto_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 510
    .line 511
    .line 512
    move-result v7

    .line 513
    if-eqz v7, :cond_14

    .line 514
    .line 515
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v7

    .line 519
    check-cast v7, Lan/c;

    .line 520
    .line 521
    iget-object v8, v7, Lan/c;->a:Ljava/lang/String;

    .line 522
    .line 523
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    move-result-object v9

    .line 527
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 528
    .line 529
    .line 530
    move-result v8

    .line 531
    if-eqz v8, :cond_13

    .line 532
    .line 533
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v3

    .line 537
    check-cast v3, Landroid/graphics/Typeface;

    .line 538
    .line 539
    iput-object v3, v7, Lan/c;->c:Landroid/graphics/Typeface;

    .line 540
    .line 541
    move v3, v5

    .line 542
    goto :goto_f

    .line 543
    :cond_14
    if-nez v3, :cond_12

    .line 544
    .line 545
    new-instance v1, Ljava/lang/StringBuilder;

    .line 546
    .line 547
    const-string v3, "Parsed font for "

    .line 548
    .line 549
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    move-result-object p1

    .line 556
    check-cast p1, Ljava/lang/String;

    .line 557
    .line 558
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 559
    .line 560
    .line 561
    const-string p1, " however it was not found in the animation."

    .line 562
    .line 563
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 564
    .line 565
    .line 566
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 567
    .line 568
    .line 569
    move-result-object p1

    .line 570
    invoke-static {p1}, Lgn/c;->a(Ljava/lang/String;)V

    .line 571
    .line 572
    .line 573
    goto :goto_e

    .line 574
    :cond_15
    invoke-virtual {v0}, Ljava/util/HashMap;->isEmpty()Z

    .line 575
    .line 576
    .line 577
    move-result p0

    .line 578
    if-eqz p0, :cond_18

    .line 579
    .line 580
    invoke-virtual {v4}, Lum/a;->c()Ljava/util/Map;

    .line 581
    .line 582
    .line 583
    move-result-object p0

    .line 584
    check-cast p0, Ljava/util/HashMap;

    .line 585
    .line 586
    invoke-virtual {p0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 587
    .line 588
    .line 589
    move-result-object p0

    .line 590
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 591
    .line 592
    .line 593
    move-result-object p0

    .line 594
    :cond_16
    :goto_10
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 595
    .line 596
    .line 597
    move-result p1

    .line 598
    if-eqz p1, :cond_18

    .line 599
    .line 600
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    move-result-object p1

    .line 604
    check-cast p1, Ljava/util/Map$Entry;

    .line 605
    .line 606
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object p1

    .line 610
    check-cast p1, Lum/l;

    .line 611
    .line 612
    if-nez p1, :cond_17

    .line 613
    .line 614
    return-object v2

    .line 615
    :cond_17
    iget-object v0, p1, Lum/l;->d:Ljava/lang/String;

    .line 616
    .line 617
    new-instance v1, Landroid/graphics/BitmapFactory$Options;

    .line 618
    .line 619
    invoke-direct {v1}, Landroid/graphics/BitmapFactory$Options;-><init>()V

    .line 620
    .line 621
    .line 622
    iput-boolean v5, v1, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 623
    .line 624
    const/16 v3, 0xa0

    .line 625
    .line 626
    iput v3, v1, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 627
    .line 628
    const-string v3, "data:"

    .line 629
    .line 630
    invoke-virtual {v0, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 631
    .line 632
    .line 633
    move-result v3

    .line 634
    if-eqz v3, :cond_16

    .line 635
    .line 636
    const-string v3, "base64,"

    .line 637
    .line 638
    invoke-virtual {v0, v3}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 639
    .line 640
    .line 641
    move-result v3

    .line 642
    if-lez v3, :cond_16

    .line 643
    .line 644
    const/16 v3, 0x2c

    .line 645
    .line 646
    :try_start_c
    invoke-virtual {v0, v3}, Ljava/lang/String;->indexOf(I)I

    .line 647
    .line 648
    .line 649
    move-result v3

    .line 650
    add-int/2addr v3, v5

    .line 651
    invoke-virtual {v0, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v0

    .line 655
    invoke-static {v0, v6}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 656
    .line 657
    .line 658
    move-result-object v0
    :try_end_c
    .catch Ljava/lang/IllegalArgumentException; {:try_start_c .. :try_end_c} :catch_0

    .line 659
    array-length v3, v0

    .line 660
    invoke-static {v0, v6, v3, v1}, Landroid/graphics/BitmapFactory;->decodeByteArray([BIILandroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 661
    .line 662
    .line 663
    move-result-object v0

    .line 664
    if-eqz v0, :cond_16

    .line 665
    .line 666
    iget v1, p1, Lum/l;->a:I

    .line 667
    .line 668
    iget v3, p1, Lum/l;->b:I

    .line 669
    .line 670
    invoke-static {v0, v1, v3}, Lgn/h;->d(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    .line 671
    .line 672
    .line 673
    move-result-object v0

    .line 674
    iput-object v0, p1, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 675
    .line 676
    goto :goto_10

    .line 677
    :catch_0
    move-exception p0

    .line 678
    const-string p1, "data URL did not have correct base64 format."

    .line 679
    .line 680
    invoke-static {p1, p0}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 681
    .line 682
    .line 683
    return-object v2

    .line 684
    :cond_18
    if-eqz p2, :cond_19

    .line 685
    .line 686
    sget-object p0, Lan/e;->b:Lan/e;

    .line 687
    .line 688
    iget-object p0, p0, Lan/e;->a:Landroidx/collection/w;

    .line 689
    .line 690
    invoke-virtual {p0, p2, v4}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 691
    .line 692
    .line 693
    :cond_19
    new-instance p0, Lum/n;

    .line 694
    .line 695
    invoke-direct {p0, v4}, Lum/n;-><init>(Lum/a;)V

    .line 696
    .line 697
    .line 698
    return-object p0

    .line 699
    :catch_1
    move-exception p0

    .line 700
    new-instance p1, Lum/n;

    .line 701
    .line 702
    invoke-direct {p1, p0}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 703
    .line 704
    .line 705
    return-object p1
.end method

.method public static c(Lu01/b0;[B)Ljava/lang/Boolean;
    .locals 4

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lu01/b0;->b()Lu01/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    array-length v0, p1

    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    if-ge v1, v0, :cond_1

    .line 8
    .line 9
    aget-byte v2, p1, v1

    .line 10
    .line 11
    invoke-virtual {p0}, Lu01/b0;->readByte()B

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-eq v3, v2, :cond_0

    .line 16
    .line 17
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-virtual {p0}, Lu01/b0;->close()V

    .line 24
    .line 25
    .line 26
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodError; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    return-object p0

    .line 29
    :catch_0
    sget-object p0, Lgn/c;->a:Lgn/b;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 35
    .line 36
    return-object p0

    .line 37
    :catch_1
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 38
    .line 39
    return-object p0
.end method

.method public static d()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    sget-object v1, Lum/d;->b:Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-gtz v1, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    new-instance v0, Ljava/lang/ClassCastException;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw v0
.end method
