.class public abstract Lcom/google/android/gms/internal/measurement/w6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lsun/misc/Unsafe;

.field public static final b:Ljava/lang/Class;

.field public static final c:Lcom/google/android/gms/internal/measurement/v6;

.field public static final d:Z

.field public static final e:Z

.field public static final f:J

.field public static final g:Z


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    const-class v0, Ljava/lang/Class;

    .line 2
    .line 3
    invoke-static {}, Lcom/google/android/gms/internal/measurement/w6;->l()Lsun/misc/Unsafe;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sput-object v1, Lcom/google/android/gms/internal/measurement/w6;->a:Lsun/misc/Unsafe;

    .line 8
    .line 9
    sget v2, Lcom/google/android/gms/internal/measurement/v4;->a:I

    .line 10
    .line 11
    const-class v2, Llibcore/io/Memory;

    .line 12
    .line 13
    sput-object v2, Lcom/google/android/gms/internal/measurement/w6;->b:Ljava/lang/Class;

    .line 14
    .line 15
    sget-object v2, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 16
    .line 17
    invoke-static {v2}, Lcom/google/android/gms/internal/measurement/w6;->m(Ljava/lang/Class;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    sget-object v4, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 22
    .line 23
    invoke-static {v4}, Lcom/google/android/gms/internal/measurement/w6;->m(Ljava/lang/Class;)Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    const/4 v6, 0x0

    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    if-eqz v3, :cond_1

    .line 32
    .line 33
    new-instance v6, Lcom/google/android/gms/internal/measurement/u6;

    .line 34
    .line 35
    invoke-direct {v6, v1}, Lcom/google/android/gms/internal/measurement/v6;-><init>(Lsun/misc/Unsafe;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    if-eqz v5, :cond_2

    .line 40
    .line 41
    new-instance v6, Lcom/google/android/gms/internal/measurement/t6;

    .line 42
    .line 43
    invoke-direct {v6, v1}, Lcom/google/android/gms/internal/measurement/v6;-><init>(Lsun/misc/Unsafe;)V

    .line 44
    .line 45
    .line 46
    :cond_2
    :goto_0
    sput-object v6, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 47
    .line 48
    const-string v1, "logMissingMethod"

    .line 49
    .line 50
    const-string v3, "com.google.protobuf.UnsafeUtil"

    .line 51
    .line 52
    const-string v5, "platform method missing - proto runtime falling back to safer methods: "

    .line 53
    .line 54
    const-class v7, Lcom/google/android/gms/internal/measurement/w6;

    .line 55
    .line 56
    const-string v8, "getLong"

    .line 57
    .line 58
    const-class v9, Ljava/lang/reflect/Field;

    .line 59
    .line 60
    const-string v10, "objectFieldOffset"

    .line 61
    .line 62
    const/4 v11, 0x1

    .line 63
    const/4 v12, 0x0

    .line 64
    const-class v13, Ljava/lang/Object;

    .line 65
    .line 66
    if-nez v6, :cond_3

    .line 67
    .line 68
    :goto_1
    move v6, v12

    .line 69
    goto :goto_2

    .line 70
    :cond_3
    iget-object v6, v6, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 71
    .line 72
    :try_start_0
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    move-result-object v6

    .line 76
    filled-new-array {v9}, [Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    move-result-object v14

    .line 80
    invoke-virtual {v6, v10, v14}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 81
    .line 82
    .line 83
    filled-new-array {v13, v2}, [Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    move-result-object v14

    .line 87
    invoke-virtual {v6, v8, v14}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 88
    .line 89
    .line 90
    invoke-static {}, Lcom/google/android/gms/internal/measurement/w6;->b()Ljava/lang/reflect/Field;

    .line 91
    .line 92
    .line 93
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    if-nez v6, :cond_4

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_4
    move v6, v11

    .line 98
    goto :goto_2

    .line 99
    :catchall_0
    move-exception v6

    .line 100
    invoke-virtual {v7}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v14

    .line 104
    invoke-static {v14}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 105
    .line 106
    .line 107
    move-result-object v14

    .line 108
    sget-object v15, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 109
    .line 110
    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    invoke-virtual {v5, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v6

    .line 118
    invoke-virtual {v14, v15, v3, v1, v6}, Ljava/util/logging/Logger;->logp(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :goto_2
    sput-boolean v6, Lcom/google/android/gms/internal/measurement/w6;->d:Z

    .line 123
    .line 124
    sget-object v6, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 125
    .line 126
    if-nez v6, :cond_5

    .line 127
    .line 128
    :goto_3
    move v0, v12

    .line 129
    goto :goto_4

    .line 130
    :cond_5
    iget-object v6, v6, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 131
    .line 132
    :try_start_1
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    filled-new-array {v9}, [Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    move-result-object v9

    .line 140
    invoke-virtual {v6, v10, v9}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 141
    .line 142
    .line 143
    const-string v9, "arrayBaseOffset"

    .line 144
    .line 145
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    move-result-object v10

    .line 149
    invoke-virtual {v6, v9, v10}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 150
    .line 151
    .line 152
    const-string v9, "arrayIndexScale"

    .line 153
    .line 154
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    invoke-virtual {v6, v9, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 159
    .line 160
    .line 161
    const-string v0, "getInt"

    .line 162
    .line 163
    filled-new-array {v13, v2}, [Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    move-result-object v9

    .line 167
    invoke-virtual {v6, v0, v9}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 168
    .line 169
    .line 170
    const-string v0, "putInt"

    .line 171
    .line 172
    filled-new-array {v13, v2, v4}, [Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    invoke-virtual {v6, v0, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 177
    .line 178
    .line 179
    filled-new-array {v13, v2}, [Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    invoke-virtual {v6, v8, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 184
    .line 185
    .line 186
    const-string v0, "putLong"

    .line 187
    .line 188
    filled-new-array {v13, v2, v2}, [Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    invoke-virtual {v6, v0, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 193
    .line 194
    .line 195
    const-string v0, "getObject"

    .line 196
    .line 197
    filled-new-array {v13, v2}, [Ljava/lang/Class;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-virtual {v6, v0, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 202
    .line 203
    .line 204
    const-string v0, "putObject"

    .line 205
    .line 206
    filled-new-array {v13, v2, v13}, [Ljava/lang/Class;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    invoke-virtual {v6, v0, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 211
    .line 212
    .line 213
    move v0, v11

    .line 214
    goto :goto_4

    .line 215
    :catchall_1
    move-exception v0

    .line 216
    invoke-virtual {v7}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    invoke-static {v2}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    sget-object v4, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 225
    .line 226
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    invoke-virtual {v5, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    invoke-virtual {v2, v4, v3, v1, v0}, Ljava/util/logging/Logger;->logp(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    goto :goto_3

    .line 238
    :goto_4
    sput-boolean v0, Lcom/google/android/gms/internal/measurement/w6;->e:Z

    .line 239
    .line 240
    const-class v0, [B

    .line 241
    .line 242
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 243
    .line 244
    .line 245
    move-result v0

    .line 246
    int-to-long v0, v0

    .line 247
    sput-wide v0, Lcom/google/android/gms/internal/measurement/w6;->f:J

    .line 248
    .line 249
    const-class v0, [Z

    .line 250
    .line 251
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 252
    .line 253
    .line 254
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 255
    .line 256
    .line 257
    const-class v0, [I

    .line 258
    .line 259
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 260
    .line 261
    .line 262
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 263
    .line 264
    .line 265
    const-class v0, [J

    .line 266
    .line 267
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 268
    .line 269
    .line 270
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 271
    .line 272
    .line 273
    const-class v0, [F

    .line 274
    .line 275
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 276
    .line 277
    .line 278
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 279
    .line 280
    .line 281
    const-class v0, [D

    .line 282
    .line 283
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 284
    .line 285
    .line 286
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 287
    .line 288
    .line 289
    const-class v0, [Ljava/lang/Object;

    .line 290
    .line 291
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->p(Ljava/lang/Class;)I

    .line 292
    .line 293
    .line 294
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/w6;->a(Ljava/lang/Class;)V

    .line 295
    .line 296
    .line 297
    invoke-static {}, Lcom/google/android/gms/internal/measurement/w6;->b()Ljava/lang/reflect/Field;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    if-eqz v0, :cond_6

    .line 302
    .line 303
    sget-object v1, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 304
    .line 305
    if-eqz v1, :cond_6

    .line 306
    .line 307
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 308
    .line 309
    invoke-virtual {v1, v0}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 310
    .line 311
    .line 312
    :cond_6
    invoke-static {}, Ljava/nio/ByteOrder;->nativeOrder()Ljava/nio/ByteOrder;

    .line 313
    .line 314
    .line 315
    move-result-object v0

    .line 316
    sget-object v1, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 317
    .line 318
    if-ne v0, v1, :cond_7

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_7
    move v11, v12

    .line 322
    :goto_5
    sput-boolean v11, Lcom/google/android/gms/internal/measurement/w6;->g:Z

    .line 323
    .line 324
    return-void
.end method

.method public static a(Ljava/lang/Class;)V
    .locals 1

    .line 1
    sget-boolean v0, Lcom/google/android/gms/internal/measurement/w6;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 6
    .line 7
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lsun/misc/Unsafe;->arrayIndexScale(Ljava/lang/Class;)I

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public static b()Ljava/lang/reflect/Field;
    .locals 4

    .line 1
    sget v0, Lcom/google/android/gms/internal/measurement/v4;->a:I

    .line 2
    .line 3
    const-class v0, Ljava/nio/Buffer;

    .line 4
    .line 5
    const-string v1, "effectiveDirectAddress"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :try_start_0
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 9
    .line 10
    .line 11
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-object v1, v2

    .line 14
    :goto_0
    if-nez v1, :cond_1

    .line 15
    .line 16
    const-string v1, "address"

    .line 17
    .line 18
    :try_start_1
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 19
    .line 20
    .line 21
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 22
    goto :goto_1

    .line 23
    :catchall_1
    move-object v0, v2

    .line 24
    :goto_1
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    sget-object v3, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 31
    .line 32
    if-ne v1, v3, :cond_0

    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_0
    return-object v2

    .line 36
    :cond_1
    return-object v1
.end method

.method public static c(Ljava/lang/Object;JB)V
    .locals 5

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    const-wide/16 v1, -0x4

    .line 6
    .line 7
    and-long/2addr v1, p1

    .line 8
    invoke-virtual {v0, p0, v1, v2}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    long-to-int p1, p1

    .line 13
    not-int p1, p1

    .line 14
    and-int/lit8 p1, p1, 0x3

    .line 15
    .line 16
    shl-int/lit8 p1, p1, 0x3

    .line 17
    .line 18
    const/16 p2, 0xff

    .line 19
    .line 20
    shl-int v4, p2, p1

    .line 21
    .line 22
    not-int v4, v4

    .line 23
    and-int/2addr v3, v4

    .line 24
    and-int/2addr p2, p3

    .line 25
    shl-int p1, p2, p1

    .line 26
    .line 27
    or-int/2addr p1, v3

    .line 28
    invoke-virtual {v0, p0, v1, v2, p1}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public static d(Ljava/lang/Object;JB)V
    .locals 5

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    const-wide/16 v1, -0x4

    .line 6
    .line 7
    and-long/2addr v1, p1

    .line 8
    invoke-virtual {v0, p0, v1, v2}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    long-to-int p1, p1

    .line 13
    and-int/lit8 p1, p1, 0x3

    .line 14
    .line 15
    shl-int/lit8 p1, p1, 0x3

    .line 16
    .line 17
    const/16 p2, 0xff

    .line 18
    .line 19
    shl-int v4, p2, p1

    .line 20
    .line 21
    not-int v4, v4

    .line 22
    and-int/2addr v3, v4

    .line 23
    and-int/2addr p2, p3

    .line 24
    shl-int p1, p2, p1

    .line 25
    .line 26
    or-int/2addr p1, v3

    .line 27
    invoke-virtual {v0, p0, v1, v2, p1}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static e(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1

    .line 1
    :try_start_0
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->a:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lsun/misc/Unsafe;->allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    return-object p0

    .line 8
    :catch_0
    move-exception p0

    .line 9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 12
    .line 13
    .line 14
    throw v0
.end method

.method public static f(JLjava/lang/Object;)I
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    invoke-virtual {v0, p2, p0, p1}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static g(JLjava/lang/Object;I)V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    invoke-virtual {v0, p2, p0, p1, p3}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static h(JLjava/lang/Object;)J
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    invoke-virtual {v0, p2, p0, p1}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public static i(JLjava/lang/Object;J)V
    .locals 7

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    move-wide v3, p0

    .line 6
    move-object v2, p2

    .line 7
    move-wide v5, p3

    .line 8
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static j(JLjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    invoke-virtual {v0, p2, p0, p1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static k(Ljava/lang/Object;JLjava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1, p2, p3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static l()Lsun/misc/Unsafe;
    .locals 1

    .line 1
    :try_start_0
    new-instance v0, Lcom/google/android/gms/internal/measurement/s6;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Ljava/security/AccessController;->doPrivileged(Ljava/security/PrivilegedExceptionAction;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lsun/misc/Unsafe;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    return-object v0

    .line 13
    :catchall_0
    const/4 v0, 0x0

    .line 14
    return-object v0
.end method

.method public static m(Ljava/lang/Class;)Z
    .locals 6

    .line 1
    const-class v0, [B

    .line 2
    .line 3
    sget v1, Lcom/google/android/gms/internal/measurement/v4;->a:I

    .line 4
    .line 5
    :try_start_0
    sget-object v1, Lcom/google/android/gms/internal/measurement/w6;->b:Ljava/lang/Class;

    .line 6
    .line 7
    const-string v2, "peekLong"

    .line 8
    .line 9
    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 10
    .line 11
    filled-new-array {p0, v3}, [Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    invoke-virtual {v1, v2, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 16
    .line 17
    .line 18
    const-string v2, "pokeLong"

    .line 19
    .line 20
    sget-object v4, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 21
    .line 22
    filled-new-array {p0, v4, v3}, [Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-virtual {v1, v2, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 27
    .line 28
    .line 29
    const-string v2, "pokeInt"

    .line 30
    .line 31
    sget-object v4, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 32
    .line 33
    filled-new-array {p0, v4, v3}, [Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    invoke-virtual {v1, v2, v5}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 38
    .line 39
    .line 40
    const-string v2, "peekInt"

    .line 41
    .line 42
    filled-new-array {p0, v3}, [Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 47
    .line 48
    .line 49
    const-string v2, "pokeByte"

    .line 50
    .line 51
    sget-object v3, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 52
    .line 53
    filled-new-array {p0, v3}, [Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 58
    .line 59
    .line 60
    const-string v2, "peekByte"

    .line 61
    .line 62
    filled-new-array {p0}, [Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 67
    .line 68
    .line 69
    const-string v2, "pokeByteArray"

    .line 70
    .line 71
    filled-new-array {p0, v0, v4, v4}, [Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 76
    .line 77
    .line 78
    const-string v2, "peekByteArray"

    .line 79
    .line 80
    filled-new-array {p0, v0, v4, v4}, [Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-virtual {v1, v2, p0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    .line 86
    .line 87
    const/4 p0, 0x1

    .line 88
    return p0

    .line 89
    :catchall_0
    const/4 p0, 0x0

    .line 90
    return p0
.end method

.method public static synthetic n(JLjava/lang/Object;)Z
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    const-wide/16 v1, -0x4

    .line 6
    .line 7
    and-long/2addr v1, p0

    .line 8
    invoke-virtual {v0, p2, v1, v2}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    not-long p0, p0

    .line 13
    const-wide/16 v0, 0x3

    .line 14
    .line 15
    and-long/2addr p0, v0

    .line 16
    const/4 v0, 0x3

    .line 17
    shl-long/2addr p0, v0

    .line 18
    long-to-int p0, p0

    .line 19
    ushr-int p0, p2, p0

    .line 20
    .line 21
    and-int/lit16 p0, p0, 0xff

    .line 22
    .line 23
    int-to-byte p0, p0

    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public static synthetic o(JLjava/lang/Object;)Z
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 4
    .line 5
    const-wide/16 v1, -0x4

    .line 6
    .line 7
    and-long/2addr v1, p0

    .line 8
    invoke-virtual {v0, p2, v1, v2}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    const-wide/16 v0, 0x3

    .line 13
    .line 14
    and-long/2addr p0, v0

    .line 15
    const/4 v0, 0x3

    .line 16
    shl-long/2addr p0, v0

    .line 17
    long-to-int p0, p0

    .line 18
    ushr-int p0, p2, p0

    .line 19
    .line 20
    and-int/lit16 p0, p0, 0xff

    .line 21
    .line 22
    int-to-byte p0, p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public static p(Ljava/lang/Class;)I
    .locals 1

    .line 1
    sget-boolean v0, Lcom/google/android/gms/internal/measurement/w6;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/google/android/gms/internal/measurement/w6;->c:Lcom/google/android/gms/internal/measurement/v6;

    .line 6
    .line 7
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/v6;->a:Lsun/misc/Unsafe;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lsun/misc/Unsafe;->arrayBaseOffset(Ljava/lang/Class;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, -0x1

    .line 15
    return p0
.end method
