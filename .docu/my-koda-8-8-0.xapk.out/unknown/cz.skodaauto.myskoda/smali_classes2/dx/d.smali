.class public final Ldx/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

.field public final synthetic g:Ljava/util/Date;

.field public final synthetic h:Ldx/i;

.field public final synthetic i:Lkotlin/jvm/internal/f0;

.field public final synthetic j:Lfx/a;


# direct methods
.method public constructor <init>(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;Ljava/util/Date;Ldx/i;Lkotlin/jvm/internal/f0;Lfx/a;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ldx/d;->f:Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 2
    .line 3
    iput-object p2, p0, Ldx/d;->g:Ljava/util/Date;

    .line 4
    .line 5
    iput-object p3, p0, Ldx/d;->h:Ldx/i;

    .line 6
    .line 7
    iput-object p4, p0, Ldx/d;->i:Lkotlin/jvm/internal/f0;

    .line 8
    .line 9
    iput-object p5, p0, Ldx/d;->j:Lfx/a;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 6
    .line 7
    iget-object v2, v0, Ldx/d;->h:Ldx/i;

    .line 8
    .line 9
    iget-object v2, v2, Ldx/i;->a:Ldx/k;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {v1}, Lcom/wultra/android/sslpinning/model/CachedData;->getCertificates()[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    :cond_0
    new-array v1, v3, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 21
    .line 22
    :cond_1
    new-instance v4, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    array-length v5, v1

    .line 28
    move v6, v3

    .line 29
    :goto_0
    iget-object v7, v0, Ldx/d;->g:Ljava/util/Date;

    .line 30
    .line 31
    if-ge v6, v5, :cond_3

    .line 32
    .line 33
    aget-object v8, v1, v6

    .line 34
    .line 35
    invoke-virtual {v8, v7}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->isExpired$library_release(Ljava/util/Date;)Z

    .line 36
    .line 37
    .line 38
    move-result v7

    .line 39
    if-nez v7, :cond_2

    .line 40
    .line 41
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_3
    invoke-static {v4}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    iget-object v4, v0, Ldx/d;->f:Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 52
    .line 53
    invoke-virtual {v4}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->getFingerprints()[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    array-length v5, v4

    .line 58
    move v6, v3

    .line 59
    :goto_1
    const-string v8, "Wultra-SSL-Pinning"

    .line 60
    .line 61
    iget-object v9, v0, Ldx/d;->i:Lkotlin/jvm/internal/f0;

    .line 62
    .line 63
    if-ge v6, v5, :cond_8

    .line 64
    .line 65
    aget-object v10, v4, v6

    .line 66
    .line 67
    new-instance v11, Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 68
    .line 69
    invoke-direct {v11, v10}, Lcom/wultra/android/sslpinning/model/CertificateInfo;-><init>(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v11, v7}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->isExpired$library_release(Ljava/util/Date;)Z

    .line 73
    .line 74
    .line 75
    move-result v12

    .line 76
    if-eqz v12, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 80
    .line 81
    .line 82
    move-result v12

    .line 83
    const/4 v13, -0x1

    .line 84
    if-eq v12, v13, :cond_5

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_5
    iget-boolean v12, v2, Ldx/k;->c:Z

    .line 88
    .line 89
    if-nez v12, :cond_7

    .line 90
    .line 91
    invoke-virtual {v10}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->dataForSignature$library_release()Lgx/a;

    .line 92
    .line 93
    .line 94
    move-result-object v12

    .line 95
    const/16 v13, 0x27

    .line 96
    .line 97
    const-string v14, "message"

    .line 98
    .line 99
    if-nez v12, :cond_6

    .line 100
    .line 101
    new-instance v0, Ljava/lang/StringBuilder;

    .line 102
    .line 103
    const-string v4, "CertStore: Failed to prepare data for signature validation. CN = \'"

    .line 104
    .line 105
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v10}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->getName()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v4

    .line 112
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-static {v8, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 126
    .line 127
    .line 128
    sget-object v0, Ldx/l;->g:Ldx/l;

    .line 129
    .line 130
    iput-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_6
    iget-object v15, v12, Lgx/a;->a:[B

    .line 134
    .line 135
    iget-object v12, v12, Lgx/a;->b:[B

    .line 136
    .line 137
    iget-object v3, v0, Ldx/d;->j:Lfx/a;

    .line 138
    .line 139
    iget-object v3, v3, Lfx/a;->a:Lio/getlime/security/powerauth/core/EcPublicKey;

    .line 140
    .line 141
    invoke-static {v15, v12, v3}, Lio/getlime/security/powerauth/core/CryptoUtils;->ecdsaValidateSignature([B[BLio/getlime/security/powerauth/core/EcPublicKey;)Z

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    if-nez v3, :cond_7

    .line 146
    .line 147
    new-instance v0, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    const-string v3, "CertStore: Invalid signature detected. CN = \'"

    .line 150
    .line 151
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v10}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->getName()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    invoke-static {v8, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 172
    .line 173
    .line 174
    sget-object v0, Ldx/l;->h:Ldx/l;

    .line 175
    .line 176
    iput-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_7
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    :goto_2
    add-int/lit8 v6, v6, 0x1

    .line 183
    .line 184
    const/4 v3, 0x0

    .line 185
    goto :goto_1

    .line 186
    :cond_8
    :goto_3
    iget-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 187
    .line 188
    sget-object v3, Ldx/l;->d:Ldx/l;

    .line 189
    .line 190
    if-ne v0, v3, :cond_9

    .line 191
    .line 192
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-eqz v0, :cond_9

    .line 197
    .line 198
    const-string v0, "CertStore: Database after update is still empty."

    .line 199
    .line 200
    invoke-static {v8, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 201
    .line 202
    .line 203
    sget-object v0, Ldx/l;->e:Ldx/l;

    .line 204
    .line 205
    iput-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 206
    .line 207
    :cond_9
    iget-object v0, v9, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 208
    .line 209
    if-eq v0, v3, :cond_a

    .line 210
    .line 211
    const/4 v0, 0x0

    .line 212
    return-object v0

    .line 213
    :cond_a
    invoke-static {v1}, Lmx0/q;->m0(Ljava/util/List;)V

    .line 214
    .line 215
    .line 216
    const/4 v0, 0x0

    .line 217
    new-array v3, v0, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 218
    .line 219
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    check-cast v1, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 224
    .line 225
    iget-wide v3, v2, Ldx/k;->d:J

    .line 226
    .line 227
    iget-wide v5, v2, Ldx/k;->e:J

    .line 228
    .line 229
    const-string v2, "certificates"

    .line 230
    .line 231
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    new-instance v2, Ljava/util/LinkedHashSet;

    .line 235
    .line 236
    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v7}, Ljava/util/Date;->getTime()J

    .line 240
    .line 241
    .line 242
    move-result-wide v8

    .line 243
    sget-object v10, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 244
    .line 245
    const-wide/16 v11, 0xe42

    .line 246
    .line 247
    invoke-virtual {v10, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 248
    .line 249
    .line 250
    move-result-wide v10

    .line 251
    add-long/2addr v10, v8

    .line 252
    array-length v8, v1

    .line 253
    :goto_4
    if-ge v0, v8, :cond_c

    .line 254
    .line 255
    aget-object v9, v1, v0

    .line 256
    .line 257
    invoke-virtual {v9}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->getCommonName()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object v12

    .line 261
    invoke-interface {v2, v12}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v12

    .line 265
    if-eqz v12, :cond_b

    .line 266
    .line 267
    goto :goto_5

    .line 268
    :cond_b
    invoke-virtual {v9}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->getCommonName()Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v12

    .line 272
    invoke-interface {v2, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    invoke-virtual {v9}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->getExpires()Ljava/util/Date;

    .line 276
    .line 277
    .line 278
    move-result-object v9

    .line 279
    invoke-virtual {v9}, Ljava/util/Date;->getTime()J

    .line 280
    .line 281
    .line 282
    move-result-wide v12

    .line 283
    invoke-static {v10, v11, v12, v13}, Ljava/lang/Math;->min(JJ)J

    .line 284
    .line 285
    .line 286
    move-result-wide v9

    .line 287
    move-wide v10, v9

    .line 288
    :goto_5
    add-int/lit8 v0, v0, 0x1

    .line 289
    .line 290
    goto :goto_4

    .line 291
    :cond_c
    invoke-virtual {v7}, Ljava/util/Date;->getTime()J

    .line 292
    .line 293
    .line 294
    move-result-wide v8

    .line 295
    sub-long/2addr v10, v8

    .line 296
    const-wide/16 v8, 0x0

    .line 297
    .line 298
    cmp-long v0, v10, v8

    .line 299
    .line 300
    if-lez v0, :cond_d

    .line 301
    .line 302
    cmp-long v0, v10, v5

    .line 303
    .line 304
    if-gez v0, :cond_e

    .line 305
    .line 306
    long-to-double v5, v10

    .line 307
    const-wide/high16 v8, 0x3fc0000000000000L    # 0.125

    .line 308
    .line 309
    mul-double/2addr v5, v8

    .line 310
    invoke-static {v5, v6}, Ljava/lang/Math;->round(D)J

    .line 311
    .line 312
    .line 313
    move-result-wide v10

    .line 314
    goto :goto_6

    .line 315
    :cond_d
    move-wide v10, v8

    .line 316
    :cond_e
    :goto_6
    invoke-static {v10, v11, v3, v4}, Ljava/lang/Math;->min(JJ)J

    .line 317
    .line 318
    .line 319
    move-result-wide v2

    .line 320
    new-instance v0, Ljava/util/Date;

    .line 321
    .line 322
    invoke-virtual {v7}, Ljava/util/Date;->getTime()J

    .line 323
    .line 324
    .line 325
    move-result-wide v4

    .line 326
    add-long/2addr v4, v2

    .line 327
    invoke-direct {v0, v4, v5}, Ljava/util/Date;-><init>(J)V

    .line 328
    .line 329
    .line 330
    new-instance v2, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 331
    .line 332
    invoke-direct {v2, v1, v0}, Lcom/wultra/android/sslpinning/model/CachedData;-><init>([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)V

    .line 333
    .line 334
    .line 335
    return-object v2
.end method
