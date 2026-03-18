.class public abstract Lzl0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz70/e0;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Le21/a;

    .line 9
    .line 10
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lz70/e0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    sput-object v1, Lzl0/b;->a:Le21/a;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;Z)Ld01/h0;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serviceLabel"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    new-instance v1, Ldm0/m;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-direct {v1, v2}, Ldm0/m;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    new-instance v1, Ldm0/m;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v1, v2}, Ldm0/m;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    const-class v1, Lxl0/o;

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    if-eqz p1, :cond_0

    .line 37
    .line 38
    new-instance v3, Ldm0/b;

    .line 39
    .line 40
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 41
    .line 42
    invoke-virtual {v4, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    invoke-virtual {p0, v4, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Lxl0/o;

    .line 51
    .line 52
    invoke-direct {v3, v4, p1}, Ldm0/b;-><init>(Lxl0/o;Lxl0/g;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, v3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    :cond_0
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 59
    .line 60
    const-class v3, Ldm0/b;

    .line 61
    .line 62
    invoke-virtual {p1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {p0, v3, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v0, v3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    if-eqz p2, :cond_1

    .line 74
    .line 75
    new-instance v3, Ldm0/b;

    .line 76
    .line 77
    invoke-virtual {p1, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {p0, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    check-cast v1, Lxl0/o;

    .line 86
    .line 87
    invoke-direct {v3, v1, p2}, Ldm0/b;-><init>(Lxl0/o;Ljava/util/List;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v3}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    :cond_1
    const-class p2, Ldm0/i;

    .line 94
    .line 95
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    invoke-virtual {p0, p2, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    invoke-virtual {v0, p2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    if-eqz p7, :cond_2

    .line 107
    .line 108
    const-class p2, Lim0/a;

    .line 109
    .line 110
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    invoke-virtual {p0, p2, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    check-cast p2, Lim0/a;

    .line 119
    .line 120
    iput-object p4, p2, Lim0/a;->b:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {v0, p2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    const-class p2, Lt01/c;

    .line 126
    .line 127
    invoke-virtual {p1, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-virtual {p0, p1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-virtual {v0, p0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    :cond_2
    if-eqz p6, :cond_3

    .line 139
    .line 140
    invoke-virtual {v0, p6}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    :cond_3
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    new-instance p1, Ld01/g0;

    .line 148
    .line 149
    invoke-direct {p1}, Ld01/g0;-><init>()V

    .line 150
    .line 151
    .line 152
    sget-object p2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 153
    .line 154
    const-wide/16 p6, 0x1e

    .line 155
    .line 156
    invoke-virtual {p1, p6, p7, p2}, Ld01/g0;->b(JLjava/util/concurrent/TimeUnit;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1, p6, p7, p2}, Ld01/g0;->f(JLjava/util/concurrent/TimeUnit;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p1, p6, p7, p2}, Ld01/g0;->d(JLjava/util/concurrent/TimeUnit;)V

    .line 163
    .line 164
    .line 165
    if-eqz p0, :cond_4

    .line 166
    .line 167
    const/4 p2, 0x0

    .line 168
    invoke-virtual {p0, p2}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    :goto_0
    move-object p2, p0

    .line 173
    check-cast p2, Lnx0/a;

    .line 174
    .line 175
    invoke-virtual {p2}, Lnx0/a;->hasNext()Z

    .line 176
    .line 177
    .line 178
    move-result p4

    .line 179
    if-eqz p4, :cond_4

    .line 180
    .line 181
    invoke-virtual {p2}, Lnx0/a;->next()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p2

    .line 185
    check-cast p2, Ld01/c0;

    .line 186
    .line 187
    invoke-virtual {p1, p2}, Ld01/g0;->a(Ld01/c0;)V

    .line 188
    .line 189
    .line 190
    goto :goto_0

    .line 191
    :cond_4
    if-eqz p3, :cond_5

    .line 192
    .line 193
    iput-object p3, p1, Ld01/g0;->h:Ld01/c;

    .line 194
    .line 195
    :cond_5
    if-eqz p5, :cond_6

    .line 196
    .line 197
    new-instance p0, Lex/a;

    .line 198
    .line 199
    invoke-direct {p0, p5}, Lex/a;-><init>(Ldx/i;)V

    .line 200
    .line 201
    .line 202
    const-string p2, "X509"

    .line 203
    .line 204
    invoke-static {p2}, Ljavax/net/ssl/TrustManagerFactory;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;

    .line 205
    .line 206
    .line 207
    move-result-object p2

    .line 208
    invoke-virtual {p2, v2}, Ljavax/net/ssl/TrustManagerFactory;->init(Ljava/security/KeyStore;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {p2}, Ljavax/net/ssl/TrustManagerFactory;->getTrustManagers()[Ljavax/net/ssl/TrustManager;

    .line 212
    .line 213
    .line 214
    move-result-object p2

    .line 215
    new-instance p3, Ld01/x;

    .line 216
    .line 217
    const/4 p4, 0x2

    .line 218
    invoke-direct {p3, p4}, Ld01/x;-><init>(I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {p3, p0}, Ld01/x;->b(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    const-string p0, "originalTrustManagers"

    .line 225
    .line 226
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {p3, p2}, Ld01/x;->g(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    iget-object p0, p3, Ld01/x;->b:Ljava/util/ArrayList;

    .line 233
    .line 234
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 235
    .line 236
    .line 237
    move-result p2

    .line 238
    new-array p2, p2, [Ljavax/net/ssl/TrustManager;

    .line 239
    .line 240
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    check-cast p0, [Ljavax/net/ssl/TrustManager;

    .line 245
    .line 246
    :try_start_0
    const-string p2, "TLS"

    .line 247
    .line 248
    invoke-static {p2}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    .line 249
    .line 250
    .line 251
    move-result-object p2

    .line 252
    invoke-virtual {p2, v2, p0, v2}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p2}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    const-string p2, "sc.socketFactory"

    .line 260
    .line 261
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/KeyManagementException; {:try_start_0 .. :try_end_0} :catch_0

    .line 262
    .line 263
    .line 264
    new-instance p2, Lex/a;

    .line 265
    .line 266
    invoke-direct {p2, p5}, Lex/a;-><init>(Ldx/i;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p1, p0, p2}, Ld01/g0;->e(Ljavax/net/ssl/SSLSocketFactory;Ljavax/net/ssl/X509TrustManager;)V

    .line 270
    .line 271
    .line 272
    goto :goto_1

    .line 273
    :catch_0
    move-exception p0

    .line 274
    new-instance p1, Ljava/lang/RuntimeException;

    .line 275
    .line 276
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 277
    .line 278
    .line 279
    throw p1

    .line 280
    :catch_1
    move-exception p0

    .line 281
    new-instance p1, Ljava/lang/RuntimeException;

    .line 282
    .line 283
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 284
    .line 285
    .line 286
    throw p1

    .line 287
    :cond_6
    new-instance p0, Ldc/a;

    .line 288
    .line 289
    const/16 p2, 0xa

    .line 290
    .line 291
    invoke-direct {p0, p2}, Ldc/a;-><init>(I)V

    .line 292
    .line 293
    .line 294
    invoke-static {v2, p1, p0}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 295
    .line 296
    .line 297
    :goto_1
    new-instance p0, Ld01/h0;

    .line 298
    .line 299
    invoke-direct {p0, p1}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 300
    .line 301
    .line 302
    return-object p0
.end method

.method public static synthetic b(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;I)Ld01/h0;
    .locals 2

    .line 1
    and-int/lit8 v0, p7, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p7, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    move-object p2, v1

    .line 12
    :cond_1
    and-int/lit8 v0, p7, 0x4

    .line 13
    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    move-object p3, v1

    .line 17
    :cond_2
    and-int/lit8 v0, p7, 0x8

    .line 18
    .line 19
    if-eqz v0, :cond_3

    .line 20
    .line 21
    const-string p4, "unknown"

    .line 22
    .line 23
    :cond_3
    and-int/lit8 v0, p7, 0x10

    .line 24
    .line 25
    if-eqz v0, :cond_4

    .line 26
    .line 27
    move-object p5, v1

    .line 28
    :cond_4
    and-int/lit8 p7, p7, 0x20

    .line 29
    .line 30
    if-eqz p7, :cond_5

    .line 31
    .line 32
    move-object p6, v1

    .line 33
    :cond_5
    const/4 p7, 0x1

    .line 34
    invoke-static/range {p0 .. p7}, Lzl0/b;->a(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;Z)Ld01/h0;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static final c(Lk21/a;Ld01/h0;)Lretrofit2/Retrofit;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "okHttpClient"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lretrofit2/Retrofit$Builder;

    .line 12
    .line 13
    invoke-direct {p0}, Lretrofit2/Retrofit$Builder;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lretrofit2/Retrofit$Builder;->a:Ld01/i;

    .line 17
    .line 18
    const-string p1, "https://myskoda.com/"

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lretrofit2/Retrofit$Builder;->c(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance p1, Lcom/squareup/moshi/Moshi$Builder;

    .line 24
    .line 25
    invoke-direct {p1}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v0, Lbx/d;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/LocalDateAdapter;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/URIAdapter;

    .line 45
    .line 46
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/OffsetDateTimeAdapter;

    .line 53
    .line 54
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/BigDecimalAdapter;

    .line 61
    .line 62
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/UUIDAdapter;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p1, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Lcom/squareup/moshi/Moshi;

    .line 77
    .line 78
    invoke-direct {v0, p1}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 79
    .line 80
    .line 81
    new-instance p1, Lretrofit2/converter/moshi/MoshiConverterFactory;

    .line 82
    .line 83
    invoke-direct {p1, v0}, Lretrofit2/converter/moshi/MoshiConverterFactory;-><init>(Lcom/squareup/moshi/Moshi;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lretrofit2/Retrofit$Builder;->b(Lretrofit2/Converter$Factory;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0}, Lretrofit2/Retrofit$Builder;->d()Lretrofit2/Retrofit;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method
