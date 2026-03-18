.class public final Ldu/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:J

.field public static final j:[I


# instance fields
.field public final a:Lht/d;

.field public final b:Lgt/b;

.field public final c:Ljava/util/concurrent/Executor;

.field public final d:Ljava/util/Random;

.field public final e:Ldu/c;

.field public final f:Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;

.field public final g:Ldu/n;

.field public final h:Ljava/util/Map;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->HOURS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    const-wide/16 v1, 0xc

    .line 4
    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sput-wide v0, Ldu/i;->i:J

    .line 10
    .line 11
    const/16 v0, 0x8

    .line 12
    .line 13
    new-array v0, v0, [I

    .line 14
    .line 15
    fill-array-data v0, :array_0

    .line 16
    .line 17
    .line 18
    sput-object v0, Ldu/i;->j:[I

    .line 19
    .line 20
    return-void

    .line 21
    :array_0
    .array-data 4
        0x2
        0x4
        0x8
        0x10
        0x20
        0x40
        0x80
        0x100
    .end array-data
.end method

.method public constructor <init>(Lht/d;Lgt/b;Ljava/util/concurrent/Executor;Ljava/util/Random;Ldu/c;Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;Ldu/n;Ljava/util/HashMap;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldu/i;->a:Lht/d;

    .line 5
    .line 6
    iput-object p2, p0, Ldu/i;->b:Lgt/b;

    .line 7
    .line 8
    iput-object p3, p0, Ldu/i;->c:Ljava/util/concurrent/Executor;

    .line 9
    .line 10
    iput-object p4, p0, Ldu/i;->d:Ljava/util/Random;

    .line 11
    .line 12
    iput-object p5, p0, Ldu/i;->e:Ldu/c;

    .line 13
    .line 14
    iput-object p6, p0, Ldu/i;->f:Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;

    .line 15
    .line 16
    iput-object p7, p0, Ldu/i;->g:Ldu/n;

    .line 17
    .line 18
    iput-object p8, p0, Ldu/i;->h:Ljava/util/Map;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(J)Laq/t;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    iget-object v1, p0, Ldu/i;->h:Ljava/util/Map;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "X-Firebase-RC-Fetch-Type"

    .line 9
    .line 10
    const-string v2, "BASE/1"

    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    iget-object v1, p0, Ldu/i;->e:Ldu/c;

    .line 16
    .line 17
    invoke-virtual {v1}, Ldu/c;->b()Laq/j;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Ldu/f;

    .line 22
    .line 23
    invoke-direct {v2, p0, p1, p2, v0}, Ldu/f;-><init>(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Ldu/i;->c:Ljava/util/concurrent/Executor;

    .line 27
    .line 28
    invoke-virtual {v1, p0, v2}, Laq/j;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/util/HashMap;)Ldu/h;
    .locals 12

    .line 1
    const/4 v1, 0x1

    .line 2
    :try_start_0
    iget-object v0, p0, Ldu/i;->f:Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;

    .line 3
    .line 4
    invoke-virtual {v0}, Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;->b()Ljava/net/HttpURLConnection;

    .line 5
    .line 6
    .line 7
    move-result-object v3

    .line 8
    iget-object v2, p0, Ldu/i;->f:Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;

    .line 9
    .line 10
    invoke-virtual {p0}, Ldu/i;->e()Ljava/util/HashMap;

    .line 11
    .line 12
    .line 13
    move-result-object v6

    .line 14
    iget-object v0, p0, Ldu/i;->g:Ldu/n;

    .line 15
    .line 16
    iget-object v0, v0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 17
    .line 18
    const-string v4, "last_fetch_etag"

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    invoke-interface {v0, v4, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    iget-object v0, p0, Ldu/i;->b:Lgt/b;

    .line 26
    .line 27
    invoke-interface {v0}, Lgt/b;->get()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lwr/b;

    .line 32
    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    :goto_0
    move-object v9, v5

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    check-cast v0, Lwr/c;

    .line 38
    .line 39
    iget-object v0, v0, Lwr/c;->a:Lro/f;

    .line 40
    .line 41
    iget-object v0, v0, Lro/f;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lcom/google/android/gms/internal/measurement/k1;

    .line 44
    .line 45
    invoke-virtual {v0, v5, v5, v1}, Lcom/google/android/gms/internal/measurement/k1;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/util/Map;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    const-string v4, "_fot"

    .line 50
    .line 51
    invoke-interface {v0, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    move-object v5, v0

    .line 56
    check-cast v5, Ljava/lang/Long;

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :goto_1
    iget-object v0, p0, Ldu/i;->g:Ldu/n;

    .line 60
    .line 61
    invoke-virtual {v0}, Ldu/n;->b()Ljava/util/HashMap;

    .line 62
    .line 63
    .line 64
    move-result-object v11

    .line 65
    move-object v4, p1

    .line 66
    move-object v5, p2

    .line 67
    move-object v10, p3

    .line 68
    move-object/from16 v8, p4

    .line 69
    .line 70
    invoke-virtual/range {v2 .. v11}, Lcom/google/firebase/remoteconfig/internal/ConfigFetchHttpClient;->fetch(Ljava/net/HttpURLConnection;Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/util/Map;Ljava/lang/Long;Ljava/util/Date;Ljava/util/Map;)Ldu/h;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    iget-object p2, p1, Ldu/h;->b:Ldu/e;

    .line 75
    .line 76
    if-eqz p2, :cond_1

    .line 77
    .line 78
    iget-object v0, p0, Ldu/i;->g:Ldu/n;

    .line 79
    .line 80
    iget-wide v2, p2, Ldu/e;->f:J

    .line 81
    .line 82
    iget-object p2, v0, Ldu/n;->b:Ljava/lang/Object;

    .line 83
    .line 84
    monitor-enter p2
    :try_end_0
    .catch Lcu/f; {:try_start_0 .. :try_end_0} :catch_0

    .line 85
    :try_start_1
    iget-object v0, v0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 86
    .line 87
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    const-string v4, "last_template_version"

    .line 92
    .line 93
    invoke-interface {v0, v4, v2, v3}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 98
    .line 99
    .line 100
    monitor-exit p2

    .line 101
    goto :goto_2

    .line 102
    :catchall_0
    move-exception v0

    .line 103
    move-object p1, v0

    .line 104
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 105
    :try_start_2
    throw p1

    .line 106
    :catch_0
    move-exception v0

    .line 107
    move-object p1, v0

    .line 108
    goto :goto_4

    .line 109
    :cond_1
    :goto_2
    iget-object p2, p1, Ldu/h;->c:Ljava/lang/String;

    .line 110
    .line 111
    if-eqz p2, :cond_2

    .line 112
    .line 113
    iget-object v0, p0, Ldu/i;->g:Ldu/n;

    .line 114
    .line 115
    iget-object v2, v0, Ldu/n;->b:Ljava/lang/Object;

    .line 116
    .line 117
    monitor-enter v2
    :try_end_2
    .catch Lcu/f; {:try_start_2 .. :try_end_2} :catch_0

    .line 118
    :try_start_3
    iget-object v0, v0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 119
    .line 120
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    const-string v3, "last_fetch_etag"

    .line 125
    .line 126
    invoke-interface {v0, v3, p2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 127
    .line 128
    .line 129
    move-result-object p2

    .line 130
    invoke-interface {p2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 131
    .line 132
    .line 133
    monitor-exit v2

    .line 134
    goto :goto_3

    .line 135
    :catchall_1
    move-exception v0

    .line 136
    move-object p1, v0

    .line 137
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 138
    :try_start_4
    throw p1

    .line 139
    :cond_2
    :goto_3
    iget-object p2, p0, Ldu/i;->g:Ldu/n;

    .line 140
    .line 141
    sget-object v0, Ldu/n;->f:Ljava/util/Date;

    .line 142
    .line 143
    const/4 v2, 0x0

    .line 144
    invoke-virtual {p2, v2, v0}, Ldu/n;->d(ILjava/util/Date;)V
    :try_end_4
    .catch Lcu/f; {:try_start_4 .. :try_end_4} :catch_0

    .line 145
    .line 146
    .line 147
    return-object p1

    .line 148
    :goto_4
    iget p2, p1, Lcu/f;->d:I

    .line 149
    .line 150
    iget-object v0, p0, Ldu/i;->g:Ldu/n;

    .line 151
    .line 152
    const/16 v2, 0x1ad

    .line 153
    .line 154
    if-eq p2, v2, :cond_3

    .line 155
    .line 156
    const/16 v3, 0x1f6

    .line 157
    .line 158
    if-eq p2, v3, :cond_3

    .line 159
    .line 160
    const/16 v3, 0x1f7

    .line 161
    .line 162
    if-eq p2, v3, :cond_3

    .line 163
    .line 164
    const/16 v3, 0x1f8

    .line 165
    .line 166
    if-ne p2, v3, :cond_4

    .line 167
    .line 168
    :cond_3
    invoke-virtual {v0}, Ldu/n;->a()Ldu/m;

    .line 169
    .line 170
    .line 171
    move-result-object p2

    .line 172
    iget p2, p2, Ldu/m;->a:I

    .line 173
    .line 174
    add-int/2addr p2, v1

    .line 175
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    .line 176
    .line 177
    sget-object v4, Ldu/i;->j:[I

    .line 178
    .line 179
    array-length v5, v4

    .line 180
    invoke-static {p2, v5}, Ljava/lang/Math;->min(II)I

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    sub-int/2addr v5, v1

    .line 185
    aget v4, v4, v5

    .line 186
    .line 187
    int-to-long v4, v4

    .line 188
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 189
    .line 190
    .line 191
    move-result-wide v3

    .line 192
    const-wide/16 v5, 0x2

    .line 193
    .line 194
    div-long v5, v3, v5

    .line 195
    .line 196
    iget-object p0, p0, Ldu/i;->d:Ljava/util/Random;

    .line 197
    .line 198
    long-to-int v3, v3

    .line 199
    invoke-virtual {p0, v3}, Ljava/util/Random;->nextInt(I)I

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    int-to-long v3, p0

    .line 204
    add-long/2addr v5, v3

    .line 205
    new-instance p0, Ljava/util/Date;

    .line 206
    .line 207
    invoke-virtual {p3}, Ljava/util/Date;->getTime()J

    .line 208
    .line 209
    .line 210
    move-result-wide v3

    .line 211
    add-long/2addr v3, v5

    .line 212
    invoke-direct {p0, v3, v4}, Ljava/util/Date;-><init>(J)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, p2, p0}, Ldu/n;->d(ILjava/util/Date;)V

    .line 216
    .line 217
    .line 218
    :cond_4
    invoke-virtual {v0}, Ldu/n;->a()Ldu/m;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    iget p2, p1, Lcu/f;->d:I

    .line 223
    .line 224
    iget v0, p0, Ldu/m;->a:I

    .line 225
    .line 226
    if-gt v0, v1, :cond_9

    .line 227
    .line 228
    if-eq p2, v2, :cond_9

    .line 229
    .line 230
    const/16 p0, 0x191

    .line 231
    .line 232
    if-eq p2, p0, :cond_8

    .line 233
    .line 234
    const/16 p0, 0x193

    .line 235
    .line 236
    if-eq p2, p0, :cond_7

    .line 237
    .line 238
    if-eq p2, v2, :cond_6

    .line 239
    .line 240
    const/16 p0, 0x1f4

    .line 241
    .line 242
    if-eq p2, p0, :cond_5

    .line 243
    .line 244
    packed-switch p2, :pswitch_data_0

    .line 245
    .line 246
    .line 247
    const-string p0, "The server returned an unexpected error."

    .line 248
    .line 249
    goto :goto_5

    .line 250
    :pswitch_0
    const-string p0, "The server is unavailable. Please try again later."

    .line 251
    .line 252
    goto :goto_5

    .line 253
    :cond_5
    const-string p0, "There was an internal server error."

    .line 254
    .line 255
    goto :goto_5

    .line 256
    :cond_6
    new-instance p0, Lcu/c;

    .line 257
    .line 258
    const-string p1, "The throttled response from the server was not handled correctly by the FRC SDK."

    .line 259
    .line 260
    invoke-direct {p0, p1}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    throw p0

    .line 264
    :cond_7
    const-string p0, "The user is not authorized to access the project. Please make sure you are using the API key that corresponds to your Firebase project."

    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_8
    const-string p0, "The request did not have the required credentials. Please make sure your google-services.json is valid."

    .line 268
    .line 269
    :goto_5
    new-instance p2, Lcu/f;

    .line 270
    .line 271
    iget v0, p1, Lcu/f;->d:I

    .line 272
    .line 273
    const-string v1, "Fetch failed: "

    .line 274
    .line 275
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    invoke-direct {p2, v0, p0, p1}, Lcu/f;-><init>(ILjava/lang/String;Lcu/f;)V

    .line 280
    .line 281
    .line 282
    throw p2

    .line 283
    :cond_9
    new-instance p1, Lcu/e;

    .line 284
    .line 285
    iget-object p0, p0, Ldu/m;->b:Ljava/util/Date;

    .line 286
    .line 287
    invoke-virtual {p0}, Ljava/util/Date;->getTime()J

    .line 288
    .line 289
    .line 290
    const-string p0, "Fetch was throttled."

    .line 291
    .line 292
    invoke-direct {p1, p0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw p1

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x1f6
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Laq/j;JLjava/util/HashMap;)Laq/t;
    .locals 9

    .line 1
    new-instance v4, Ljava/util/Date;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-direct {v4, v0, v1}, Ljava/util/Date;-><init>(J)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/4 v0, 0x2

    .line 15
    const/4 v1, 0x0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Ldu/i;->g:Ldu/n;

    .line 18
    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    new-instance p1, Ljava/util/Date;

    .line 22
    .line 23
    iget-object v5, v3, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 24
    .line 25
    const-string v6, "last_fetch_time_in_millis"

    .line 26
    .line 27
    const-wide/16 v7, -0x1

    .line 28
    .line 29
    invoke-interface {v5, v6, v7, v8}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    invoke-direct {p1, v5, v6}, Ljava/util/Date;-><init>(J)V

    .line 34
    .line 35
    .line 36
    sget-object v5, Ldu/n;->e:Ljava/util/Date;

    .line 37
    .line 38
    invoke-virtual {p1, v5}, Ljava/util/Date;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    if-eqz v5, :cond_0

    .line 43
    .line 44
    move p1, v2

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    new-instance v5, Ljava/util/Date;

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    .line 49
    .line 50
    .line 51
    move-result-wide v6

    .line 52
    sget-object p1, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 53
    .line 54
    invoke-virtual {p1, p2, p3}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 55
    .line 56
    .line 57
    move-result-wide p1

    .line 58
    add-long/2addr p1, v6

    .line 59
    invoke-direct {v5, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v4, v5}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    :goto_0
    if-eqz p1, :cond_1

    .line 67
    .line 68
    new-instance p0, Ldu/h;

    .line 69
    .line 70
    invoke-direct {p0, v0, v1, v1}, Ldu/h;-><init>(ILdu/e;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :cond_1
    invoke-virtual {v3}, Ldu/n;->a()Ldu/m;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    iget-object p1, p1, Ldu/m;->b:Ljava/util/Date;

    .line 83
    .line 84
    invoke-virtual {v4, p1}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    if-eqz p2, :cond_2

    .line 89
    .line 90
    move-object v1, p1

    .line 91
    :cond_2
    iget-object p1, p0, Ldu/i;->c:Ljava/util/concurrent/Executor;

    .line 92
    .line 93
    if-eqz v1, :cond_3

    .line 94
    .line 95
    new-instance p2, Lcu/e;

    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    .line 98
    .line 99
    .line 100
    move-result-wide p3

    .line 101
    invoke-virtual {v4}, Ljava/util/Date;->getTime()J

    .line 102
    .line 103
    .line 104
    move-result-wide v2

    .line 105
    sub-long/2addr p3, v2

    .line 106
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 107
    .line 108
    invoke-virtual {v0, p3, p4}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 109
    .line 110
    .line 111
    move-result-wide p3

    .line 112
    invoke-static {p3, p4}, Landroid/text/format/DateUtils;->formatElapsedTime(J)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p3

    .line 116
    new-instance p4, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string v0, "Fetch is throttled. Please wait before calling fetch again: "

    .line 119
    .line 120
    invoke-direct {p4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    .line 131
    .line 132
    .line 133
    invoke-direct {p2, p3}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-static {p2}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 137
    .line 138
    .line 139
    move-result-object p2

    .line 140
    move-object v1, p0

    .line 141
    goto :goto_1

    .line 142
    :cond_3
    iget-object p2, p0, Ldu/i;->a:Lht/d;

    .line 143
    .line 144
    check-cast p2, Lht/c;

    .line 145
    .line 146
    move p3, v2

    .line 147
    invoke-virtual {p2}, Lht/c;->c()Laq/t;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    invoke-virtual {p2}, Lht/c;->d()Laq/t;

    .line 152
    .line 153
    .line 154
    move-result-object v3

    .line 155
    new-array p2, v0, [Laq/j;

    .line 156
    .line 157
    aput-object v2, p2, p3

    .line 158
    .line 159
    const/4 p3, 0x1

    .line 160
    aput-object v3, p2, p3

    .line 161
    .line 162
    invoke-static {p2}, Ljp/l1;->g([Laq/j;)Laq/t;

    .line 163
    .line 164
    .line 165
    move-result-object p2

    .line 166
    new-instance v0, Ldu/g;

    .line 167
    .line 168
    move-object v1, p0

    .line 169
    move-object v5, p4

    .line 170
    invoke-direct/range {v0 .. v5}, Ldu/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p2, p1, v0}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    :goto_1
    new-instance p0, La0/h;

    .line 178
    .line 179
    const/16 p3, 0xb

    .line 180
    .line 181
    invoke-direct {p0, p3, v1, v4}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p2, p1, p0}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    return-object p0
.end method

.method public final d(I)Laq/t;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    iget-object v1, p0, Ldu/i;->h:Ljava/util/Map;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 11
    .line 12
    .line 13
    const-string v2, "REALTIME"

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v2, "/"

    .line 19
    .line 20
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    const-string v1, "X-Firebase-RC-Fetch-Type"

    .line 31
    .line 32
    invoke-virtual {v0, v1, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Ldu/i;->e:Ldu/c;

    .line 36
    .line 37
    invoke-virtual {p1}, Ldu/c;->b()Laq/j;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    new-instance v1, La0/h;

    .line 42
    .line 43
    const/16 v2, 0xc

    .line 44
    .line 45
    invoke-direct {v1, v2, p0, v0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Ldu/i;->c:Ljava/util/concurrent/Executor;

    .line 49
    .line 50
    invoke-virtual {p1, p0, v1}, Laq/j;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method

.method public final e()Ljava/util/HashMap;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ldu/i;->b:Lgt/b;

    .line 7
    .line 8
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lwr/b;

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    check-cast p0, Lwr/c;

    .line 18
    .line 19
    iget-object p0, p0, Lwr/c;->a:Lro/f;

    .line 20
    .line 21
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lcom/google/android/gms/internal/measurement/k1;

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-virtual {p0, v1, v1, v2}, Lcom/google/android/gms/internal/measurement/k1;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/util/Map;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_1

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Ljava/util/Map$Entry;

    .line 50
    .line 51
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    check-cast v2, Ljava/lang/String;

    .line 56
    .line 57
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    :goto_1
    return-object v0
.end method
