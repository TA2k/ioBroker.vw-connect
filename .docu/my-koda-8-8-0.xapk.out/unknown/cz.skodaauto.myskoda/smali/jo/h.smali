.class public abstract Ljo/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public static b:Z = false

.field public static c:Z = false

.field public static final d:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public static final synthetic e:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Ljo/h;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Landroid/content/Context;)Z
    .locals 5

    .line 1
    sget-boolean v0, Ljo/h;->c:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    :try_start_0
    invoke-static {p0}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v3, "com.google.android.gms"

    .line 12
    .line 13
    const/16 v4, 0x40

    .line 14
    .line 15
    invoke-virtual {v0, v4, v3}, Lcq/r1;->c(ILjava/lang/String;)Landroid/content/pm/PackageInfo;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {p0}, Ljo/i;->a(Landroid/content/Context;)Ljo/i;

    .line 20
    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-static {v0, v1}, Ljo/i;->d(Landroid/content/pm/PackageInfo;Z)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_0

    .line 29
    .line 30
    invoke-static {v0, v2}, Ljo/i;->d(Landroid/content/pm/PackageInfo;Z)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_0

    .line 35
    .line 36
    sput-boolean v2, Ljo/h;->b:Z

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    goto :goto_2

    .line 41
    :catch_0
    move-exception p0

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    sput-boolean v1, Ljo/h;->b:Z
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    :goto_0
    sput-boolean v2, Ljo/h;->c:Z

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :goto_1
    :try_start_1
    const-string v0, "GooglePlayServicesUtil"

    .line 49
    .line 50
    const-string v3, "Cannot find Google Play services package name."

    .line 51
    .line 52
    invoke-static {v0, v3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 53
    .line 54
    .line 55
    sput-boolean v2, Ljo/h;->c:Z

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :goto_2
    sput-boolean v2, Ljo/h;->c:Z

    .line 59
    .line 60
    throw p0

    .line 61
    :cond_1
    :goto_3
    sget-boolean p0, Ljo/h;->b:Z

    .line 62
    .line 63
    if-nez p0, :cond_3

    .line 64
    .line 65
    const-string p0, "user"

    .line 66
    .line 67
    sget-object v0, Landroid/os/Build;->TYPE:Ljava/lang/String;

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-nez p0, :cond_2

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_2
    return v1

    .line 77
    :cond_3
    :goto_4
    return v2
.end method

.method public static b(Landroid/content/Context;I)I
    .locals 9

    .line 1
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const v1, 0x7f120155

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :catchall_0
    const-string v0, "GooglePlayServicesUtil"

    .line 13
    .line 14
    const-string v1, "The Google Play services resources were not found. Check your project configuration to ensure that the resources are included."

    .line 15
    .line 16
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    :goto_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "com.google.android.gms"

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/4 v1, 0x1

    .line 30
    if-nez v0, :cond_5

    .line 31
    .line 32
    sget-object v0, Ljo/h;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    goto :goto_4

    .line 41
    :cond_0
    sget-object v0, Lno/c0;->a:Ljava/lang/Object;

    .line 42
    .line 43
    monitor-enter v0

    .line 44
    :try_start_1
    sget-boolean v2, Lno/c0;->b:Z

    .line 45
    .line 46
    if-eqz v2, :cond_1

    .line 47
    .line 48
    monitor-exit v0

    .line 49
    goto :goto_2

    .line 50
    :catchall_1
    move-exception p0

    .line 51
    goto :goto_3

    .line 52
    :cond_1
    sput-boolean v1, Lno/c0;->b:Z

    .line 53
    .line 54
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-static {p0}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 59
    .line 60
    .line 61
    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 62
    const/16 v4, 0x80

    .line 63
    .line 64
    :try_start_2
    invoke-virtual {v3, v4, v2}, Lcq/r1;->b(ILjava/lang/String;)Landroid/content/pm/ApplicationInfo;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    iget-object v2, v2, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 69
    .line 70
    if-nez v2, :cond_2

    .line 71
    .line 72
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 73
    goto :goto_2

    .line 74
    :cond_2
    :try_start_4
    const-string v3, "com.google.app.id"

    .line 75
    .line 76
    invoke-virtual {v2, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    const-string v3, "com.google.android.gms.version"

    .line 80
    .line 81
    invoke-virtual {v2, v3}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    sput v2, Lno/c0;->c:I
    :try_end_4
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :catch_0
    move-exception v2

    .line 89
    :try_start_5
    const-string v3, "MetadataValueReader"

    .line 90
    .line 91
    const-string v4, "This should never happen."

    .line 92
    .line 93
    invoke-static {v3, v4, v2}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 94
    .line 95
    .line 96
    :goto_1
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 97
    :goto_2
    sget v0, Lno/c0;->c:I

    .line 98
    .line 99
    if-eqz v0, :cond_4

    .line 100
    .line 101
    const v2, 0xbdfcb8

    .line 102
    .line 103
    .line 104
    if-ne v0, v2, :cond_3

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_3
    new-instance p0, Lcom/google/android/gms/common/GooglePlayServicesIncorrectManifestValueException;

    .line 108
    .line 109
    sget p1, Ljo/f;->a:I

    .line 110
    .line 111
    const-string v1, "The meta-data tag in your app\'s AndroidManifest.xml does not have the right value.  Expected "

    .line 112
    .line 113
    const-string v2, " but found "

    .line 114
    .line 115
    const-string v3, ".  You must have the following declaration within the <application> element:     <meta-data android:name=\"com.google.android.gms.version\" android:value=\"@integer/google_play_services_version\" />"

    .line 116
    .line 117
    invoke-static {p1, v0, v1, v2, v3}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_4
    new-instance p0, Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException;

    .line 126
    .line 127
    invoke-direct {p0}, Lcom/google/android/gms/common/GooglePlayServicesMissingManifestValueException;-><init>()V

    .line 128
    .line 129
    .line 130
    throw p0

    .line 131
    :goto_3
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 132
    throw p0

    .line 133
    :cond_5
    :goto_4
    invoke-static {p0}, Lto/b;->e(Landroid/content/Context;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    const/4 v2, 0x0

    .line 138
    if-nez v0, :cond_9

    .line 139
    .line 140
    sget-object v0, Lto/b;->e:Ljava/lang/Boolean;

    .line 141
    .line 142
    if-nez v0, :cond_8

    .line 143
    .line 144
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    const-string v3, "android.hardware.type.iot"

    .line 149
    .line 150
    invoke-virtual {v0, v3}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    if-nez v0, :cond_6

    .line 155
    .line 156
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    const-string v3, "android.hardware.type.embedded"

    .line 161
    .line 162
    invoke-virtual {v0, v3}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    if-eqz v0, :cond_7

    .line 167
    .line 168
    :cond_6
    move v0, v1

    .line 169
    goto :goto_5

    .line 170
    :cond_7
    move v0, v2

    .line 171
    :goto_5
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    sput-object v0, Lto/b;->e:Ljava/lang/Boolean;

    .line 176
    .line 177
    :cond_8
    sget-object v0, Lto/b;->e:Ljava/lang/Boolean;

    .line 178
    .line 179
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-nez v0, :cond_9

    .line 184
    .line 185
    move v0, v1

    .line 186
    goto :goto_6

    .line 187
    :cond_9
    move v0, v2

    .line 188
    :goto_6
    if-ltz p1, :cond_a

    .line 189
    .line 190
    move v3, v1

    .line 191
    goto :goto_7

    .line 192
    :cond_a
    move v3, v2

    .line 193
    :goto_7
    invoke-static {v3}, Lno/c0;->a(Z)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    const/16 v5, 0x9

    .line 205
    .line 206
    if-eqz v0, :cond_b

    .line 207
    .line 208
    :try_start_7
    const-string v6, "com.android.vending"

    .line 209
    .line 210
    const/16 v7, 0x2040

    .line 211
    .line 212
    invoke-virtual {v4, v6, v7}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 213
    .line 214
    .line 215
    move-result-object v6
    :try_end_7
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_7 .. :try_end_7} :catch_1

    .line 216
    goto :goto_9

    .line 217
    :catch_1
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    const-string p1, " requires the Google Play Store, but it is missing."

    .line 222
    .line 223
    const-string v0, "GooglePlayServicesUtil"

    .line 224
    .line 225
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    :goto_8
    move v1, v5

    .line 233
    goto/16 :goto_d

    .line 234
    .line 235
    :cond_b
    const/4 v6, 0x0

    .line 236
    :goto_9
    :try_start_8
    const-string v7, "com.google.android.gms"

    .line 237
    .line 238
    const/16 v8, 0x40

    .line 239
    .line 240
    invoke-virtual {v4, v7, v8}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 241
    .line 242
    .line 243
    move-result-object v7
    :try_end_8
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_8 .. :try_end_8} :catch_3

    .line 244
    invoke-static {p0}, Ljo/i;->a(Landroid/content/Context;)Ljo/i;

    .line 245
    .line 246
    .line 247
    invoke-static {v7, v1}, Ljo/i;->d(Landroid/content/pm/PackageInfo;Z)Z

    .line 248
    .line 249
    .line 250
    move-result p0

    .line 251
    if-nez p0, :cond_c

    .line 252
    .line 253
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object p0

    .line 257
    const-string p1, " requires Google Play services, but their signature is invalid."

    .line 258
    .line 259
    const-string v0, "GooglePlayServicesUtil"

    .line 260
    .line 261
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object p0

    .line 265
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    goto :goto_8

    .line 269
    :cond_c
    if-eqz v0, :cond_d

    .line 270
    .line 271
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    invoke-static {v6, v1}, Ljo/i;->d(Landroid/content/pm/PackageInfo;Z)Z

    .line 275
    .line 276
    .line 277
    move-result p0

    .line 278
    if-nez p0, :cond_d

    .line 279
    .line 280
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    const-string p1, " requires Google Play Store, but its signature is invalid."

    .line 285
    .line 286
    const-string v0, "GooglePlayServicesUtil"

    .line 287
    .line 288
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 293
    .line 294
    .line 295
    goto :goto_8

    .line 296
    :cond_d
    if-eqz v0, :cond_e

    .line 297
    .line 298
    if-eqz v6, :cond_e

    .line 299
    .line 300
    iget-object p0, v6, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 301
    .line 302
    aget-object p0, p0, v2

    .line 303
    .line 304
    iget-object v0, v7, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 305
    .line 306
    aget-object v0, v0, v2

    .line 307
    .line 308
    invoke-virtual {p0, v0}, Landroid/content/pm/Signature;->equals(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result p0

    .line 312
    if-nez p0, :cond_e

    .line 313
    .line 314
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    const-string p1, " requires Google Play Store, but its signature doesn\'t match that of Google Play services."

    .line 319
    .line 320
    const-string v0, "GooglePlayServicesUtil"

    .line 321
    .line 322
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object p0

    .line 326
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 327
    .line 328
    .line 329
    goto :goto_8

    .line 330
    :cond_e
    iget p0, v7, Landroid/content/pm/PackageInfo;->versionCode:I

    .line 331
    .line 332
    const/4 v0, -0x1

    .line 333
    if-ne p0, v0, :cond_f

    .line 334
    .line 335
    move v5, v0

    .line 336
    goto :goto_a

    .line 337
    :cond_f
    div-int/lit16 v5, p0, 0x3e8

    .line 338
    .line 339
    :goto_a
    if-ne p1, v0, :cond_10

    .line 340
    .line 341
    goto :goto_b

    .line 342
    :cond_10
    div-int/lit16 v0, p1, 0x3e8

    .line 343
    .line 344
    :goto_b
    if-ge v5, v0, :cond_11

    .line 345
    .line 346
    const-string v0, "Google Play services out of date for "

    .line 347
    .line 348
    const-string v1, ".  Requires "

    .line 349
    .line 350
    const-string v2, " but found "

    .line 351
    .line 352
    invoke-static {v0, p1, v3, v1, v2}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 353
    .line 354
    .line 355
    move-result-object p1

    .line 356
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    const-string p1, "GooglePlayServicesUtil"

    .line 364
    .line 365
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 366
    .line 367
    .line 368
    const/4 v1, 0x2

    .line 369
    goto :goto_d

    .line 370
    :cond_11
    iget-object p0, v7, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 371
    .line 372
    if-nez p0, :cond_12

    .line 373
    .line 374
    :try_start_9
    const-string p0, "com.google.android.gms"

    .line 375
    .line 376
    invoke-virtual {v4, p0, v2}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 377
    .line 378
    .line 379
    move-result-object p0
    :try_end_9
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_9 .. :try_end_9} :catch_2

    .line 380
    goto :goto_c

    .line 381
    :catch_2
    move-exception p0

    .line 382
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object p1

    .line 386
    const-string v0, " requires Google Play services, but they\'re missing when getting application info."

    .line 387
    .line 388
    const-string v2, "GooglePlayServicesUtil"

    .line 389
    .line 390
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object p1

    .line 394
    invoke-static {v2, p1, p0}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 395
    .line 396
    .line 397
    goto :goto_d

    .line 398
    :cond_12
    :goto_c
    iget-boolean p0, p0, Landroid/content/pm/ApplicationInfo;->enabled:Z

    .line 399
    .line 400
    if-nez p0, :cond_13

    .line 401
    .line 402
    const/4 v1, 0x3

    .line 403
    goto :goto_d

    .line 404
    :cond_13
    return v2

    .line 405
    :catch_3
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 406
    .line 407
    .line 408
    move-result-object p0

    .line 409
    const-string p1, " requires Google Play services, but they are missing."

    .line 410
    .line 411
    const-string v0, "GooglePlayServicesUtil"

    .line 412
    .line 413
    invoke-virtual {p0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    move-result-object p0

    .line 417
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 418
    .line 419
    .line 420
    :goto_d
    return v1
.end method

.method public static c(Landroid/content/Context;)Z
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/pm/PackageManager;->getPackageInstaller()Landroid/content/pm/PackageInstaller;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Landroid/content/pm/PackageInstaller;->getAllSessions()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const-string v2, "com.google.android.gms"

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Landroid/content/pm/PackageInstaller$SessionInfo;

    .line 30
    .line 31
    invoke-virtual {v1}, Landroid/content/pm/PackageInstaller$SessionInfo;->getAppPackageName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_0

    .line 40
    .line 41
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :cond_1
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const/16 v0, 0x2000

    .line 48
    .line 49
    :try_start_1
    invoke-virtual {p0, v2, v0}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    iget-boolean p0, p0, Landroid/content/pm/ApplicationInfo;->enabled:Z
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0

    .line 54
    .line 55
    return p0

    .line 56
    :catch_0
    const/4 p0, 0x0

    .line 57
    return p0
.end method
