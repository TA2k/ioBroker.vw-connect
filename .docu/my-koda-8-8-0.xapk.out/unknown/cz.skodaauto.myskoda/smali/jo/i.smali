.class public final Ljo/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static c:Ljo/i;


# instance fields
.field public final a:Landroid/content/Context;

.field public volatile b:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Ljo/i;->a:Landroid/content/Context;

    .line 9
    .line 10
    return-void
.end method

.method public static a(Landroid/content/Context;)Ljo/i;
    .locals 4

    .line 1
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    const-class v0, Ljo/i;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    sget-object v1, Ljo/i;->c:Ljo/i;

    .line 8
    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    sget-object v1, Ljo/q;->a:Ljo/m;

    .line 12
    .line 13
    const-class v1, Ljo/q;

    .line 14
    .line 15
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 16
    :try_start_1
    sget-object v2, Ljo/q;->e:Landroid/content/Context;

    .line 17
    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    sput-object v2, Ljo/q;->e:Landroid/content/Context;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    .line 26
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 27
    goto :goto_0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    :try_start_3
    const-string v2, "GoogleCertificates"

    .line 31
    .line 32
    const-string v3, "GoogleCertificates has been initialized already"

    .line 33
    .line 34
    invoke-static {v2, v3}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 35
    .line 36
    .line 37
    :try_start_4
    monitor-exit v1

    .line 38
    :goto_0
    new-instance v1, Ljo/i;

    .line 39
    .line 40
    invoke-direct {v1, p0}, Ljo/i;-><init>(Landroid/content/Context;)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Ljo/i;->c:Ljo/i;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :catchall_1
    move-exception p0

    .line 47
    goto :goto_3

    .line 48
    :goto_1
    :try_start_5
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 49
    :try_start_6
    throw p0

    .line 50
    :cond_1
    :goto_2
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 51
    sget-object p0, Ljo/i;->c:Ljo/i;

    .line 52
    .line 53
    return-object p0

    .line 54
    :goto_3
    :try_start_7
    monitor-exit v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 55
    throw p0
.end method

.method public static final varargs c(Landroid/content/pm/PackageInfo;[Ljo/n;)Ljo/n;
    .locals 3

    .line 1
    iget-object v0, p0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    array-length v0, v0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-eq v0, v2, :cond_1

    .line 10
    .line 11
    const-string p0, "GoogleSignatureVerifier"

    .line 12
    .line 13
    const-string p1, "Package has more than one signature."

    .line 14
    .line 15
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 16
    .line 17
    .line 18
    return-object v1

    .line 19
    :cond_1
    new-instance v0, Ljo/o;

    .line 20
    .line 21
    iget-object p0, p0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    aget-object p0, p0, v2

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/content/pm/Signature;->toByteArray()[B

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {v0, p0}, Ljo/o;-><init>([B)V

    .line 31
    .line 32
    .line 33
    :goto_0
    array-length p0, p1

    .line 34
    if-ge v2, p0, :cond_3

    .line 35
    .line 36
    aget-object p0, p1, v2

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Ljo/n;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_2

    .line 43
    .line 44
    aget-object p0, p1, v2

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    :goto_1
    return-object v1
.end method

.method public static final d(Landroid/content/pm/PackageInfo;Z)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-eqz p1, :cond_3

    .line 4
    .line 5
    if-eqz p0, :cond_4

    .line 6
    .line 7
    const-string v2, "com.android.vending"

    .line 8
    .line 9
    iget-object v3, p0, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    iget-object v2, p0, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    .line 18
    .line 19
    const-string v3, "com.google.android.gms"

    .line 20
    .line 21
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_3

    .line 26
    .line 27
    :cond_0
    iget-object p1, p0, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 28
    .line 29
    if-nez p1, :cond_2

    .line 30
    .line 31
    :cond_1
    move p1, v1

    .line 32
    goto :goto_0

    .line 33
    :cond_2
    iget p1, p1, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 34
    .line 35
    and-int/lit16 p1, p1, 0x81

    .line 36
    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    move p1, v0

    .line 40
    :cond_3
    :goto_0
    move-object v2, p0

    .line 41
    goto :goto_1

    .line 42
    :cond_4
    const/4 v2, 0x0

    .line 43
    :goto_1
    if-eqz p0, :cond_6

    .line 44
    .line 45
    iget-object p0, v2, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 46
    .line 47
    if-eqz p0, :cond_6

    .line 48
    .line 49
    if-eqz p1, :cond_5

    .line 50
    .line 51
    sget-object p0, Ljo/p;->a:[Ljo/n;

    .line 52
    .line 53
    invoke-static {v2, p0}, Ljo/i;->c(Landroid/content/pm/PackageInfo;[Ljo/n;)Ljo/n;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    goto :goto_2

    .line 58
    :cond_5
    sget-object p0, Ljo/p;->a:[Ljo/n;

    .line 59
    .line 60
    aget-object p0, p0, v1

    .line 61
    .line 62
    filled-new-array {p0}, [Ljo/n;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-static {v2, p0}, Ljo/i;->c(Landroid/content/pm/PackageInfo;[Ljo/n;)Ljo/n;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    :goto_2
    if-eqz p0, :cond_6

    .line 71
    .line 72
    return v0

    .line 73
    :cond_6
    return v1
.end method


# virtual methods
.method public final b(I)Z
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Ljo/i;->a:Landroid/content/Context;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    move/from16 v2, p1

    .line 10
    .line 11
    invoke-virtual {v0, v2}, Landroid/content/pm/PackageManager;->getPackagesForUid(I)[Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const/4 v3, 0x3

    .line 16
    const/4 v4, 0x0

    .line 17
    const/4 v5, 0x0

    .line 18
    if-eqz v2, :cond_e

    .line 19
    .line 20
    array-length v6, v2

    .line 21
    if-nez v6, :cond_0

    .line 22
    .line 23
    goto/16 :goto_a

    .line 24
    .line 25
    :cond_0
    move-object v0, v4

    .line 26
    move v7, v5

    .line 27
    :goto_0
    if-ge v7, v6, :cond_d

    .line 28
    .line 29
    aget-object v8, v2, v7

    .line 30
    .line 31
    const-string v9, "Failed to get Google certificates from remote"

    .line 32
    .line 33
    const-string v10, "GoogleCertificates"

    .line 34
    .line 35
    const-string v11, "null pkg"

    .line 36
    .line 37
    if-nez v8, :cond_1

    .line 38
    .line 39
    new-instance v0, Ljo/t;

    .line 40
    .line 41
    invoke-direct {v0, v5, v11, v4}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 42
    .line 43
    .line 44
    goto/16 :goto_9

    .line 45
    .line 46
    :cond_1
    iget-object v0, v1, Ljo/i;->b:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {v8, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_a

    .line 53
    .line 54
    sget-object v0, Ljo/q;->a:Ljo/m;

    .line 55
    .line 56
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskReads()Landroid/os/StrictMode$ThreadPolicy;

    .line 57
    .line 58
    .line 59
    move-result-object v12

    .line 60
    :try_start_0
    invoke-static {}, Ljo/q;->b()V

    .line 61
    .line 62
    .line 63
    sget-object v0, Ljo/q;->c:Lno/b0;

    .line 64
    .line 65
    check-cast v0, Lno/z;

    .line 66
    .line 67
    invoke-virtual {v0}, Lno/z;->W()Z

    .line 68
    .line 69
    .line 70
    move-result v0
    :try_end_0
    .catch Lzo/a; {:try_start_0 .. :try_end_0} :catch_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    goto :goto_1

    .line 72
    :catchall_0
    move-exception v0

    .line 73
    goto/16 :goto_8

    .line 74
    .line 75
    :catch_0
    move-exception v0

    .line 76
    :try_start_1
    invoke-static {v10, v9, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    .line 78
    .line 79
    move v0, v5

    .line 80
    :goto_1
    invoke-static {v12}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 81
    .line 82
    .line 83
    const/4 v12, 0x2

    .line 84
    const/4 v13, 0x1

    .line 85
    if-eqz v0, :cond_5

    .line 86
    .line 87
    iget-object v0, v1, Ljo/i;->a:Landroid/content/Context;

    .line 88
    .line 89
    invoke-static {v0}, Ljo/h;->a(Landroid/content/Context;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskReads()Landroid/os/StrictMode$ThreadPolicy;

    .line 94
    .line 95
    .line 96
    move-result-object v11

    .line 97
    :try_start_2
    sget-object v14, Ljo/q;->e:Landroid/content/Context;

    .line 98
    .line 99
    invoke-static {v14}, Lno/c0;->h(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 100
    .line 101
    .line 102
    :try_start_3
    invoke-static {}, Ljo/q;->b()V
    :try_end_3
    .catch Lzo/a; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 103
    .line 104
    .line 105
    :try_start_4
    sget-object v14, Ljo/q;->e:Landroid/content/Context;

    .line 106
    .line 107
    new-instance v15, Lyo/b;

    .line 108
    .line 109
    invoke-direct {v15, v14}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v15}, Lyo/b;->T(Landroid/os/IBinder;)Lyo/a;

    .line 113
    .line 114
    .line 115
    move-result-object v14

    .line 116
    invoke-static {v14}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v14

    .line 120
    check-cast v14, Landroid/content/Context;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 121
    .line 122
    :try_start_5
    sget-object v15, Ljo/q;->c:Lno/b0;

    .line 123
    .line 124
    check-cast v15, Lno/z;

    .line 125
    .line 126
    invoke-virtual {v15}, Lbp/a;->S()Landroid/os/Parcel;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    sget v16, Lep/a;->a:I

    .line 131
    .line 132
    invoke-virtual {v4, v13}, Landroid/os/Parcel;->writeInt(I)V

    .line 133
    .line 134
    .line 135
    const/16 v5, 0x4f45

    .line 136
    .line 137
    invoke-static {v4, v5}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    invoke-static {v4, v8, v13}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 142
    .line 143
    .line 144
    const/4 v13, 0x4

    .line 145
    invoke-static {v4, v12, v13}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v4, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 149
    .line 150
    .line 151
    invoke-static {v4, v3, v13}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 152
    .line 153
    .line 154
    const/4 v12, 0x0

    .line 155
    invoke-virtual {v4, v12}, Landroid/os/Parcel;->writeInt(I)V

    .line 156
    .line 157
    .line 158
    new-instance v0, Lyo/b;

    .line 159
    .line 160
    invoke-direct {v0, v14}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    invoke-static {v4, v13, v0}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 164
    .line 165
    .line 166
    const/4 v0, 0x5

    .line 167
    invoke-static {v4, v0, v13}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v4, v12}, Landroid/os/Parcel;->writeInt(I)V

    .line 171
    .line 172
    .line 173
    const/4 v0, 0x6

    .line 174
    invoke-static {v4, v0, v13}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 175
    .line 176
    .line 177
    const/4 v12, 0x1

    .line 178
    invoke-virtual {v4, v12}, Landroid/os/Parcel;->writeInt(I)V

    .line 179
    .line 180
    .line 181
    invoke-static {v4, v5}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v15, v4, v0}, Lbp/a;->b(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    sget-object v4, Ljo/r;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 189
    .line 190
    invoke-static {v0, v4}, Lep/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    check-cast v4, Ljo/r;

    .line 195
    .line 196
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V
    :try_end_5
    .catch Landroid/os/RemoteException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 197
    .line 198
    .line 199
    :try_start_6
    iget-boolean v0, v4, Ljo/r;->d:Z

    .line 200
    .line 201
    if-eqz v0, :cond_2

    .line 202
    .line 203
    iget v0, v4, Ljo/r;->g:I

    .line 204
    .line 205
    invoke-static {v0}, Llp/fc;->b(I)I

    .line 206
    .line 207
    .line 208
    new-instance v0, Ljo/t;

    .line 209
    .line 210
    const/4 v4, 0x0

    .line 211
    const/4 v12, 0x1

    .line 212
    invoke-direct {v0, v12, v4, v4}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 213
    .line 214
    .line 215
    goto :goto_4

    .line 216
    :cond_2
    iget-object v0, v4, Ljo/r;->e:Ljava/lang/String;

    .line 217
    .line 218
    iget v5, v4, Ljo/r;->f:I

    .line 219
    .line 220
    invoke-static {v5}, Llp/gc;->b(I)I

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    if-ne v5, v13, :cond_3

    .line 225
    .line 226
    new-instance v5, Landroid/content/pm/PackageManager$NameNotFoundException;

    .line 227
    .line 228
    invoke-direct {v5}, Landroid/content/pm/PackageManager$NameNotFoundException;-><init>()V

    .line 229
    .line 230
    .line 231
    goto :goto_2

    .line 232
    :catchall_1
    move-exception v0

    .line 233
    goto :goto_5

    .line 234
    :cond_3
    const/4 v5, 0x0

    .line 235
    :goto_2
    const-string v9, "error checking package certificate"

    .line 236
    .line 237
    if-nez v0, :cond_4

    .line 238
    .line 239
    move-object v0, v9

    .line 240
    :cond_4
    iget v9, v4, Ljo/r;->g:I

    .line 241
    .line 242
    invoke-static {v9}, Llp/fc;->b(I)I

    .line 243
    .line 244
    .line 245
    iget v4, v4, Ljo/r;->f:I

    .line 246
    .line 247
    invoke-static {v4}, Llp/gc;->b(I)I

    .line 248
    .line 249
    .line 250
    new-instance v4, Ljo/t;

    .line 251
    .line 252
    const/4 v12, 0x0

    .line 253
    invoke-direct {v4, v12, v0, v5}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 254
    .line 255
    .line 256
    move-object v0, v4

    .line 257
    goto :goto_4

    .line 258
    :catch_1
    move-exception v0

    .line 259
    invoke-static {v10, v9, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 260
    .line 261
    .line 262
    const-string v4, "module call"

    .line 263
    .line 264
    new-instance v5, Ljo/t;

    .line 265
    .line 266
    const/4 v12, 0x0

    .line 267
    invoke-direct {v5, v12, v4, v0}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 268
    .line 269
    .line 270
    :goto_3
    move-object v0, v5

    .line 271
    goto :goto_4

    .line 272
    :catch_2
    move-exception v0

    .line 273
    invoke-static {v10, v9, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 274
    .line 275
    .line 276
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v4

    .line 280
    const-string v5, "module init: "

    .line 281
    .line 282
    invoke-static {v4}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-virtual {v5, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v4

    .line 290
    new-instance v5, Ljo/t;

    .line 291
    .line 292
    const/4 v12, 0x0

    .line 293
    invoke-direct {v5, v12, v4, v0}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 294
    .line 295
    .line 296
    goto :goto_3

    .line 297
    :goto_4
    invoke-static {v11}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 298
    .line 299
    .line 300
    goto/16 :goto_7

    .line 301
    .line 302
    :goto_5
    invoke-static {v11}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 303
    .line 304
    .line 305
    throw v0

    .line 306
    :cond_5
    :try_start_7
    iget-object v0, v1, Ljo/i;->a:Landroid/content/Context;

    .line 307
    .line 308
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    const/16 v4, 0x40

    .line 313
    .line 314
    invoke-virtual {v0, v8, v4}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 315
    .line 316
    .line 317
    move-result-object v0
    :try_end_7
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_7 .. :try_end_7} :catch_3

    .line 318
    iget-object v4, v1, Ljo/i;->a:Landroid/content/Context;

    .line 319
    .line 320
    invoke-static {v4}, Ljo/h;->a(Landroid/content/Context;)Z

    .line 321
    .line 322
    .line 323
    move-result v4

    .line 324
    if-nez v0, :cond_6

    .line 325
    .line 326
    new-instance v0, Ljo/t;

    .line 327
    .line 328
    const/4 v4, 0x0

    .line 329
    const/4 v5, 0x0

    .line 330
    invoke-direct {v0, v5, v11, v4}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 331
    .line 332
    .line 333
    goto :goto_7

    .line 334
    :cond_6
    const/4 v5, 0x0

    .line 335
    iget-object v9, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 336
    .line 337
    if-eqz v9, :cond_9

    .line 338
    .line 339
    array-length v9, v9

    .line 340
    const/4 v10, 0x1

    .line 341
    if-eq v9, v10, :cond_7

    .line 342
    .line 343
    goto :goto_6

    .line 344
    :cond_7
    new-instance v9, Ljo/o;

    .line 345
    .line 346
    iget-object v10, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 347
    .line 348
    aget-object v10, v10, v5

    .line 349
    .line 350
    invoke-virtual {v10}, Landroid/content/pm/Signature;->toByteArray()[B

    .line 351
    .line 352
    .line 353
    move-result-object v10

    .line 354
    invoke-direct {v9, v10}, Ljo/o;-><init>([B)V

    .line 355
    .line 356
    .line 357
    iget-object v10, v0, Landroid/content/pm/PackageInfo;->packageName:Ljava/lang/String;

    .line 358
    .line 359
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskReads()Landroid/os/StrictMode$ThreadPolicy;

    .line 360
    .line 361
    .line 362
    move-result-object v11

    .line 363
    :try_start_8
    invoke-static {v10, v9, v4, v5}, Ljo/q;->a(Ljava/lang/String;Ljo/o;ZZ)Ljo/t;

    .line 364
    .line 365
    .line 366
    move-result-object v4
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 367
    invoke-static {v11}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 368
    .line 369
    .line 370
    iget-boolean v5, v4, Ljo/t;->a:Z

    .line 371
    .line 372
    if-eqz v5, :cond_8

    .line 373
    .line 374
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    .line 375
    .line 376
    if-eqz v0, :cond_8

    .line 377
    .line 378
    iget v0, v0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 379
    .line 380
    and-int/2addr v0, v12

    .line 381
    if-eqz v0, :cond_8

    .line 382
    .line 383
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskReads()Landroid/os/StrictMode$ThreadPolicy;

    .line 384
    .line 385
    .line 386
    move-result-object v5

    .line 387
    const/4 v11, 0x0

    .line 388
    const/4 v12, 0x1

    .line 389
    :try_start_9
    invoke-static {v10, v9, v11, v12}, Ljo/q;->a(Ljava/lang/String;Ljo/o;ZZ)Ljo/t;

    .line 390
    .line 391
    .line 392
    move-result-object v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 393
    invoke-static {v5}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 394
    .line 395
    .line 396
    iget-boolean v0, v0, Ljo/t;->a:Z

    .line 397
    .line 398
    if-eqz v0, :cond_8

    .line 399
    .line 400
    new-instance v0, Ljo/t;

    .line 401
    .line 402
    const-string v4, "debuggable release cert app rejected"

    .line 403
    .line 404
    const/4 v5, 0x0

    .line 405
    invoke-direct {v0, v11, v4, v5}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 406
    .line 407
    .line 408
    goto :goto_7

    .line 409
    :catchall_2
    move-exception v0

    .line 410
    invoke-static {v5}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 411
    .line 412
    .line 413
    throw v0

    .line 414
    :cond_8
    move-object v0, v4

    .line 415
    goto :goto_7

    .line 416
    :catchall_3
    move-exception v0

    .line 417
    invoke-static {v11}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 418
    .line 419
    .line 420
    throw v0

    .line 421
    :cond_9
    :goto_6
    new-instance v0, Ljo/t;

    .line 422
    .line 423
    const-string v4, "single cert required"

    .line 424
    .line 425
    const/4 v5, 0x0

    .line 426
    const/4 v12, 0x0

    .line 427
    invoke-direct {v0, v12, v4, v5}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 428
    .line 429
    .line 430
    :goto_7
    iget-boolean v4, v0, Ljo/t;->a:Z

    .line 431
    .line 432
    if-eqz v4, :cond_b

    .line 433
    .line 434
    iput-object v8, v1, Ljo/i;->b:Ljava/lang/String;

    .line 435
    .line 436
    goto :goto_9

    .line 437
    :catch_3
    move-exception v0

    .line 438
    const-string v4, "no pkg "

    .line 439
    .line 440
    invoke-virtual {v4, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v4

    .line 444
    new-instance v5, Ljo/t;

    .line 445
    .line 446
    const/4 v12, 0x0

    .line 447
    invoke-direct {v5, v12, v4, v0}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 448
    .line 449
    .line 450
    move-object v0, v5

    .line 451
    goto :goto_9

    .line 452
    :goto_8
    invoke-static {v12}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 453
    .line 454
    .line 455
    throw v0

    .line 456
    :cond_a
    sget-object v0, Ljo/t;->d:Ljo/t;

    .line 457
    .line 458
    :cond_b
    :goto_9
    iget-boolean v4, v0, Ljo/t;->a:Z

    .line 459
    .line 460
    if-eqz v4, :cond_c

    .line 461
    .line 462
    goto :goto_b

    .line 463
    :cond_c
    add-int/lit8 v7, v7, 0x1

    .line 464
    .line 465
    const/4 v4, 0x0

    .line 466
    const/4 v5, 0x0

    .line 467
    goto/16 :goto_0

    .line 468
    .line 469
    :cond_d
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 470
    .line 471
    .line 472
    goto :goto_b

    .line 473
    :cond_e
    :goto_a
    new-instance v0, Ljo/t;

    .line 474
    .line 475
    const-string v1, "no pkgs"

    .line 476
    .line 477
    const/4 v4, 0x0

    .line 478
    const/4 v12, 0x0

    .line 479
    invoke-direct {v0, v12, v1, v4}, Ljo/t;-><init>(ZLjava/lang/String;Ljava/lang/Exception;)V

    .line 480
    .line 481
    .line 482
    :goto_b
    iget-object v1, v0, Ljo/t;->c:Ljava/lang/Throwable;

    .line 483
    .line 484
    iget-boolean v2, v0, Ljo/t;->a:Z

    .line 485
    .line 486
    if-nez v2, :cond_10

    .line 487
    .line 488
    const-string v2, "GoogleCertificatesRslt"

    .line 489
    .line 490
    invoke-static {v2, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 491
    .line 492
    .line 493
    move-result v3

    .line 494
    if-eqz v3, :cond_10

    .line 495
    .line 496
    if-eqz v1, :cond_f

    .line 497
    .line 498
    invoke-virtual {v0}, Ljo/t;->a()Ljava/lang/String;

    .line 499
    .line 500
    .line 501
    move-result-object v3

    .line 502
    invoke-static {v2, v3, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 503
    .line 504
    .line 505
    goto :goto_c

    .line 506
    :cond_f
    invoke-virtual {v0}, Ljo/t;->a()Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v1

    .line 510
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 511
    .line 512
    .line 513
    :cond_10
    :goto_c
    iget-boolean v0, v0, Ljo/t;->a:Z

    .line 514
    .line 515
    return v0
.end method
