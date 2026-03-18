.class public abstract Lwp/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljo/f;

.field public static final b:Ljava/lang/Object;

.field public static c:Ljava/lang/reflect/Method; = null

.field public static d:Z = false


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ljo/f;->b:Ljo/f;

    .line 2
    .line 3
    sput-object v0, Lwp/a;->a:Ljo/f;

    .line 4
    .line 5
    new-instance v0, Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lwp/a;->b:Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method

.method public static a(Landroid/content/Context;)V
    .locals 13

    .line 1
    const-string v0, "Context must not be null"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lwp/a;->a:Ljo/f;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    sget-object v0, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 12
    .line 13
    sget-object v0, Ljo/f;->b:Ljo/f;

    .line 14
    .line 15
    const v1, 0xb5f608

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p0, v1}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    const-string v2, "e"

    .line 25
    .line 26
    invoke-virtual {v0, p0, v2, v1}, Ljo/f;->b(Landroid/content/Context;Ljava/lang/String;I)Landroid/content/Intent;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance v0, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v2, "GooglePlayServices not available due to error "

    .line 33
    .line 34
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v2, "GooglePlayServicesUtil"

    .line 45
    .line 46
    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    if-nez p0, :cond_0

    .line 50
    .line 51
    new-instance p0, Ljo/g;

    .line 52
    .line 53
    invoke-direct {p0, v1}, Ljo/g;-><init>(I)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_0
    const-string p0, "Google Play Services not available"

    .line 58
    .line 59
    new-instance v0, Lb0/l;

    .line 60
    .line 61
    invoke-direct {v0, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_1
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    sget-object v2, Lwp/a;->b:Ljava/lang/Object;

    .line 70
    .line 71
    monitor-enter v2

    .line 72
    :try_start_0
    sget-boolean v3, Lwp/a;->d:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 73
    .line 74
    const/4 v4, 0x0

    .line 75
    if-nez v3, :cond_2

    .line 76
    .line 77
    :try_start_1
    sget-object v3, Lzo/d;->e:Lwq/f;

    .line 78
    .line 79
    const-string v5, "com.google.android.gms.providerinstaller.dynamite"

    .line 80
    .line 81
    invoke-static {p0, v3, v5}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    iget-object v3, v3, Lzo/d;->a:Landroid/content/Context;
    :try_end_1
    .catch Lzo/a; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :catchall_0
    move-exception p0

    .line 89
    goto/16 :goto_5

    .line 90
    .line 91
    :catch_0
    move-exception v3

    .line 92
    :try_start_2
    const-string v5, "ProviderInstaller"

    .line 93
    .line 94
    invoke-virtual {v3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    const-string v6, "Failed to load providerinstaller module: "

    .line 99
    .line 100
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-virtual {v6, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-static {v5, v3}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    move-object v3, v4

    .line 112
    :goto_0
    if-eqz v3, :cond_2

    .line 113
    .line 114
    const-string p0, "com.google.android.gms.providerinstaller.ProviderInstallerImpl"

    .line 115
    .line 116
    invoke-static {v3, p0}, Lwp/a;->b(Landroid/content/Context;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    monitor-exit v2

    .line 120
    goto :goto_4

    .line 121
    :cond_2
    sget-boolean v3, Lwp/a;->d:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 122
    .line 123
    const/4 v5, 0x3

    .line 124
    :try_start_3
    const-string v6, "com.google.android.gms"

    .line 125
    .line 126
    invoke-virtual {p0, v6, v5}, Landroid/content/Context;->createPackageContext(Ljava/lang/String;I)Landroid/content/Context;

    .line 127
    .line 128
    .line 129
    move-result-object v6
    :try_end_3
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 130
    goto :goto_1

    .line 131
    :catch_1
    move-object v6, v4

    .line 132
    :goto_1
    if-nez v6, :cond_3

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_3
    const/4 v4, 0x1

    .line 136
    :try_start_4
    sput-boolean v4, Lwp/a;->d:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 137
    .line 138
    if-nez v3, :cond_4

    .line 139
    .line 140
    :try_start_5
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 141
    .line 142
    .line 143
    move-result-wide v7

    .line 144
    invoke-virtual {v6}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    const-class v9, Landroid/content/Context;

    .line 149
    .line 150
    new-instance v10, Lvp/y1;

    .line 151
    .line 152
    const/4 v11, 0x4

    .line 153
    const/4 v12, 0x0

    .line 154
    invoke-direct {v10, v9, p0, v12, v11}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 155
    .line 156
    .line 157
    new-instance p0, Lep/b;

    .line 158
    .line 159
    sget-object v9, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 160
    .line 161
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-direct {p0, v9, v0, v12, v11}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 166
    .line 167
    .line 168
    new-instance v0, Lep/b;

    .line 169
    .line 170
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-direct {v0, v9, v1, v12, v11}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 175
    .line 176
    .line 177
    new-array v1, v5, [Lvp/y1;

    .line 178
    .line 179
    aput-object v10, v1, v12

    .line 180
    .line 181
    aput-object p0, v1, v4

    .line 182
    .line 183
    const/4 p0, 0x2

    .line 184
    aput-object v0, v1, p0

    .line 185
    .line 186
    const-string p0, "com.google.android.gms.common.security.ProviderInstallerImpl"

    .line 187
    .line 188
    invoke-virtual {v3, p0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    const-string v0, "reportRequestStats2"

    .line 193
    .line 194
    invoke-static {p0, v0, v1}, Lkp/p6;->g(Ljava/lang/Class;Ljava/lang/String;[Lvp/y1;)Ljava/lang/Object;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :catch_2
    move-exception p0

    .line 199
    :try_start_6
    const-string v0, "ProviderInstaller"

    .line 200
    .line 201
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    const-string v1, "Failed to report request stats: "

    .line 206
    .line 207
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object p0

    .line 211
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 212
    .line 213
    .line 214
    :cond_4
    :goto_2
    move-object v4, v6

    .line 215
    :goto_3
    if-eqz v4, :cond_5

    .line 216
    .line 217
    const-string p0, "com.google.android.gms.common.security.ProviderInstallerImpl"

    .line 218
    .line 219
    invoke-static {v4, p0}, Lwp/a;->b(Landroid/content/Context;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    monitor-exit v2

    .line 223
    :goto_4
    return-void

    .line 224
    :cond_5
    const-string p0, "ProviderInstaller"

    .line 225
    .line 226
    const-string v0, "Failed to get remote context"

    .line 227
    .line 228
    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 229
    .line 230
    .line 231
    new-instance p0, Ljo/g;

    .line 232
    .line 233
    const/16 v0, 0x8

    .line 234
    .line 235
    invoke-direct {p0, v0}, Ljo/g;-><init>(I)V

    .line 236
    .line 237
    .line 238
    throw p0

    .line 239
    :goto_5
    monitor-exit v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 240
    throw p0
.end method

.method public static b(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3

    .line 1
    :try_start_0
    sget-object v0, Lwp/a;->c:Ljava/lang/reflect/Method;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-class v0, Landroid/content/Context;

    .line 6
    .line 7
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "insertProvider"

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v2, p1}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p1, v1, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    sput-object p1, Lwp/a;->c:Ljava/lang/reflect/Method;

    .line 26
    .line 27
    :cond_0
    sget-object p1, Lwp/a;->c:Ljava/lang/reflect/Method;

    .line 28
    .line 29
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const/4 v0, 0x0

    .line 34
    invoke-virtual {p1, v0, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :catch_0
    move-exception p0

    .line 39
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    const/4 v0, 0x6

    .line 44
    const-string v1, "ProviderInstaller"

    .line 45
    .line 46
    invoke-static {v1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    if-nez p1, :cond_1

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    goto :goto_0

    .line 59
    :cond_1
    invoke-virtual {p1}, Ljava/lang/Throwable;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    :goto_0
    const-string p1, "Failed to install provider: "

    .line 64
    .line 65
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-static {v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 74
    .line 75
    .line 76
    :cond_2
    new-instance p0, Ljo/g;

    .line 77
    .line 78
    const/16 p1, 0x8

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljo/g;-><init>(I)V

    .line 81
    .line 82
    .line 83
    throw p0
.end method
