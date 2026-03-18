.class public Landroidx/profileinstaller/ProfileInstallReceiver;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 6

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "androidx.profileinstaller.action.INSTALL_PROFILE"

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    new-instance p2, Lha/c;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p2, v0}, Lha/c;-><init>(I)V

    .line 21
    .line 22
    .line 23
    new-instance v0, La0/j;

    .line 24
    .line 25
    const/16 v1, 0x1d

    .line 26
    .line 27
    invoke-direct {v0, p0, v1}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    invoke-static {p1, p2, v0, p0}, Lia/d;->t(Landroid/content/Context;Ljava/util/concurrent/Executor;Lia/c;Z)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    const-string v1, "androidx.profileinstaller.action.SKIP_FILE"

    .line 36
    .line 37
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    const-string v2, "ProfileInstaller"

    .line 42
    .line 43
    const/16 v3, 0xa

    .line 44
    .line 45
    const/4 v4, 0x0

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    if-eqz p2, :cond_9

    .line 53
    .line 54
    const-string v0, "EXTRA_SKIP_FILE_OPERATION"

    .line 55
    .line 56
    invoke-virtual {p2, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    const-string v0, "WRITE_SKIP_FILE"

    .line 61
    .line 62
    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    new-instance p2, La0/j;

    .line 69
    .line 70
    const/16 v0, 0x1d

    .line 71
    .line 72
    invoke-direct {p2, p0, v0}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    const/4 v1, 0x0

    .line 88
    :try_start_0
    invoke-virtual {v0, p0, v1}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 89
    .line 90
    .line 91
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 92
    invoke-virtual {p1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-static {p0, p1}, Lia/d;->e(Landroid/content/pm/PackageInfo;Ljava/io/File;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p2, v3, v4}, La0/j;->n(ILjava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    goto/16 :goto_1

    .line 103
    .line 104
    :catch_0
    move-exception p0

    .line 105
    const/4 p1, 0x7

    .line 106
    invoke-virtual {p2, p1, p0}, La0/j;->n(ILjava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto/16 :goto_1

    .line 110
    .line 111
    :cond_2
    const-string v0, "DELETE_SKIP_FILE"

    .line 112
    .line 113
    invoke-virtual {v0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result p2

    .line 117
    if-eqz p2, :cond_9

    .line 118
    .line 119
    invoke-virtual {p1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    new-instance p2, Ljava/io/File;

    .line 124
    .line 125
    const-string v0, "profileinstaller_profileWrittenFor_lastUpdateTime.dat"

    .line 126
    .line 127
    invoke-direct {p2, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p2}, Ljava/io/File;->delete()Z

    .line 131
    .line 132
    .line 133
    const-string p1, "RESULT_DELETE_SKIP_FILE_SUCCESS"

    .line 134
    .line 135
    invoke-static {v2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 136
    .line 137
    .line 138
    const/16 p1, 0xb

    .line 139
    .line 140
    invoke-virtual {p0, p1}, Landroid/content/BroadcastReceiver;->setResultCode(I)V

    .line 141
    .line 142
    .line 143
    return-void

    .line 144
    :cond_3
    const-string v1, "androidx.profileinstaller.action.SAVE_PROFILE"

    .line 145
    .line 146
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    const/16 v5, 0xc

    .line 151
    .line 152
    if-eqz v1, :cond_4

    .line 153
    .line 154
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 155
    .line 156
    .line 157
    move-result p1

    .line 158
    invoke-static {p1, v3}, Landroid/os/Process;->sendSignal(II)V

    .line 159
    .line 160
    .line 161
    const-string p1, ""

    .line 162
    .line 163
    invoke-static {v2, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0, v5}, Landroid/content/BroadcastReceiver;->setResultCode(I)V

    .line 167
    .line 168
    .line 169
    return-void

    .line 170
    :cond_4
    const-string v1, "androidx.profileinstaller.action.BENCHMARK_OPERATION"

    .line 171
    .line 172
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    if-eqz v0, :cond_9

    .line 177
    .line 178
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 179
    .line 180
    .line 181
    move-result-object p2

    .line 182
    if-eqz p2, :cond_9

    .line 183
    .line 184
    const-string v0, "EXTRA_BENCHMARK_OPERATION"

    .line 185
    .line 186
    invoke-virtual {p2, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    new-instance v1, La0/j;

    .line 191
    .line 192
    const/16 v2, 0x1d

    .line 193
    .line 194
    invoke-direct {v1, p0, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 195
    .line 196
    .line 197
    const-string p0, "DROP_SHADER_CACHE"

    .line 198
    .line 199
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result p0

    .line 203
    if-eqz p0, :cond_7

    .line 204
    .line 205
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 206
    .line 207
    const/16 p2, 0x22

    .line 208
    .line 209
    if-lt p0, p2, :cond_5

    .line 210
    .line 211
    invoke-virtual {p1}, Landroid/content/Context;->createDeviceProtectedStorageContext()Landroid/content/Context;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    goto :goto_0

    .line 220
    :cond_5
    invoke-virtual {p1}, Landroid/content/Context;->createDeviceProtectedStorageContext()Landroid/content/Context;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    invoke-virtual {p0}, Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    :goto_0
    invoke-static {p0}, Lia/d;->c(Ljava/io/File;)Z

    .line 229
    .line 230
    .line 231
    move-result p0

    .line 232
    if-eqz p0, :cond_6

    .line 233
    .line 234
    const/16 p0, 0xe

    .line 235
    .line 236
    invoke-virtual {v1, p0, v4}, La0/j;->n(ILjava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    return-void

    .line 240
    :cond_6
    const/16 p0, 0xf

    .line 241
    .line 242
    invoke-virtual {v1, p0, v4}, La0/j;->n(ILjava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :cond_7
    const-string p0, "SAVE_PROFILE"

    .line 247
    .line 248
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result p0

    .line 252
    if-eqz p0, :cond_8

    .line 253
    .line 254
    const-string p0, "EXTRA_PID"

    .line 255
    .line 256
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 257
    .line 258
    .line 259
    move-result p1

    .line 260
    invoke-virtual {p2, p0, p1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    invoke-static {p0, v3}, Landroid/os/Process;->sendSignal(II)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v1, v5, v4}, La0/j;->n(ILjava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    return-void

    .line 271
    :cond_8
    const/16 p0, 0x10

    .line 272
    .line 273
    invoke-virtual {v1, p0, v4}, La0/j;->n(ILjava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    :cond_9
    :goto_1
    return-void
.end method
