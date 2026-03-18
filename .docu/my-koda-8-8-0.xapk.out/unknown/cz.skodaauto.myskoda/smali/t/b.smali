.class public final synthetic Lt/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt/e;


# direct methods
.method public synthetic constructor <init>(Lt/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt/b;->e:Lt/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lt/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt/b;->e:Lt/e;

    .line 7
    .line 8
    iget-object p0, p0, Lt/e;->d:Landroid/content/Context;

    .line 9
    .line 10
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const/16 v1, 0x84

    .line 19
    .line 20
    invoke-virtual {v0, p0, v1}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 21
    .line 22
    .line 23
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    iget-object p0, p0, Landroid/content/pm/PackageInfo;->services:[Landroid/content/pm/ServiceInfo;

    .line 25
    .line 26
    if-nez p0, :cond_0

    .line 27
    .line 28
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-static {p0}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :cond_1
    invoke-virtual {p0}, Landroidx/collection/d1;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    invoke-virtual {p0}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    check-cast v0, Landroid/content/pm/ServiceInfo;

    .line 46
    .line 47
    iget-object v0, v0, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;

    .line 48
    .line 49
    if-eqz v0, :cond_1

    .line 50
    .line 51
    const-string v1, "androidx.camera.featurecombinationquery.PLAY_SERVICES_IMPL_PROVIDER_KEY"

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :catch_0
    const/4 p0, 0x0

    .line 66
    :goto_0
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0

    .line 77
    :pswitch_0
    iget-object p0, p0, Lt/b;->e:Lt/e;

    .line 78
    .line 79
    iget-object p0, p0, Lt/e;->i:Llx0/q;

    .line 80
    .line 81
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lv/b;

    .line 86
    .line 87
    invoke-static {p0}, Lpv/g;->d(Lv/b;)Lpv/g;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 92
    .line 93
    const/16 v1, 0x21

    .line 94
    .line 95
    if-lt v0, v1, :cond_3

    .line 96
    .line 97
    const/4 v0, 0x1

    .line 98
    goto :goto_1

    .line 99
    :cond_3
    const/4 v0, 0x0

    .line 100
    :goto_1
    const-string v1, "DynamicRangesCompat can only be converted to DynamicRangeProfiles on API 33 or higher."

    .line 101
    .line 102
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 103
    .line 104
    .line 105
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Lw/b;

    .line 108
    .line 109
    invoke-interface {p0}, Lw/b;->a()Landroid/hardware/camera2/params/DynamicRangeProfiles;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :pswitch_1
    iget-object p0, p0, Lt/b;->e:Lt/e;

    .line 115
    .line 116
    :try_start_1
    iget-object v0, p0, Lt/e;->f:Lv/d;

    .line 117
    .line 118
    iget-object p0, p0, Lt/e;->e:Ljava/lang/String;

    .line 119
    .line 120
    invoke-virtual {v0, p0}, Lv/d;->a(Ljava/lang/String;)Lv/b;

    .line 121
    .line 122
    .line 123
    move-result-object p0
    :try_end_1
    .catch Lv/a; {:try_start_1 .. :try_end_1} :catch_1

    .line 124
    return-object p0

    .line 125
    :catch_1
    move-exception p0

    .line 126
    new-instance v0, Lb0/s;

    .line 127
    .line 128
    invoke-direct {v0, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 129
    .line 130
    .line 131
    throw v0

    .line 132
    :pswitch_2
    iget-object p0, p0, Lt/b;->e:Lt/e;

    .line 133
    .line 134
    iget-object v0, p0, Lt/e;->f:Lv/d;

    .line 135
    .line 136
    iget-object v1, v0, Lv/d;->a:Lv/e;

    .line 137
    .line 138
    iget-object v1, v1, Lh/w;->b:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v1, Landroid/hardware/camera2/CameraManager;

    .line 141
    .line 142
    iget-object p0, p0, Lt/e;->e:Ljava/lang/String;

    .line 143
    .line 144
    invoke-static {v1, p0}, Lf8/a;->j(Landroid/hardware/camera2/CameraManager;Ljava/lang/String;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-eqz v1, :cond_4

    .line 149
    .line 150
    iget-object v0, v0, Lv/d;->a:Lv/e;

    .line 151
    .line 152
    iget-object v0, v0, Lh/w;->b:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Landroid/hardware/camera2/CameraManager;

    .line 155
    .line 156
    invoke-static {v0, p0}, Lf8/a;->b(Landroid/hardware/camera2/CameraManager;Ljava/lang/String;)Landroid/hardware/camera2/CameraDevice$CameraDeviceSetup;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    goto :goto_2

    .line 161
    :cond_4
    const/4 p0, 0x0

    .line 162
    :goto_2
    return-object p0

    .line 163
    :pswitch_3
    iget-object p0, p0, Lt/b;->e:Lt/e;

    .line 164
    .line 165
    iget-object v0, p0, Lt/e;->d:Landroid/content/Context;

    .line 166
    .line 167
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 168
    .line 169
    const/16 v2, 0x23

    .line 170
    .line 171
    const/4 v3, 0x0

    .line 172
    if-lt v1, v2, :cond_5

    .line 173
    .line 174
    new-instance v1, Lu0/b;

    .line 175
    .line 176
    invoke-direct {v1, v0}, Lu0/b;-><init>(Landroid/content/Context;)V

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_5
    move-object v1, v3

    .line 181
    :goto_3
    :try_start_2
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    const/16 v5, 0x84

    .line 190
    .line 191
    invoke-virtual {v2, v4, v5}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 192
    .line 193
    .line 194
    move-result-object v2
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_3

    .line 195
    iget-object v2, v2, Landroid/content/pm/PackageInfo;->services:[Landroid/content/pm/ServiceInfo;

    .line 196
    .line 197
    if-nez v2, :cond_6

    .line 198
    .line 199
    goto :goto_6

    .line 200
    :cond_6
    array-length v4, v2

    .line 201
    const/4 v5, 0x0

    .line 202
    move-object v6, v3

    .line 203
    :goto_4
    if-ge v5, v4, :cond_a

    .line 204
    .line 205
    aget-object v7, v2, v5

    .line 206
    .line 207
    iget-object v7, v7, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;

    .line 208
    .line 209
    if-nez v7, :cond_7

    .line 210
    .line 211
    goto :goto_5

    .line 212
    :cond_7
    const-string v8, "androidx.camera.featurecombinationquery.PLAY_SERVICES_IMPL_PROVIDER_KEY"

    .line 213
    .line 214
    invoke-virtual {v7, v8}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    if-eqz v7, :cond_9

    .line 219
    .line 220
    if-nez v6, :cond_8

    .line 221
    .line 222
    move-object v6, v7

    .line 223
    goto :goto_5

    .line 224
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 225
    .line 226
    const-string v0, "Multiple Play Services CameraDeviceSetupCompat implementations found in the manifest."

    .line 227
    .line 228
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    throw p0

    .line 232
    :cond_9
    :goto_5
    add-int/lit8 v5, v5, 0x1

    .line 233
    .line 234
    goto :goto_4

    .line 235
    :cond_a
    if-nez v6, :cond_b

    .line 236
    .line 237
    goto :goto_6

    .line 238
    :cond_b
    :try_start_3
    invoke-static {v6}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    const-class v3, Landroid/content/Context;

    .line 243
    .line 244
    filled-new-array {v3}, [Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    invoke-virtual {v2, v3}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {v2, v0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    move-object v3, v0

    .line 261
    check-cast v3, Lu0/b;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_2

    .line 262
    .line 263
    goto :goto_6

    .line 264
    :catch_2
    move-exception p0

    .line 265
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 266
    .line 267
    const-string v1, "Failed to instantiate Play Services CameraDeviceSetupCompat implementation"

    .line 268
    .line 269
    invoke-direct {v0, v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 270
    .line 271
    .line 272
    throw v0

    .line 273
    :catch_3
    :goto_6
    iget-object p0, p0, Lt/e;->e:Ljava/lang/String;

    .line 274
    .line 275
    new-instance v0, Ljava/util/ArrayList;

    .line 276
    .line 277
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 278
    .line 279
    .line 280
    if-eqz v3, :cond_c

    .line 281
    .line 282
    new-instance v2, Lu0/a;

    .line 283
    .line 284
    iget-object v3, v3, Lu0/b;->a:Landroid/hardware/camera2/CameraManager;

    .line 285
    .line 286
    invoke-direct {v2, v3, p0}, Lu0/a;-><init>(Landroid/hardware/camera2/CameraManager;Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    :cond_c
    if-eqz v1, :cond_d

    .line 293
    .line 294
    :try_start_4
    new-instance v2, Lu0/a;

    .line 295
    .line 296
    iget-object v1, v1, Lu0/b;->a:Landroid/hardware/camera2/CameraManager;

    .line 297
    .line 298
    invoke-direct {v2, v1, p0}, Lu0/a;-><init>(Landroid/hardware/camera2/CameraManager;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_4
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_4 .. :try_end_4} :catch_4

    .line 302
    .line 303
    .line 304
    :catch_4
    :cond_d
    new-instance p0, Lu0/a;

    .line 305
    .line 306
    invoke-direct {p0, v0}, Lu0/a;-><init>(Ljava/util/ArrayList;)V

    .line 307
    .line 308
    .line 309
    return-object p0

    .line 310
    nop

    .line 311
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
