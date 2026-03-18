.class public final Lil/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lil/g;


# direct methods
.method public synthetic constructor <init>(Lil/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lil/e;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lil/e;->g:Lil/g;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lil/e;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v1, Lxl/e;->a:Lxl/e;

    .line 7
    .line 8
    iget-object p0, p0, Lil/e;->g:Lil/g;

    .line 9
    .line 10
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/content/Context;

    .line 13
    .line 14
    monitor-enter v1

    .line 15
    :try_start_0
    sget-object v0, Lxl/e;->b:Lll/f;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    sget-object v5, Lu01/k;->d:Lu01/u;

    .line 20
    .line 21
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 22
    .line 23
    sget-object v7, Lcz0/d;->e:Lcz0/d;

    .line 24
    .line 25
    sget-object v0, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    if-eqz p0, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/io/File;->mkdirs()Z

    .line 34
    .line 35
    .line 36
    const-string v0, "image_cache"

    .line 37
    .line 38
    new-instance v2, Ljava/io/File;

    .line 39
    .line 40
    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {p0, v2}, Lwx0/i;->e(Ljava/io/File;Ljava/io/File;)Ljava/io/File;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    sget-object v0, Lu01/y;->e:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {p0}, Lrb0/a;->b(Ljava/io/File;)Lu01/y;

    .line 50
    .line 51
    .line 52
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    const-wide/32 v10, 0xa00000

    .line 54
    .line 55
    .line 56
    :try_start_1
    invoke-virtual {v6}, Lu01/y;->toFile()Ljava/io/File;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p0}, Ljava/io/File;->mkdir()Z

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    new-instance v0, Landroid/os/StatFs;

    .line 68
    .line 69
    invoke-direct {v0, p0}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Landroid/os/StatFs;->getBlockCountLong()J

    .line 73
    .line 74
    .line 75
    move-result-wide v2

    .line 76
    long-to-double v2, v2

    .line 77
    const-wide v8, 0x3f947ae147ae147bL    # 0.02

    .line 78
    .line 79
    .line 80
    .line 81
    .line 82
    mul-double/2addr v8, v2

    .line 83
    invoke-virtual {v0}, Landroid/os/StatFs;->getBlockSizeLong()J

    .line 84
    .line 85
    .line 86
    move-result-wide v2

    .line 87
    long-to-double v2, v2

    .line 88
    mul-double/2addr v8, v2

    .line 89
    double-to-long v8, v8

    .line 90
    const-wide/32 v12, 0xfa00000

    .line 91
    .line 92
    .line 93
    invoke-static/range {v8 .. v13}, Lkp/r9;->g(JJJ)J

    .line 94
    .line 95
    .line 96
    move-result-wide v10
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 97
    :catch_0
    move-wide v3, v10

    .line 98
    :try_start_2
    new-instance v2, Lll/f;

    .line 99
    .line 100
    invoke-direct/range {v2 .. v7}, Lll/f;-><init>(JLu01/k;Lu01/y;Lvy0/x;)V

    .line 101
    .line 102
    .line 103
    sput-object v2, Lxl/e;->b:Lll/f;

    .line 104
    .line 105
    move-object v0, v2

    .line 106
    goto :goto_0

    .line 107
    :catchall_0
    move-exception v0

    .line 108
    move-object p0, v0

    .line 109
    goto :goto_1

    .line 110
    :cond_0
    const-string p0, "cacheDir == null"

    .line 111
    .line 112
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 118
    :cond_1
    :goto_0
    monitor-exit v1

    .line 119
    return-object v0

    .line 120
    :goto_1
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 121
    throw p0

    .line 122
    :pswitch_0
    const-class v0, Landroid/app/ActivityManager;

    .line 123
    .line 124
    iget-object p0, p0, Lil/e;->g:Lil/g;

    .line 125
    .line 126
    iget-object p0, p0, Lil/g;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast p0, Landroid/content/Context;

    .line 129
    .line 130
    sget-object v1, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 131
    .line 132
    const-wide v1, 0x3fc999999999999aL    # 0.2

    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    :try_start_4
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    check-cast v3, Landroid/app/ActivityManager;

    .line 145
    .line 146
    invoke-virtual {v3}, Landroid/app/ActivityManager;->isLowRamDevice()Z

    .line 147
    .line 148
    .line 149
    move-result v3
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    .line 150
    if-eqz v3, :cond_2

    .line 151
    .line 152
    const-wide v1, 0x3fc3333333333333L    # 0.15

    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    :catch_1
    :cond_2
    new-instance v3, Lhm/g;

    .line 158
    .line 159
    const/4 v4, 0x1

    .line 160
    invoke-direct {v3, v4}, Lhm/g;-><init>(I)V

    .line 161
    .line 162
    .line 163
    const-wide/16 v4, 0x0

    .line 164
    .line 165
    cmpl-double v4, v1, v4

    .line 166
    .line 167
    if-lez v4, :cond_4

    .line 168
    .line 169
    sget-object v4, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 170
    .line 171
    :try_start_5
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    check-cast v0, Landroid/app/ActivityManager;

    .line 179
    .line 180
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->flags:I

    .line 185
    .line 186
    const/high16 v4, 0x100000

    .line 187
    .line 188
    and-int/2addr p0, v4

    .line 189
    if-eqz p0, :cond_3

    .line 190
    .line 191
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getLargeMemoryClass()I

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    goto :goto_2

    .line 196
    :cond_3
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getMemoryClass()I

    .line 197
    .line 198
    .line 199
    move-result p0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2

    .line 200
    goto :goto_2

    .line 201
    :catch_2
    const/16 p0, 0x100

    .line 202
    .line 203
    :goto_2
    int-to-double v4, p0

    .line 204
    mul-double/2addr v1, v4

    .line 205
    const/16 p0, 0x400

    .line 206
    .line 207
    int-to-double v4, p0

    .line 208
    mul-double/2addr v1, v4

    .line 209
    mul-double/2addr v1, v4

    .line 210
    double-to-int p0, v1

    .line 211
    goto :goto_3

    .line 212
    :cond_4
    const/4 p0, 0x0

    .line 213
    :goto_3
    if-lez p0, :cond_5

    .line 214
    .line 215
    new-instance v0, Lb81/c;

    .line 216
    .line 217
    invoke-direct {v0, p0, v3}, Lb81/c;-><init>(ILhm/g;)V

    .line 218
    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_5
    new-instance v0, Lh6/e;

    .line 222
    .line 223
    const/16 p0, 0x1d

    .line 224
    .line 225
    invoke-direct {v0, v3, p0}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 226
    .line 227
    .line 228
    :goto_4
    new-instance p0, Lrl/c;

    .line 229
    .line 230
    invoke-direct {p0, v0, v3}, Lrl/c;-><init>(Lrl/g;Lhm/g;)V

    .line 231
    .line 232
    .line 233
    return-object p0

    .line 234
    nop

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
