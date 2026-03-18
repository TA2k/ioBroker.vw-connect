.class public final Lh6/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/RemoteViewsService$RemoteViewsFactory;


# static fields
.field public static final e:Lh6/i;


# instance fields
.field public final a:Landroidx/core/widget/RemoteViewsCompatService;

.field public final b:I

.field public final c:I

.field public d:Lh6/i;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lh6/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [J

    .line 5
    .line 6
    new-array v1, v1, [Landroid/widget/RemoteViews;

    .line 7
    .line 8
    invoke-direct {v0, v2, v1}, Lh6/i;-><init>([J[Landroid/widget/RemoteViews;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lh6/k;->e:Lh6/i;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Landroidx/core/widget/RemoteViewsCompatService;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh6/k;->a:Landroidx/core/widget/RemoteViewsCompatService;

    .line 5
    .line 6
    iput p2, p0, Lh6/k;->b:I

    .line 7
    .line 8
    iput p3, p0, Lh6/k;->c:I

    .line 9
    .line 10
    sget-object p1, Lh6/k;->e:Lh6/i;

    .line 11
    .line 12
    iput-object p1, p0, Lh6/k;->d:Lh6/i;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 13

    .line 1
    const-string v0, "bytes"

    .line 2
    .line 3
    iget-object v1, p0, Lh6/k;->a:Landroidx/core/widget/RemoteViewsCompatService;

    .line 4
    .line 5
    const-string v2, "androidx.core.widget.prefs.RemoteViewsCompat"

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-virtual {v1, v2, v3}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    const-string v4, "context.getSharedPrefere\u2026S_FILENAME, MODE_PRIVATE)"

    .line 13
    .line 14
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v4, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 20
    .line 21
    .line 22
    iget v5, p0, Lh6/k;->b:I

    .line 23
    .line 24
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const/16 v6, 0x3a

    .line 28
    .line 29
    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget v6, p0, Lh6/k;->c:I

    .line 33
    .line 34
    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    const/4 v6, 0x0

    .line 42
    invoke-interface {v2, v4, v6}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    const-string v4, "RemoteViewsCompatServic"

    .line 47
    .line 48
    if-nez v2, :cond_0

    .line 49
    .line 50
    new-instance v0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v1, "No collection items were stored for widget "

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 65
    .line 66
    .line 67
    goto/16 :goto_1

    .line 68
    .line 69
    :cond_0
    invoke-static {v2, v3}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    const-string v7, "decode(hexString, Base64.DEFAULT)"

    .line 74
    .line 75
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    const-string v8, "obtain()"

    .line 83
    .line 84
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    :try_start_0
    array-length v9, v2

    .line 88
    invoke-virtual {v7, v2, v3, v9}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v7, v3}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 92
    .line 93
    .line 94
    new-instance v2, Lh6/j;

    .line 95
    .line 96
    const-string v9, "parcel"

    .line 97
    .line 98
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v7}, Landroid/os/Parcel;->readInt()I

    .line 105
    .line 106
    .line 107
    move-result v9

    .line 108
    new-array v9, v9, [B

    .line 109
    .line 110
    iput-object v9, v2, Lh6/j;->e:Ljava/lang/Object;

    .line 111
    .line 112
    invoke-virtual {v7, v9}, Landroid/os/Parcel;->readByteArray([B)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v7}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v9

    .line 119
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iput-object v9, v2, Lh6/j;->f:Ljava/lang/Object;

    .line 123
    .line 124
    invoke-virtual {v7}, Landroid/os/Parcel;->readLong()J

    .line 125
    .line 126
    .line 127
    move-result-wide v9

    .line 128
    iput-wide v9, v2, Lh6/j;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 129
    .line 130
    invoke-virtual {v7}, Landroid/os/Parcel;->recycle()V

    .line 131
    .line 132
    .line 133
    sget-object v7, Landroid/os/Build$VERSION;->INCREMENTAL:Ljava/lang/String;

    .line 134
    .line 135
    iget-object v9, v2, Lh6/j;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v9, Ljava/lang/String;

    .line 138
    .line 139
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-nez v7, :cond_1

    .line 144
    .line 145
    new-instance v0, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const-string v1, "Android version code has changed, not using stored collection items for widget "

    .line 148
    .line 149
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 160
    .line 161
    .line 162
    goto/16 :goto_1

    .line 163
    .line 164
    :cond_1
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    :try_start_1
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v9

    .line 172
    invoke-virtual {v7, v9, v3}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 173
    .line 174
    .line 175
    move-result-object v1
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0

    .line 176
    invoke-virtual {v1}, Landroid/content/pm/PackageInfo;->getLongVersionCode()J

    .line 177
    .line 178
    .line 179
    move-result-wide v9

    .line 180
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    goto :goto_0

    .line 185
    :catch_0
    move-exception v7

    .line 186
    new-instance v9, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    const-string v10, "Couldn\'t retrieve version code for "

    .line 189
    .line 190
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    invoke-static {v4, v1, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 205
    .line 206
    .line 207
    move-object v1, v6

    .line 208
    :goto_0
    if-nez v1, :cond_2

    .line 209
    .line 210
    new-instance v0, Ljava/lang/StringBuilder;

    .line 211
    .line 212
    const-string v1, "Couldn\'t get version code, not using stored collection items for widget "

    .line 213
    .line 214
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 225
    .line 226
    .line 227
    goto :goto_1

    .line 228
    :cond_2
    iget-wide v9, v2, Lh6/j;->d:J

    .line 229
    .line 230
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 231
    .line 232
    .line 233
    move-result-wide v11

    .line 234
    cmp-long v1, v11, v9

    .line 235
    .line 236
    if-eqz v1, :cond_3

    .line 237
    .line 238
    new-instance v0, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    const-string v1, "App version code has changed, not using stored collection items for widget "

    .line 241
    .line 242
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 253
    .line 254
    .line 255
    goto :goto_1

    .line 256
    :cond_3
    :try_start_2
    iget-object v1, v2, Lh6/j;->e:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast v1, [B

    .line 259
    .line 260
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 268
    .line 269
    .line 270
    :try_start_3
    array-length v2, v1

    .line 271
    invoke-virtual {v0, v1, v3, v2}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v0, v3}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 275
    .line 276
    .line 277
    new-instance v1, Lh6/i;

    .line 278
    .line 279
    invoke-direct {v1, v0}, Lh6/i;-><init>(Landroid/os/Parcel;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 280
    .line 281
    .line 282
    :try_start_4
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 283
    .line 284
    .line 285
    move-object v6, v1

    .line 286
    goto :goto_1

    .line 287
    :catchall_0
    move-exception v1

    .line 288
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 289
    .line 290
    .line 291
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 292
    :catchall_1
    move-exception v0

    .line 293
    new-instance v1, Ljava/lang/StringBuilder;

    .line 294
    .line 295
    const-string v2, "Unable to deserialize stored collection items for widget "

    .line 296
    .line 297
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 301
    .line 302
    .line 303
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object v1

    .line 307
    invoke-static {v4, v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 308
    .line 309
    .line 310
    :goto_1
    if-nez v6, :cond_4

    .line 311
    .line 312
    sget-object v6, Lh6/k;->e:Lh6/i;

    .line 313
    .line 314
    :cond_4
    iput-object v6, p0, Lh6/k;->d:Lh6/i;

    .line 315
    .line 316
    return-void

    .line 317
    :catchall_2
    move-exception p0

    .line 318
    invoke-virtual {v7}, Landroid/os/Parcel;->recycle()V

    .line 319
    .line 320
    .line 321
    throw p0
.end method

.method public final getCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/k;->d:Lh6/i;

    .line 2
    .line 3
    iget-object p0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, [J

    .line 6
    .line 7
    array-length p0, p0

    .line 8
    return p0
.end method

.method public final getItemId(I)J
    .locals 0

    .line 1
    :try_start_0
    iget-object p0, p0, Lh6/k;->d:Lh6/i;

    .line 2
    .line 3
    iget-object p0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, [J

    .line 6
    .line 7
    aget-wide p0, p0, p1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :catch_0
    const-wide/16 p0, -0x1

    .line 11
    .line 12
    return-wide p0
.end method

.method public final bridge synthetic getLoadingView()Landroid/widget/RemoteViews;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final getViewAt(I)Landroid/widget/RemoteViews;
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lh6/k;->d:Lh6/i;

    .line 2
    .line 3
    iget-object v0, v0, Lh6/i;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, [Landroid/widget/RemoteViews;

    .line 6
    .line 7
    aget-object p0, v0, p1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :catch_0
    new-instance p1, Landroid/widget/RemoteViews;

    .line 11
    .line 12
    iget-object p0, p0, Lh6/k;->a:Landroidx/core/widget/RemoteViewsCompatService;

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const v0, 0x7f0d028e

    .line 19
    .line 20
    .line 21
    invoke-direct {p1, p0, v0}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    return-object p1
.end method

.method public final getViewTypeCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/k;->d:Lh6/i;

    .line 2
    .line 3
    iget p0, p0, Lh6/i;->b:I

    .line 4
    .line 5
    return p0
.end method

.method public final hasStableIds()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/k;->d:Lh6/i;

    .line 2
    .line 3
    iget-boolean p0, p0, Lh6/i;->c:Z

    .line 4
    .line 5
    return p0
.end method

.method public final onCreate()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh6/k;->a()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onDataSetChanged()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh6/k;->a()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onDestroy()V
    .locals 0

    .line 1
    return-void
.end method
