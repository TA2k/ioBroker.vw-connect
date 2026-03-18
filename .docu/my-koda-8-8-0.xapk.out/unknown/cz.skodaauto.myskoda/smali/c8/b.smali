.class public final Lc8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lc8/b;

.field public static final d:Lhr/x0;

.field public static final e:Lhr/c1;


# instance fields
.field public final a:Landroid/util/SparseArray;

.field public final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc8/b;

    .line 2
    .line 3
    sget-object v1, Lc8/a;->d:Lc8/a;

    .line 4
    .line 5
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-direct {v0, v1}, Lc8/b;-><init>(Lhr/x0;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lc8/b;->c:Lc8/b;

    .line 13
    .line 14
    const/4 v0, 0x2

    .line 15
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const/4 v1, 0x5

    .line 20
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const/4 v2, 0x6

    .line 25
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    filled-new-array {v0, v1, v2}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const/4 v3, 0x3

    .line 34
    invoke-static {v3, v0}, Lhr/q;->a(I[Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v3, v0}, Lhr/h0;->n(I[Ljava/lang/Object;)Lhr/x0;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Lc8/b;->d:Lhr/x0;

    .line 42
    .line 43
    new-instance v0, Lbb/g0;

    .line 44
    .line 45
    const/4 v3, 0x4

    .line 46
    invoke-direct {v0, v3}, Lbb/g0;-><init>(I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1, v2}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/16 v1, 0x11

    .line 53
    .line 54
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {v0, v1, v2}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    const/4 v1, 0x7

    .line 62
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-virtual {v0, v1, v2}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    const/16 v1, 0x1e

    .line 70
    .line 71
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    const/16 v3, 0xa

    .line 76
    .line 77
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    invoke-virtual {v0, v1, v3}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    const/16 v1, 0x12

    .line 85
    .line 86
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {v0, v1, v2}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    const/16 v1, 0x8

    .line 94
    .line 95
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    invoke-virtual {v0, v2, v1}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v1, v1}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    const/16 v2, 0xe

    .line 106
    .line 107
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-virtual {v0, v2, v1}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Lbb/g0;->e()Lhr/c1;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sput-object v0, Lc8/b;->e:Lhr/c1;

    .line 119
    .line 120
    return-void
.end method

.method public constructor <init>(Lhr/x0;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/util/SparseArray;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    move v1, v0

    .line 13
    :goto_0
    iget v2, p1, Lhr/x0;->g:I

    .line 14
    .line 15
    if-ge v1, v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1, v1}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lc8/a;

    .line 22
    .line 23
    iget-object v3, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 24
    .line 25
    iget v4, v2, Lc8/a;->a:I

    .line 26
    .line 27
    invoke-virtual {v3, v4, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move p1, v0

    .line 34
    :goto_1
    iget-object v1, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 35
    .line 36
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-ge v0, v1, :cond_1

    .line 41
    .line 42
    iget-object v1, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lc8/a;

    .line 49
    .line 50
    iget v1, v1, Lc8/a;->b:I

    .line 51
    .line 52
    invoke-static {p1, v1}, Ljava/lang/Math;->max(II)I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    add-int/lit8 v0, v0, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    iput p1, p0, Lc8/b;->b:I

    .line 60
    .line 61
    return-void
.end method

.method public static a(I[I)Lhr/x0;
    .locals 4

    .line 1
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    new-array p1, v1, [I

    .line 9
    .line 10
    :cond_0
    :goto_0
    array-length v2, p1

    .line 11
    if-ge v1, v2, :cond_1

    .line 12
    .line 13
    aget v2, p1, v1

    .line 14
    .line 15
    new-instance v3, Lc8/a;

    .line 16
    .line 17
    invoke-direct {v3, v2, p0}, Lc8/a;-><init>(II)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v3}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {v0}, Lhr/e0;->i()Lhr/x0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public static b(Landroid/content/Context;Landroid/content/Intent;Lt7/c;La0/j;)Lc8/b;
    .locals 12

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    invoke-static {p0}, Lu7/b;->a(Landroid/content/Context;)Landroid/media/AudioManager;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    const/16 v3, 0x21

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    sget p3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 17
    .line 18
    const/4 v5, 0x0

    .line 19
    if-lt p3, v3, :cond_2

    .line 20
    .line 21
    invoke-virtual {p2}, Lt7/c;->a()Lpv/g;

    .line 22
    .line 23
    .line 24
    move-result-object p3

    .line 25
    iget-object p3, p3, Lpv/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p3, Landroid/media/AudioAttributes;

    .line 28
    .line 29
    invoke-static {v2, p3}, Lb/s;->t(Landroid/media/AudioManager;Landroid/media/AudioAttributes;)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    invoke-interface {p3}, Ljava/util/List;->isEmpty()Z

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    if-eqz v6, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance v5, La0/j;

    .line 41
    .line 42
    invoke-interface {p3, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p3

    .line 46
    check-cast p3, Landroid/media/AudioDeviceInfo;

    .line 47
    .line 48
    const/16 v6, 0x8

    .line 49
    .line 50
    invoke-direct {v5, p3, v6}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    :cond_2
    :goto_0
    move-object p3, v5

    .line 54
    :goto_1
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 55
    .line 56
    const-string v6, "android.hardware.type.automotive"

    .line 57
    .line 58
    sget-object v7, Lc8/b;->e:Lhr/c1;

    .line 59
    .line 60
    const/16 v8, 0xc

    .line 61
    .line 62
    const/4 v9, 0x1

    .line 63
    if-lt v5, v3, :cond_9

    .line 64
    .line 65
    invoke-static {p0}, Lw7/w;->C(Landroid/content/Context;)Z

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    if-nez v10, :cond_3

    .line 70
    .line 71
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    invoke-virtual {v10, v6}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    if-eqz v10, :cond_9

    .line 80
    .line 81
    :cond_3
    invoke-virtual {p2}, Lt7/c;->a()Lpv/g;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Landroid/media/AudioAttributes;

    .line 88
    .line 89
    invoke-static {v2, p0}, Lb/s;->D(Landroid/media/AudioManager;Landroid/media/AudioAttributes;)Ljava/util/List;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    new-instance p1, Lc8/b;

    .line 94
    .line 95
    new-instance p2, Ljava/util/HashMap;

    .line 96
    .line 97
    invoke-direct {p2}, Ljava/util/HashMap;-><init>()V

    .line 98
    .line 99
    .line 100
    new-instance p3, Ljava/util/HashSet;

    .line 101
    .line 102
    filled-new-array {v8}, [I

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-static {v0}, Llp/de;->b([I)Ljava/util/List;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-direct {p3, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p2, v1, p3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    :goto_2
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 117
    .line 118
    .line 119
    move-result p3

    .line 120
    if-ge v4, p3, :cond_7

    .line 121
    .line 122
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p3

    .line 126
    invoke-static {p3}, Lc4/a;->k(Ljava/lang/Object;)Landroid/media/AudioProfile;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    invoke-static {p3}, Lc4/a;->c(Landroid/media/AudioProfile;)I

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-ne v0, v9, :cond_4

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_4
    invoke-static {p3}, Lc4/a;->C(Landroid/media/AudioProfile;)I

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    invoke-static {v0}, Lw7/w;->A(I)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    if-nez v1, :cond_5

    .line 146
    .line 147
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v7, v1}, Lhr/c1;->containsKey(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    if-nez v1, :cond_5

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_5
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-virtual {p2, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    if-eqz v1, :cond_6

    .line 167
    .line 168
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-virtual {p2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    check-cast v0, Ljava/util/Set;

    .line 177
    .line 178
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 179
    .line 180
    .line 181
    check-cast v0, Ljava/util/Set;

    .line 182
    .line 183
    invoke-static {p3}, Lc4/a;->B(Landroid/media/AudioProfile;)[I

    .line 184
    .line 185
    .line 186
    move-result-object p3

    .line 187
    invoke-static {p3}, Llp/de;->b([I)Ljava/util/List;

    .line 188
    .line 189
    .line 190
    move-result-object p3

    .line 191
    invoke-interface {v0, p3}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 192
    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_6
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    new-instance v1, Ljava/util/HashSet;

    .line 200
    .line 201
    invoke-static {p3}, Lc4/a;->B(Landroid/media/AudioProfile;)[I

    .line 202
    .line 203
    .line 204
    move-result-object p3

    .line 205
    invoke-static {p3}, Llp/de;->b([I)Ljava/util/List;

    .line 206
    .line 207
    .line 208
    move-result-object p3

    .line 209
    invoke-direct {v1, p3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {p2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    :goto_3
    add-int/lit8 v4, v4, 0x1

    .line 216
    .line 217
    goto :goto_2

    .line 218
    :cond_7
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    invoke-virtual {p2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 223
    .line 224
    .line 225
    move-result-object p2

    .line 226
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 227
    .line 228
    .line 229
    move-result-object p2

    .line 230
    :goto_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 231
    .line 232
    .line 233
    move-result p3

    .line 234
    if-eqz p3, :cond_8

    .line 235
    .line 236
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object p3

    .line 240
    check-cast p3, Ljava/util/Map$Entry;

    .line 241
    .line 242
    new-instance v0, Lc8/a;

    .line 243
    .line 244
    invoke-interface {p3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    check-cast v1, Ljava/lang/Integer;

    .line 249
    .line 250
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 251
    .line 252
    .line 253
    move-result v1

    .line 254
    invoke-interface {p3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p3

    .line 258
    check-cast p3, Ljava/util/Set;

    .line 259
    .line 260
    invoke-direct {v0, v1, p3}, Lc8/a;-><init>(ILjava/util/Set;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {p0, v0}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    goto :goto_4

    .line 267
    :cond_8
    invoke-virtual {p0}, Lhr/e0;->i()Lhr/x0;

    .line 268
    .line 269
    .line 270
    move-result-object p0

    .line 271
    invoke-direct {p1, p0}, Lc8/b;-><init>(Lhr/x0;)V

    .line 272
    .line 273
    .line 274
    return-object p1

    .line 275
    :cond_9
    if-nez p3, :cond_a

    .line 276
    .line 277
    invoke-virtual {v2, v0}, Landroid/media/AudioManager;->getDevices(I)[Landroid/media/AudioDeviceInfo;

    .line 278
    .line 279
    .line 280
    move-result-object p3

    .line 281
    goto :goto_5

    .line 282
    :cond_a
    new-array v0, v9, [Landroid/media/AudioDeviceInfo;

    .line 283
    .line 284
    iget-object p3, p3, La0/j;->e:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast p3, Landroid/media/AudioDeviceInfo;

    .line 287
    .line 288
    aput-object p3, v0, v4

    .line 289
    .line 290
    move-object p3, v0

    .line 291
    :goto_5
    new-instance v0, Lhr/j0;

    .line 292
    .line 293
    const/4 v2, 0x4

    .line 294
    invoke-direct {v0, v2}, Lhr/b0;-><init>(I)V

    .line 295
    .line 296
    .line 297
    const/16 v10, 0x8

    .line 298
    .line 299
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 300
    .line 301
    .line 302
    move-result-object v10

    .line 303
    const/4 v11, 0x7

    .line 304
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 305
    .line 306
    .line 307
    move-result-object v11

    .line 308
    filled-new-array {v10, v11}, [Ljava/lang/Integer;

    .line 309
    .line 310
    .line 311
    move-result-object v10

    .line 312
    invoke-virtual {v0, v10}, Lhr/b0;->b([Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    const/16 v10, 0x1f

    .line 316
    .line 317
    if-lt v5, v10, :cond_b

    .line 318
    .line 319
    const/16 v10, 0x1a

    .line 320
    .line 321
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 322
    .line 323
    .line 324
    move-result-object v10

    .line 325
    const/16 v11, 0x1b

    .line 326
    .line 327
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 328
    .line 329
    .line 330
    move-result-object v11

    .line 331
    filled-new-array {v10, v11}, [Ljava/lang/Integer;

    .line 332
    .line 333
    .line 334
    move-result-object v10

    .line 335
    invoke-virtual {v0, v10}, Lhr/b0;->b([Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    :cond_b
    if-lt v5, v3, :cond_c

    .line 339
    .line 340
    const/16 v3, 0x1e

    .line 341
    .line 342
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 343
    .line 344
    .line 345
    move-result-object v3

    .line 346
    invoke-virtual {v0, v3}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    :cond_c
    invoke-virtual {v0}, Lhr/j0;->i()Lhr/k0;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    array-length v3, p3

    .line 354
    move v5, v4

    .line 355
    :goto_6
    if-ge v5, v3, :cond_e

    .line 356
    .line 357
    aget-object v10, p3, v5

    .line 358
    .line 359
    invoke-virtual {v10}, Landroid/media/AudioDeviceInfo;->getType()I

    .line 360
    .line 361
    .line 362
    move-result v10

    .line 363
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 364
    .line 365
    .line 366
    move-result-object v10

    .line 367
    invoke-virtual {v0, v10}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 368
    .line 369
    .line 370
    move-result v10

    .line 371
    if-eqz v10, :cond_d

    .line 372
    .line 373
    sget-object p0, Lc8/b;->c:Lc8/b;

    .line 374
    .line 375
    return-object p0

    .line 376
    :cond_d
    add-int/lit8 v5, v5, 0x1

    .line 377
    .line 378
    goto :goto_6

    .line 379
    :cond_e
    new-instance p3, Lhr/j0;

    .line 380
    .line 381
    invoke-direct {p3, v2}, Lhr/b0;-><init>(I)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {p3, v1}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 385
    .line 386
    .line 387
    invoke-static {p0}, Lw7/w;->C(Landroid/content/Context;)Z

    .line 388
    .line 389
    .line 390
    move-result v0

    .line 391
    const/16 v2, 0xa

    .line 392
    .line 393
    if-nez v0, :cond_15

    .line 394
    .line 395
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    invoke-virtual {v0, v6}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 400
    .line 401
    .line 402
    move-result v0

    .line 403
    if-eqz v0, :cond_f

    .line 404
    .line 405
    goto/16 :goto_8

    .line 406
    .line 407
    :cond_f
    invoke-virtual {p0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 408
    .line 409
    .line 410
    move-result-object p0

    .line 411
    const-string p2, "use_external_surround_sound_flag"

    .line 412
    .line 413
    invoke-static {p0, p2, v4}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I

    .line 414
    .line 415
    .line 416
    move-result p2

    .line 417
    if-ne p2, v9, :cond_10

    .line 418
    .line 419
    move p2, v9

    .line 420
    goto :goto_7

    .line 421
    :cond_10
    move p2, v4

    .line 422
    :goto_7
    if-nez p2, :cond_11

    .line 423
    .line 424
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 425
    .line 426
    const-string v1, "Amazon"

    .line 427
    .line 428
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 429
    .line 430
    .line 431
    move-result v1

    .line 432
    if-nez v1, :cond_11

    .line 433
    .line 434
    const-string v1, "Xiaomi"

    .line 435
    .line 436
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    move-result v0

    .line 440
    if-eqz v0, :cond_12

    .line 441
    .line 442
    :cond_11
    const-string v0, "external_surround_sound_enabled"

    .line 443
    .line 444
    invoke-static {p0, v0, v4}, Landroid/provider/Settings$Global;->getInt(Landroid/content/ContentResolver;Ljava/lang/String;I)I

    .line 445
    .line 446
    .line 447
    move-result p0

    .line 448
    if-ne p0, v9, :cond_12

    .line 449
    .line 450
    sget-object p0, Lc8/b;->d:Lhr/x0;

    .line 451
    .line 452
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 453
    .line 454
    .line 455
    invoke-virtual {p3, p0}, Lhr/b0;->d(Ljava/lang/Iterable;)V

    .line 456
    .line 457
    .line 458
    :cond_12
    if-eqz p1, :cond_14

    .line 459
    .line 460
    if-nez p2, :cond_14

    .line 461
    .line 462
    const-string p0, "android.media.extra.AUDIO_PLUG_STATE"

    .line 463
    .line 464
    invoke-virtual {p1, p0, v4}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 465
    .line 466
    .line 467
    move-result p0

    .line 468
    if-ne p0, v9, :cond_14

    .line 469
    .line 470
    const-string p0, "android.media.extra.ENCODINGS"

    .line 471
    .line 472
    invoke-virtual {p1, p0}, Landroid/content/Intent;->getIntArrayExtra(Ljava/lang/String;)[I

    .line 473
    .line 474
    .line 475
    move-result-object p0

    .line 476
    if-eqz p0, :cond_13

    .line 477
    .line 478
    invoke-static {p0}, Llp/de;->b([I)Ljava/util/List;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    check-cast p0, Ljava/util/List;

    .line 483
    .line 484
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 485
    .line 486
    .line 487
    invoke-virtual {p3, p0}, Lhr/b0;->d(Ljava/lang/Iterable;)V

    .line 488
    .line 489
    .line 490
    :cond_13
    new-instance p0, Lc8/b;

    .line 491
    .line 492
    invoke-virtual {p3}, Lhr/j0;->i()Lhr/k0;

    .line 493
    .line 494
    .line 495
    move-result-object p2

    .line 496
    invoke-static {p2}, Llp/de;->f(Ljava/util/Collection;)[I

    .line 497
    .line 498
    .line 499
    move-result-object p2

    .line 500
    const-string p3, "android.media.extra.MAX_CHANNEL_COUNT"

    .line 501
    .line 502
    invoke-virtual {p1, p3, v2}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 503
    .line 504
    .line 505
    move-result p1

    .line 506
    invoke-static {p1, p2}, Lc8/b;->a(I[I)Lhr/x0;

    .line 507
    .line 508
    .line 509
    move-result-object p1

    .line 510
    invoke-direct {p0, p1}, Lc8/b;-><init>(Lhr/x0;)V

    .line 511
    .line 512
    .line 513
    return-object p0

    .line 514
    :cond_14
    new-instance p0, Lc8/b;

    .line 515
    .line 516
    invoke-virtual {p3}, Lhr/j0;->i()Lhr/k0;

    .line 517
    .line 518
    .line 519
    move-result-object p1

    .line 520
    invoke-static {p1}, Llp/de;->f(Ljava/util/Collection;)[I

    .line 521
    .line 522
    .line 523
    move-result-object p1

    .line 524
    invoke-static {v2, p1}, Lc8/b;->a(I[I)Lhr/x0;

    .line 525
    .line 526
    .line 527
    move-result-object p1

    .line 528
    invoke-direct {p0, p1}, Lc8/b;-><init>(Lhr/x0;)V

    .line 529
    .line 530
    .line 531
    return-object p0

    .line 532
    :cond_15
    :goto_8
    invoke-static {}, Lhr/h0;->o()Lhr/e0;

    .line 533
    .line 534
    .line 535
    move-result-object p0

    .line 536
    invoke-virtual {v7}, Lhr/c1;->c()Lhr/k0;

    .line 537
    .line 538
    .line 539
    move-result-object p1

    .line 540
    invoke-virtual {p1}, Lhr/k0;->s()Lhr/l1;

    .line 541
    .line 542
    .line 543
    move-result-object p1

    .line 544
    :cond_16
    :goto_9
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 545
    .line 546
    .line 547
    move-result v0

    .line 548
    if-eqz v0, :cond_18

    .line 549
    .line 550
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object v0

    .line 554
    check-cast v0, Ljava/lang/Integer;

    .line 555
    .line 556
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 557
    .line 558
    .line 559
    move-result v3

    .line 560
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 561
    .line 562
    invoke-static {v3}, Lw7/w;->l(I)I

    .line 563
    .line 564
    .line 565
    move-result v5

    .line 566
    if-ge v4, v5, :cond_17

    .line 567
    .line 568
    goto :goto_9

    .line 569
    :cond_17
    new-instance v4, Landroid/media/AudioFormat$Builder;

    .line 570
    .line 571
    invoke-direct {v4}, Landroid/media/AudioFormat$Builder;-><init>()V

    .line 572
    .line 573
    .line 574
    invoke-virtual {v4, v8}, Landroid/media/AudioFormat$Builder;->setChannelMask(I)Landroid/media/AudioFormat$Builder;

    .line 575
    .line 576
    .line 577
    move-result-object v4

    .line 578
    invoke-virtual {v4, v3}, Landroid/media/AudioFormat$Builder;->setEncoding(I)Landroid/media/AudioFormat$Builder;

    .line 579
    .line 580
    .line 581
    move-result-object v3

    .line 582
    const v4, 0xbb80

    .line 583
    .line 584
    .line 585
    invoke-virtual {v3, v4}, Landroid/media/AudioFormat$Builder;->setSampleRate(I)Landroid/media/AudioFormat$Builder;

    .line 586
    .line 587
    .line 588
    move-result-object v3

    .line 589
    invoke-virtual {v3}, Landroid/media/AudioFormat$Builder;->build()Landroid/media/AudioFormat;

    .line 590
    .line 591
    .line 592
    move-result-object v3

    .line 593
    invoke-virtual {p2}, Lt7/c;->a()Lpv/g;

    .line 594
    .line 595
    .line 596
    move-result-object v4

    .line 597
    iget-object v4, v4, Lpv/g;->e:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast v4, Landroid/media/AudioAttributes;

    .line 600
    .line 601
    invoke-static {v3, v4}, Landroid/media/AudioTrack;->isDirectPlaybackSupported(Landroid/media/AudioFormat;Landroid/media/AudioAttributes;)Z

    .line 602
    .line 603
    .line 604
    move-result v3

    .line 605
    if-eqz v3, :cond_16

    .line 606
    .line 607
    invoke-virtual {p0, v0}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 608
    .line 609
    .line 610
    goto :goto_9

    .line 611
    :cond_18
    invoke-virtual {p0, v1}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 612
    .line 613
    .line 614
    invoke-virtual {p0}, Lhr/e0;->i()Lhr/x0;

    .line 615
    .line 616
    .line 617
    move-result-object p0

    .line 618
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 619
    .line 620
    .line 621
    invoke-virtual {p3, p0}, Lhr/b0;->d(Ljava/lang/Iterable;)V

    .line 622
    .line 623
    .line 624
    new-instance p0, Lc8/b;

    .line 625
    .line 626
    invoke-virtual {p3}, Lhr/j0;->i()Lhr/k0;

    .line 627
    .line 628
    .line 629
    move-result-object p1

    .line 630
    invoke-static {p1}, Llp/de;->f(Ljava/util/Collection;)[I

    .line 631
    .line 632
    .line 633
    move-result-object p1

    .line 634
    invoke-static {v2, p1}, Lc8/b;->a(I[I)Lhr/x0;

    .line 635
    .line 636
    .line 637
    move-result-object p1

    .line 638
    invoke-direct {p0, p1}, Lc8/b;-><init>(Lhr/x0;)V

    .line 639
    .line 640
    .line 641
    return-object p0
.end method

.method public static c(Landroid/content/Context;Lt7/c;La0/j;)Lc8/b;
    .locals 2

    .line 1
    new-instance v0, Landroid/content/IntentFilter;

    .line 2
    .line 3
    const-string v1, "android.media.action.HDMI_AUDIO_PLUG"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {p0, v1, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {p0, v0, p1, p2}, Lc8/b;->b(Landroid/content/Context;Landroid/content/Intent;Lt7/c;La0/j;)Lc8/b;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final d(Lt7/o;Lt7/c;)Landroid/util/Pair;
    .locals 8

    .line 1
    iget-object v0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Lt7/o;->k:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lt7/d0;->c(Ljava/lang/String;Ljava/lang/String;)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    sget-object v1, Lc8/b;->e:Lhr/c1;

    .line 13
    .line 14
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v1, v2}, Lhr/c1;->containsKey(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    goto/16 :goto_7

    .line 25
    .line 26
    :cond_0
    const/16 v1, 0x12

    .line 27
    .line 28
    iget-object p0, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 29
    .line 30
    if-ne v0, v1, :cond_1

    .line 31
    .line 32
    invoke-static {p0, v1}, Lw7/w;->i(Landroid/util/SparseArray;I)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-nez v2, :cond_1

    .line 37
    .line 38
    const/4 v0, 0x6

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/16 v2, 0x8

    .line 41
    .line 42
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    invoke-static {p0, v2}, Lw7/w;->i(Landroid/util/SparseArray;I)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_3

    .line 49
    .line 50
    :cond_2
    const/16 v2, 0x1e

    .line 51
    .line 52
    if-ne v0, v2, :cond_4

    .line 53
    .line 54
    invoke-static {p0, v2}, Lw7/w;->i(Landroid/util/SparseArray;I)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-nez v2, :cond_4

    .line 59
    .line 60
    :cond_3
    const/4 v0, 0x7

    .line 61
    :cond_4
    :goto_0
    invoke-static {p0, v0}, Lw7/w;->i(Landroid/util/SparseArray;I)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-nez v2, :cond_5

    .line 66
    .line 67
    goto/16 :goto_7

    .line 68
    .line 69
    :cond_5
    invoke-virtual {p0, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    check-cast p0, Lc8/a;

    .line 74
    .line 75
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    iget v2, p0, Lc8/a;->b:I

    .line 79
    .line 80
    iget-object v3, p0, Lc8/a;->c:Lhr/k0;

    .line 81
    .line 82
    iget v4, p1, Lt7/o;->F:I

    .line 83
    .line 84
    const/4 v5, 0x0

    .line 85
    const/16 v6, 0xa

    .line 86
    .line 87
    const/4 v7, -0x1

    .line 88
    if-eq v4, v7, :cond_b

    .line 89
    .line 90
    if-ne v0, v1, :cond_6

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_6
    iget-object p0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 94
    .line 95
    const-string p1, "audio/vnd.dts.uhd;profile=p2"

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-eqz p0, :cond_7

    .line 102
    .line 103
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 104
    .line 105
    const/16 p1, 0x21

    .line 106
    .line 107
    if-ge p0, p1, :cond_7

    .line 108
    .line 109
    if-le v4, v6, :cond_11

    .line 110
    .line 111
    goto/16 :goto_7

    .line 112
    .line 113
    :cond_7
    if-nez v3, :cond_8

    .line 114
    .line 115
    if-gt v4, v2, :cond_a

    .line 116
    .line 117
    const/4 v5, 0x1

    .line 118
    goto :goto_1

    .line 119
    :cond_8
    invoke-static {v4}, Lw7/w;->m(I)I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    if-nez p0, :cond_9

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_9
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-virtual {v3, p0}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    :cond_a
    :goto_1
    if-nez v5, :cond_11

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :cond_b
    :goto_2
    iget p1, p1, Lt7/o;->G:I

    .line 138
    .line 139
    if-eq p1, v7, :cond_c

    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_c
    const p1, 0xbb80

    .line 143
    .line 144
    .line 145
    :goto_3
    if-eqz v3, :cond_d

    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_d
    iget p0, p0, Lc8/a;->a:I

    .line 149
    .line 150
    move v2, v6

    .line 151
    :goto_4
    if-lez v2, :cond_10

    .line 152
    .line 153
    invoke-static {v2}, Lw7/w;->m(I)I

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    if-nez v1, :cond_e

    .line 158
    .line 159
    goto :goto_5

    .line 160
    :cond_e
    new-instance v3, Landroid/media/AudioFormat$Builder;

    .line 161
    .line 162
    invoke-direct {v3}, Landroid/media/AudioFormat$Builder;-><init>()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v3, p0}, Landroid/media/AudioFormat$Builder;->setEncoding(I)Landroid/media/AudioFormat$Builder;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    invoke-virtual {v3, p1}, Landroid/media/AudioFormat$Builder;->setSampleRate(I)Landroid/media/AudioFormat$Builder;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    invoke-virtual {v3, v1}, Landroid/media/AudioFormat$Builder;->setChannelMask(I)Landroid/media/AudioFormat$Builder;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    invoke-virtual {v1}, Landroid/media/AudioFormat$Builder;->build()Landroid/media/AudioFormat;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    invoke-virtual {p2}, Lt7/c;->a()Lpv/g;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    iget-object v3, v3, Lpv/g;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v3, Landroid/media/AudioAttributes;

    .line 188
    .line 189
    invoke-static {v1, v3}, Landroid/media/AudioTrack;->isDirectPlaybackSupported(Landroid/media/AudioFormat;Landroid/media/AudioAttributes;)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-eqz v1, :cond_f

    .line 194
    .line 195
    goto :goto_6

    .line 196
    :cond_f
    :goto_5
    add-int/lit8 v2, v2, -0x1

    .line 197
    .line 198
    goto :goto_4

    .line 199
    :cond_10
    move v2, v5

    .line 200
    :goto_6
    move v4, v2

    .line 201
    :cond_11
    invoke-static {v4}, Lw7/w;->m(I)I

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    if-nez p0, :cond_12

    .line 206
    .line 207
    :goto_7
    const/4 p0, 0x0

    .line 208
    return-object p0

    .line 209
    :cond_12
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    invoke-static {p1, p0}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto :goto_3

    .line 5
    :cond_0
    instance-of v1, p1, Lc8/b;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    goto :goto_4

    .line 11
    :cond_1
    check-cast p1, Lc8/b;

    .line 12
    .line 13
    iget-object v1, p1, Lc8/b;->a:Landroid/util/SparseArray;

    .line 14
    .line 15
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v3, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 18
    .line 19
    if-nez v3, :cond_4

    .line 20
    .line 21
    if-nez v1, :cond_3

    .line 22
    .line 23
    :cond_2
    move v1, v0

    .line 24
    goto :goto_2

    .line 25
    :cond_3
    :goto_0
    move v1, v2

    .line 26
    goto :goto_2

    .line 27
    :cond_4
    if-nez v1, :cond_5

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_5
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 31
    .line 32
    const/16 v5, 0x1f

    .line 33
    .line 34
    if-lt v4, v5, :cond_6

    .line 35
    .line 36
    invoke-static {v3, v1}, Lh4/b;->A(Landroid/util/SparseArray;Landroid/util/SparseArray;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    goto :goto_2

    .line 41
    :cond_6
    invoke-virtual {v3}, Landroid/util/SparseArray;->size()I

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-eq v4, v5, :cond_7

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_7
    move v5, v2

    .line 53
    :goto_1
    if-ge v5, v4, :cond_2

    .line 54
    .line 55
    invoke-virtual {v3, v5}, Landroid/util/SparseArray;->keyAt(I)I

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    invoke-virtual {v3, v5}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    invoke-virtual {v1, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    invoke-static {v7, v6}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    if-nez v6, :cond_8

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :goto_2
    if-eqz v1, :cond_9

    .line 78
    .line 79
    iget p0, p0, Lc8/b;->b:I

    .line 80
    .line 81
    iget p1, p1, Lc8/b;->b:I

    .line 82
    .line 83
    if-ne p0, p1, :cond_9

    .line 84
    .line 85
    :goto_3
    return v0

    .line 86
    :cond_9
    :goto_4
    return v2
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 2
    .line 3
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 4
    .line 5
    const/16 v1, 0x1f

    .line 6
    .line 7
    iget-object v2, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 8
    .line 9
    if-lt v0, v1, :cond_0

    .line 10
    .line 11
    invoke-static {v2}, Lh4/b;->c(Landroid/util/SparseArray;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    const/16 v0, 0x11

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    :goto_0
    invoke-virtual {v2}, Landroid/util/SparseArray;->size()I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    if-ge v3, v4, :cond_1

    .line 24
    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Landroid/util/SparseArray;->keyAt(I)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    add-int/2addr v4, v0

    .line 32
    mul-int/2addr v4, v1

    .line 33
    invoke-virtual {v2, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {v0}, Ljava/util/Objects;->hashCode(Ljava/lang/Object;)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    add-int/2addr v0, v4

    .line 42
    add-int/lit8 v3, v3, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    :goto_1
    mul-int/2addr v0, v1

    .line 46
    iget p0, p0, Lc8/b;->b:I

    .line 47
    .line 48
    add-int/2addr v0, p0

    .line 49
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "AudioCapabilities[maxChannelCount="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lc8/b;->b:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", audioProfiles="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lc8/b;->a:Landroid/util/SparseArray;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "]"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
