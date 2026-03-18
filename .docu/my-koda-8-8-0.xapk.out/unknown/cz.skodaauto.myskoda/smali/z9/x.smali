.class public Lz9/x;
.super Lz9/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lz9/j0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0017\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Lz9/x;",
        "Lz9/j0;",
        "Lz9/v;",
        "navigation-common_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Lz9/i0;
    value = "navigation"
.end annotation


# instance fields
.field public final c:Lz9/k0;


# direct methods
.method public constructor <init>(Lz9/k0;)V
    .locals 1

    .line 1
    const-string v0, "navigatorProvider"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lz9/x;->c:Lz9/k0;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public bridge synthetic a()Lz9/u;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lz9/x;->g()Lz9/v;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d(Ljava/util/List;Lz9/b0;)V
    .locals 6

    .line 1
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_c

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lz9/k;

    .line 16
    .line 17
    iget-object v1, v0, Lz9/k;->e:Lz9/u;

    .line 18
    .line 19
    const-string v2, "null cannot be cast to non-null type androidx.navigation.NavGraph"

    .line 20
    .line 21
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    check-cast v1, Lz9/v;

    .line 25
    .line 26
    iget-object v2, v1, Lz9/u;->e:Lca/j;

    .line 27
    .line 28
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 29
    .line 30
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    iget-object v0, v0, Lz9/k;->k:Lca/c;

    .line 34
    .line 35
    invoke-virtual {v0}, Lca/c;->a()Landroid/os/Bundle;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iput-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 40
    .line 41
    iget-object v0, v1, Lz9/v;->i:Lca/m;

    .line 42
    .line 43
    iget v1, v0, Lca/m;->d:I

    .line 44
    .line 45
    iget-object v4, v0, Lca/m;->h:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v4, Ljava/lang/String;

    .line 48
    .line 49
    if-nez v1, :cond_2

    .line 50
    .line 51
    if-eqz v4, :cond_0

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    iget p0, v2, Lca/j;->a:I

    .line 58
    .line 59
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string p1, "superName"

    .line 64
    .line 65
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object p1, v0, Lca/m;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p1, Lz9/v;

    .line 71
    .line 72
    iget-object p1, p1, Lz9/u;->e:Lca/j;

    .line 73
    .line 74
    iget p1, p1, Lca/j;->a:I

    .line 75
    .line 76
    if-eqz p1, :cond_1

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_1
    const-string p0, "the root navigation"

    .line 80
    .line 81
    :goto_1
    const-string p1, "no start destination defined via app:startDestination for "

    .line 82
    .line 83
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p1

    .line 97
    :cond_2
    :goto_2
    const/4 v2, 0x0

    .line 98
    if-eqz v4, :cond_3

    .line 99
    .line 100
    invoke-virtual {v0, v4, v2}, Lca/m;->e(Ljava/lang/String;Z)Lz9/u;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    goto :goto_3

    .line 105
    :cond_3
    iget-object v5, v0, Lca/m;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v5, Landroidx/collection/b1;

    .line 108
    .line 109
    invoke-virtual {v5, v1}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Lz9/u;

    .line 114
    .line 115
    :goto_3
    if-nez v1, :cond_6

    .line 116
    .line 117
    iget-object p0, v0, Lca/m;->g:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p0, Ljava/lang/String;

    .line 120
    .line 121
    if-nez p0, :cond_5

    .line 122
    .line 123
    iget-object p0, v0, Lca/m;->h:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Ljava/lang/String;

    .line 126
    .line 127
    if-nez p0, :cond_4

    .line 128
    .line 129
    iget p0, v0, Lca/m;->d:I

    .line 130
    .line 131
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    :cond_4
    iput-object p0, v0, Lca/m;->g:Ljava/lang/Object;

    .line 136
    .line 137
    :cond_5
    iget-object p0, v0, Lca/m;->g:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast p0, Ljava/lang/String;

    .line 140
    .line 141
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 145
    .line 146
    const-string p2, "navigation destination "

    .line 147
    .line 148
    const-string v0, " is not a direct child of this NavGraph"

    .line 149
    .line 150
    invoke-static {p2, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw p1

    .line 158
    :cond_6
    iget-object v0, v1, Lz9/u;->e:Lca/j;

    .line 159
    .line 160
    if-eqz v4, :cond_b

    .line 161
    .line 162
    iget-object v5, v0, Lca/j;->e:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v5, Ljava/lang/String;

    .line 165
    .line 166
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    if-nez v5, :cond_9

    .line 171
    .line 172
    invoke-virtual {v0, v4}, Lca/j;->h(Ljava/lang/String;)Lz9/t;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    if-eqz v0, :cond_7

    .line 177
    .line 178
    iget-object v0, v0, Lz9/t;->e:Landroid/os/Bundle;

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_7
    const/4 v0, 0x0

    .line 182
    :goto_4
    if-eqz v0, :cond_9

    .line 183
    .line 184
    invoke-virtual {v0}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 185
    .line 186
    .line 187
    move-result v4

    .line 188
    if-nez v4, :cond_9

    .line 189
    .line 190
    new-array v4, v2, [Llx0/l;

    .line 191
    .line 192
    invoke-static {v4, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    check-cast v2, [Llx0/l;

    .line 197
    .line 198
    invoke-static {v2}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 199
    .line 200
    .line 201
    move-result-object v2

    .line 202
    invoke-virtual {v2, v0}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 203
    .line 204
    .line 205
    iget-object v0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 206
    .line 207
    check-cast v0, Landroid/os/Bundle;

    .line 208
    .line 209
    if-eqz v0, :cond_8

    .line 210
    .line 211
    invoke-virtual {v2, v0}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 212
    .line 213
    .line 214
    :cond_8
    iput-object v2, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 215
    .line 216
    :cond_9
    invoke-virtual {v1}, Lz9/u;->i()Ljava/util/Map;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    if-nez v0, :cond_b

    .line 225
    .line 226
    invoke-virtual {v1}, Lz9/u;->i()Ljava/util/Map;

    .line 227
    .line 228
    .line 229
    move-result-object v0

    .line 230
    new-instance v2, Lo1/w0;

    .line 231
    .line 232
    const/4 v4, 0x2

    .line 233
    invoke-direct {v2, v3, v4}, Lo1/w0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 234
    .line 235
    .line 236
    invoke-static {v0, v2}, Ljb0/b;->e(Ljava/util/Map;Lay0/k;)Ljava/util/ArrayList;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 241
    .line 242
    .line 243
    move-result v2

    .line 244
    if-eqz v2, :cond_a

    .line 245
    .line 246
    goto :goto_5

    .line 247
    :cond_a
    new-instance p0, Ljava/lang/StringBuilder;

    .line 248
    .line 249
    const-string p1, "Cannot navigate to startDestination "

    .line 250
    .line 251
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    const-string p1, ". Missing required arguments ["

    .line 258
    .line 259
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    const/16 p1, 0x5d

    .line 266
    .line 267
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 268
    .line 269
    .line 270
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 275
    .line 276
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw p1

    .line 284
    :cond_b
    :goto_5
    iget-object v0, p0, Lz9/x;->c:Lz9/k0;

    .line 285
    .line 286
    iget-object v2, v1, Lz9/u;->d:Ljava/lang/String;

    .line 287
    .line 288
    invoke-virtual {v0, v2}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    invoke-virtual {p0}, Lz9/j0;->b()Lz9/m;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    iget-object v3, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast v3, Landroid/os/Bundle;

    .line 299
    .line 300
    invoke-virtual {v1, v3}, Lz9/u;->e(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 301
    .line 302
    .line 303
    move-result-object v3

    .line 304
    invoke-virtual {v2, v1, v3}, Lz9/m;->b(Lz9/u;Landroid/os/Bundle;)Lz9/k;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 309
    .line 310
    .line 311
    move-result-object v1

    .line 312
    invoke-virtual {v0, v1, p2}, Lz9/j0;->d(Ljava/util/List;Lz9/b0;)V

    .line 313
    .line 314
    .line 315
    goto/16 :goto_0

    .line 316
    .line 317
    :cond_c
    return-void
.end method

.method public g()Lz9/v;
    .locals 1

    .line 1
    new-instance v0, Lz9/v;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lz9/v;-><init>(Lz9/x;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
