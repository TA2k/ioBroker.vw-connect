.class public abstract Lip/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lip/s;


# direct methods
.method public static final a(Ljava/util/List;)V
    .locals 1

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    instance-of v0, p0, Ljava/util/Collection;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object v0, p0

    .line 8
    check-cast v0, Ljava/util/Collection;

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Ly6/l;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    :goto_1
    return-void
.end method

.method public static final varargs b([Lz6/d;)Lz6/f;
    .locals 7

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    array-length v1, p0

    .line 4
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 5
    .line 6
    .line 7
    array-length v1, p0

    .line 8
    const/4 v2, 0x0

    .line 9
    move v3, v2

    .line 10
    :goto_0
    if-ge v3, v1, :cond_0

    .line 11
    .line 12
    aget-object v4, p0, v3

    .line 13
    .line 14
    iget-object v5, v4, Lz6/d;->a:Lz6/c;

    .line 15
    .line 16
    iget-object v4, v4, Lz6/d;->b:Ljava/lang/Boolean;

    .line 17
    .line 18
    new-instance v6, Llx0/l;

    .line 19
    .line 20
    invoke-direct {v6, v5, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    add-int/lit8 v3, v3, 0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-array p0, v2, [Llx0/l;

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    check-cast p0, [Llx0/l;

    .line 36
    .line 37
    array-length v0, p0

    .line 38
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, [Llx0/l;

    .line 43
    .line 44
    invoke-static {p0}, Lmx0/x;->n([Llx0/l;)Ljava/util/LinkedHashMap;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    new-instance v0, Lz6/f;

    .line 49
    .line 50
    invoke-direct {v0, p0}, Lz6/f;-><init>(Ljava/util/LinkedHashMap;)V

    .line 51
    .line 52
    .line 53
    return-object v0
.end method

.method public static final c(Landroid/widget/RemoteViews;La7/e2;La7/d1;Ljava/util/List;)V
    .locals 3

    .line 1
    check-cast p3, Ljava/lang/Iterable;

    .line 2
    .line 3
    const/16 v0, 0xa

    .line 4
    .line 5
    invoke-static {p3, v0}, Lmx0/q;->q0(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    check-cast p3, Ljava/lang/Iterable;

    .line 10
    .line 11
    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    const/4 v0, 0x0

    .line 16
    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    add-int/lit8 v2, v0, 0x1

    .line 27
    .line 28
    if-ltz v0, :cond_0

    .line 29
    .line 30
    check-cast v1, Ly6/l;

    .line 31
    .line 32
    invoke-virtual {p1, p2, v0}, La7/e2;->b(La7/d1;I)La7/e2;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {p0, v0, v1}, Lip/t;->e(Landroid/widget/RemoteViews;La7/e2;Ly6/l;)V

    .line 37
    .line 38
    .line 39
    move v0, v2

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-static {}, Ljp/k1;->r()V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x0

    .line 45
    throw p0

    .line 46
    :cond_1
    return-void
.end method

.method public static final d(Lf7/c;)I
    .locals 7

    .line 1
    iget v0, p0, Lf7/c;->a:I

    .line 2
    .line 3
    const-string v1, "GlanceAppWidget"

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    const v4, 0x800003

    .line 8
    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    if-ne v0, v2, :cond_1

    .line 14
    .line 15
    const v4, 0x800005

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    if-ne v0, v3, :cond_2

    .line 20
    .line 21
    move v4, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_2
    new-instance v5, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v6, "Unknown horizontal alignment: "

    .line 26
    .line 27
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0}, Lf7/a;->b(I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    :goto_0
    iget p0, p0, Lf7/c;->b:I

    .line 45
    .line 46
    const/16 v0, 0x30

    .line 47
    .line 48
    if-nez p0, :cond_3

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_3
    if-ne p0, v2, :cond_4

    .line 52
    .line 53
    const/16 v0, 0x50

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_4
    if-ne p0, v3, :cond_5

    .line 57
    .line 58
    const/16 v0, 0x10

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_5
    new-instance v2, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    const-string v3, "Unknown vertical alignment: "

    .line 64
    .line 65
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-static {p0}, Lf7/b;->b(I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-static {v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    :goto_1
    or-int p0, v4, v0

    .line 83
    .line 84
    return p0
.end method

.method public static final e(Landroid/widget/RemoteViews;La7/e2;Ly6/l;)V
    .locals 20

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v0, p2

    .line 4
    .line 5
    iget-object v2, v1, La7/e2;->a:Landroid/content/Context;

    .line 6
    .line 7
    sget-object v9, La7/s;->n:La7/s;

    .line 8
    .line 9
    instance-of v3, v0, Lf7/k;

    .line 10
    .line 11
    if-eqz v3, :cond_1

    .line 12
    .line 13
    move-object v7, v0

    .line 14
    check-cast v7, Lf7/k;

    .line 15
    .line 16
    iget-object v8, v7, Ly6/n;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    iget-object v4, v7, Lf7/k;->c:Ly6/q;

    .line 23
    .line 24
    iget-object v0, v7, Lf7/k;->d:Lf7/c;

    .line 25
    .line 26
    iget v2, v0, Lf7/c;->a:I

    .line 27
    .line 28
    new-instance v5, Lf7/a;

    .line 29
    .line 30
    invoke-direct {v5, v2}, Lf7/a;-><init>(I)V

    .line 31
    .line 32
    .line 33
    iget v0, v0, Lf7/c;->b:I

    .line 34
    .line 35
    new-instance v6, Lf7/b;

    .line 36
    .line 37
    invoke-direct {v6, v0}, Lf7/b;-><init>(I)V

    .line 38
    .line 39
    .line 40
    sget-object v2, La7/m1;->f:La7/m1;

    .line 41
    .line 42
    move-object/from16 v0, p0

    .line 43
    .line 44
    invoke-static/range {v0 .. v6}, La7/j1;->b(Landroid/widget/RemoteViews;La7/e2;La7/m1;ILy6/q;Lf7/a;Lf7/b;)La7/d1;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    move-object v3, v1

    .line 49
    move-object v1, v0

    .line 50
    iget-object v0, v7, Lf7/k;->c:Ly6/q;

    .line 51
    .line 52
    invoke-static {v3, v1, v0, v2}, Lev/a;->b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_0

    .line 64
    .line 65
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    check-cast v4, Ly6/l;

    .line 70
    .line 71
    invoke-interface {v4}, Ly6/l;->b()Ly6/q;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    new-instance v6, La7/a;

    .line 76
    .line 77
    iget-object v9, v7, Lf7/k;->d:Lf7/c;

    .line 78
    .line 79
    invoke-direct {v6, v9}, La7/a;-><init>(Lf7/c;)V

    .line 80
    .line 81
    .line 82
    invoke-interface {v5, v6}, Ly6/q;->d(Ly6/q;)Ly6/q;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-interface {v4, v5}, Ly6/l;->a(Ly6/q;)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    invoke-static {v1, v3, v2, v8}, Lip/t;->c(Landroid/widget/RemoteViews;La7/e2;La7/d1;Ljava/util/List;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_1
    move-object v3, v1

    .line 95
    move-object/from16 v1, p0

    .line 96
    .line 97
    instance-of v4, v0, Lf7/m;

    .line 98
    .line 99
    const-string v7, "setGravity"

    .line 100
    .line 101
    const/16 v5, 0x1f

    .line 102
    .line 103
    if-eqz v4, :cond_3

    .line 104
    .line 105
    move-object v10, v0

    .line 106
    check-cast v10, Lf7/m;

    .line 107
    .line 108
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 109
    .line 110
    if-lt v0, v5, :cond_2

    .line 111
    .line 112
    iget-object v0, v10, Lf7/m;->c:Ly6/q;

    .line 113
    .line 114
    invoke-interface {v0, v9}, Ly6/q;->b(Lay0/k;)Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v0, :cond_2

    .line 119
    .line 120
    sget-object v0, La7/m1;->E:La7/m1;

    .line 121
    .line 122
    :goto_1
    move-object v2, v0

    .line 123
    goto :goto_2

    .line 124
    :cond_2
    sget-object v0, La7/m1;->d:La7/m1;

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :goto_2
    iget-object v11, v10, Ly6/n;->b:Ljava/util/ArrayList;

    .line 128
    .line 129
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    iget-object v4, v10, Lf7/m;->c:Ly6/q;

    .line 134
    .line 135
    iget v0, v10, Lf7/m;->e:I

    .line 136
    .line 137
    new-instance v6, Lf7/b;

    .line 138
    .line 139
    invoke-direct {v6, v0}, Lf7/b;-><init>(I)V

    .line 140
    .line 141
    .line 142
    const/4 v5, 0x0

    .line 143
    move-object v0, v1

    .line 144
    move-object/from16 v1, p1

    .line 145
    .line 146
    invoke-static/range {v0 .. v6}, La7/j1;->b(Landroid/widget/RemoteViews;La7/e2;La7/m1;ILy6/q;Lf7/a;Lf7/b;)La7/d1;

    .line 147
    .line 148
    .line 149
    move-result-object v12

    .line 150
    move-object v13, v0

    .line 151
    iget v0, v12, La7/d1;->a:I

    .line 152
    .line 153
    new-instance v1, Lf7/c;

    .line 154
    .line 155
    iget v2, v10, Lf7/m;->d:I

    .line 156
    .line 157
    iget v3, v10, Lf7/m;->e:I

    .line 158
    .line 159
    invoke-direct {v1, v2, v3}, Lf7/c;-><init>(II)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1}, Lip/t;->d(Lf7/c;)I

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    invoke-virtual {v13, v0, v7, v1}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 167
    .line 168
    .line 169
    const/4 v7, 0x0

    .line 170
    const/16 v8, 0x6fff

    .line 171
    .line 172
    const/4 v1, 0x0

    .line 173
    const/4 v2, 0x0

    .line 174
    const/4 v3, 0x0

    .line 175
    const/4 v4, 0x0

    .line 176
    const-wide/16 v5, 0x0

    .line 177
    .line 178
    move-object/from16 v0, p1

    .line 179
    .line 180
    invoke-static/range {v0 .. v8}, La7/e2;->a(La7/e2;ILjava/util/concurrent/atomic/AtomicInteger;La7/d1;Ljava/util/concurrent/atomic/AtomicBoolean;JLjava/lang/Integer;I)La7/e2;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    move-object v3, v0

    .line 185
    iget-object v0, v10, Lf7/m;->c:Ly6/q;

    .line 186
    .line 187
    invoke-static {v1, v13, v0, v12}, Lev/a;->b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V

    .line 188
    .line 189
    .line 190
    invoke-static {v13, v3, v12, v11}, Lip/t;->c(Landroid/widget/RemoteViews;La7/e2;La7/d1;Ljava/util/List;)V

    .line 191
    .line 192
    .line 193
    iget-object v0, v10, Lf7/m;->c:Ly6/q;

    .line 194
    .line 195
    invoke-interface {v0, v9}, Ly6/q;->b(Lay0/k;)Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-eqz v0, :cond_26

    .line 200
    .line 201
    invoke-static {v11}, Lip/t;->a(Ljava/util/List;)V

    .line 202
    .line 203
    .line 204
    return-void

    .line 205
    :cond_3
    move-object v13, v1

    .line 206
    instance-of v1, v0, Lf7/l;

    .line 207
    .line 208
    if-eqz v1, :cond_5

    .line 209
    .line 210
    move-object v10, v0

    .line 211
    check-cast v10, Lf7/l;

    .line 212
    .line 213
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 214
    .line 215
    if-lt v0, v5, :cond_4

    .line 216
    .line 217
    iget-object v0, v10, Lf7/l;->c:Ly6/q;

    .line 218
    .line 219
    invoke-interface {v0, v9}, Ly6/q;->b(Lay0/k;)Z

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-eqz v0, :cond_4

    .line 224
    .line 225
    sget-object v0, La7/m1;->F:La7/m1;

    .line 226
    .line 227
    :goto_3
    move-object v2, v0

    .line 228
    goto :goto_4

    .line 229
    :cond_4
    sget-object v0, La7/m1;->e:La7/m1;

    .line 230
    .line 231
    goto :goto_3

    .line 232
    :goto_4
    iget-object v11, v10, Ly6/n;->b:Ljava/util/ArrayList;

    .line 233
    .line 234
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 235
    .line 236
    .line 237
    move-result v3

    .line 238
    iget-object v4, v10, Lf7/l;->c:Ly6/q;

    .line 239
    .line 240
    iget v0, v10, Lf7/l;->e:I

    .line 241
    .line 242
    new-instance v5, Lf7/a;

    .line 243
    .line 244
    invoke-direct {v5, v0}, Lf7/a;-><init>(I)V

    .line 245
    .line 246
    .line 247
    const/4 v6, 0x0

    .line 248
    move-object/from16 v1, p1

    .line 249
    .line 250
    move-object v0, v13

    .line 251
    invoke-static/range {v0 .. v6}, La7/j1;->b(Landroid/widget/RemoteViews;La7/e2;La7/m1;ILy6/q;Lf7/a;Lf7/b;)La7/d1;

    .line 252
    .line 253
    .line 254
    move-result-object v12

    .line 255
    iget v0, v12, La7/d1;->a:I

    .line 256
    .line 257
    new-instance v1, Lf7/c;

    .line 258
    .line 259
    iget v2, v10, Lf7/l;->e:I

    .line 260
    .line 261
    iget v3, v10, Lf7/l;->d:I

    .line 262
    .line 263
    invoke-direct {v1, v2, v3}, Lf7/c;-><init>(II)V

    .line 264
    .line 265
    .line 266
    invoke-static {v1}, Lip/t;->d(Lf7/c;)I

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    invoke-virtual {v13, v0, v7, v1}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 271
    .line 272
    .line 273
    const/4 v7, 0x0

    .line 274
    const/16 v8, 0x6fff

    .line 275
    .line 276
    const/4 v1, 0x0

    .line 277
    const/4 v2, 0x0

    .line 278
    const/4 v3, 0x0

    .line 279
    const/4 v4, 0x0

    .line 280
    const-wide/16 v5, 0x0

    .line 281
    .line 282
    move-object/from16 v0, p1

    .line 283
    .line 284
    invoke-static/range {v0 .. v8}, La7/e2;->a(La7/e2;ILjava/util/concurrent/atomic/AtomicInteger;La7/d1;Ljava/util/concurrent/atomic/AtomicBoolean;JLjava/lang/Integer;I)La7/e2;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    move-object v3, v0

    .line 289
    iget-object v0, v10, Lf7/l;->c:Ly6/q;

    .line 290
    .line 291
    invoke-static {v1, v13, v0, v12}, Lev/a;->b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V

    .line 292
    .line 293
    .line 294
    invoke-static {v13, v3, v12, v11}, Lip/t;->c(Landroid/widget/RemoteViews;La7/e2;La7/d1;Ljava/util/List;)V

    .line 295
    .line 296
    .line 297
    iget-object v0, v10, Lf7/l;->c:Ly6/q;

    .line 298
    .line 299
    invoke-interface {v0, v9}, Ly6/q;->b(Lay0/k;)Z

    .line 300
    .line 301
    .line 302
    move-result v0

    .line 303
    if-eqz v0, :cond_26

    .line 304
    .line 305
    invoke-static {v11}, Lip/t;->a(Ljava/util/List;)V

    .line 306
    .line 307
    .line 308
    return-void

    .line 309
    :cond_5
    instance-of v1, v0, Lj7/a;

    .line 310
    .line 311
    const/4 v4, 0x0

    .line 312
    const/4 v6, 0x2

    .line 313
    const-string v7, "GlanceAppWidget"

    .line 314
    .line 315
    if-eqz v1, :cond_15

    .line 316
    .line 317
    check-cast v0, Lj7/a;

    .line 318
    .line 319
    sget-object v1, La7/m1;->g:La7/m1;

    .line 320
    .line 321
    iget-object v8, v0, Lj7/a;->d:Ly6/q;

    .line 322
    .line 323
    invoke-static {v13, v3, v1, v8}, La7/j1;->c(Landroid/widget/RemoteViews;La7/e2;La7/m1;Ly6/q;)La7/d1;

    .line 324
    .line 325
    .line 326
    move-result-object v1

    .line 327
    iget v8, v1, La7/d1;->a:I

    .line 328
    .line 329
    iget-object v9, v0, Lj7/a;->a:Ljava/lang/String;

    .line 330
    .line 331
    iget-object v10, v0, Lj7/a;->b:Lj7/g;

    .line 332
    .line 333
    iget v11, v0, Lj7/a;->c:I

    .line 334
    .line 335
    const v12, 0x7fffffff

    .line 336
    .line 337
    .line 338
    if-eq v11, v12, :cond_6

    .line 339
    .line 340
    const-string v12, "setMaxLines"

    .line 341
    .line 342
    invoke-virtual {v13, v8, v12, v11}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 343
    .line 344
    .line 345
    :cond_6
    if-nez v10, :cond_7

    .line 346
    .line 347
    invoke-virtual {v13, v8, v9}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 348
    .line 349
    .line 350
    goto/16 :goto_9

    .line 351
    .line 352
    :cond_7
    new-instance v11, Landroid/text/SpannableString;

    .line 353
    .line 354
    invoke-direct {v11, v9}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v11}, Landroid/text/SpannableString;->length()I

    .line 358
    .line 359
    .line 360
    move-result v9

    .line 361
    iget-object v12, v10, Lj7/g;->b:Lt4/o;

    .line 362
    .line 363
    if-eqz v12, :cond_9

    .line 364
    .line 365
    iget-wide v14, v12, Lt4/o;->a:J

    .line 366
    .line 367
    const-wide v16, 0xff00000000L

    .line 368
    .line 369
    .line 370
    .line 371
    .line 372
    and-long v16, v14, v16

    .line 373
    .line 374
    const-wide v18, 0x100000000L

    .line 375
    .line 376
    .line 377
    .line 378
    .line 379
    cmp-long v12, v16, v18

    .line 380
    .line 381
    if-nez v12, :cond_8

    .line 382
    .line 383
    invoke-static {v14, v15}, Lt4/o;->c(J)F

    .line 384
    .line 385
    .line 386
    move-result v12

    .line 387
    invoke-virtual {v13, v8, v6, v12}, Landroid/widget/RemoteViews;->setTextViewTextSize(IIF)V

    .line 388
    .line 389
    .line 390
    goto :goto_5

    .line 391
    :cond_8
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 392
    .line 393
    const-string v1, "Only Sp is currently supported for font sizes"

    .line 394
    .line 395
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    throw v0

    .line 399
    :cond_9
    :goto_5
    new-instance v6, Ljava/util/ArrayList;

    .line 400
    .line 401
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 402
    .line 403
    .line 404
    iget-object v12, v10, Lj7/g;->c:Lj7/b;

    .line 405
    .line 406
    if-eqz v12, :cond_c

    .line 407
    .line 408
    iget v12, v12, Lj7/b;->a:I

    .line 409
    .line 410
    const/16 v14, 0x2bc

    .line 411
    .line 412
    if-ne v12, v14, :cond_a

    .line 413
    .line 414
    const v12, 0x7f13016b

    .line 415
    .line 416
    .line 417
    goto :goto_6

    .line 418
    :cond_a
    const/16 v14, 0x1f4

    .line 419
    .line 420
    if-ne v12, v14, :cond_b

    .line 421
    .line 422
    const v12, 0x7f13016d

    .line 423
    .line 424
    .line 425
    goto :goto_6

    .line 426
    :cond_b
    const v12, 0x7f13016e

    .line 427
    .line 428
    .line 429
    :goto_6
    new-instance v14, Landroid/text/style/TextAppearanceSpan;

    .line 430
    .line 431
    invoke-direct {v14, v2, v12}, Landroid/text/style/TextAppearanceSpan;-><init>(Landroid/content/Context;I)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 435
    .line 436
    .line 437
    :cond_c
    iget-object v12, v10, Lj7/g;->d:Lj7/c;

    .line 438
    .line 439
    if-eqz v12, :cond_e

    .line 440
    .line 441
    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 442
    .line 443
    if-lt v12, v5, :cond_d

    .line 444
    .line 445
    sget-object v12, Ld7/c;->a:Ld7/c;

    .line 446
    .line 447
    const/16 v14, 0x31

    .line 448
    .line 449
    invoke-virtual {v12, v13, v8, v14}, Ld7/c;->a(Landroid/widget/RemoteViews;II)V

    .line 450
    .line 451
    .line 452
    goto :goto_7

    .line 453
    :cond_d
    new-instance v12, Landroid/text/style/AlignmentSpan$Standard;

    .line 454
    .line 455
    sget-object v14, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 456
    .line 457
    invoke-direct {v12, v14}, Landroid/text/style/AlignmentSpan$Standard;-><init>(Landroid/text/Layout$Alignment;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    :cond_e
    :goto_7
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 464
    .line 465
    .line 466
    move-result-object v6

    .line 467
    :goto_8
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 468
    .line 469
    .line 470
    move-result v12

    .line 471
    if-eqz v12, :cond_f

    .line 472
    .line 473
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v12

    .line 477
    check-cast v12, Landroid/text/ParcelableSpan;

    .line 478
    .line 479
    const/16 v14, 0x11

    .line 480
    .line 481
    invoke-virtual {v11, v12, v4, v9, v14}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 482
    .line 483
    .line 484
    goto :goto_8

    .line 485
    :cond_f
    invoke-virtual {v13, v8, v11}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 486
    .line 487
    .line 488
    iget-object v4, v10, Lj7/g;->a:Lk7/a;

    .line 489
    .line 490
    instance-of v6, v4, Lk7/h;

    .line 491
    .line 492
    if-eqz v6, :cond_10

    .line 493
    .line 494
    const-wide/16 v4, 0x0

    .line 495
    .line 496
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 497
    .line 498
    .line 499
    move-result v2

    .line 500
    invoke-virtual {v13, v8, v2}, Landroid/widget/RemoteViews;->setTextColor(II)V

    .line 501
    .line 502
    .line 503
    goto :goto_9

    .line 504
    :cond_10
    instance-of v6, v4, Lk7/i;

    .line 505
    .line 506
    const-string v9, "setTextColor"

    .line 507
    .line 508
    if-eqz v6, :cond_12

    .line 509
    .line 510
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 511
    .line 512
    if-lt v6, v5, :cond_11

    .line 513
    .line 514
    check-cast v4, Lk7/i;

    .line 515
    .line 516
    iget v2, v4, Lk7/i;->a:I

    .line 517
    .line 518
    invoke-static {v13, v8, v9, v2}, Lh6/h;->g(Landroid/widget/RemoteViews;ILjava/lang/String;I)V

    .line 519
    .line 520
    .line 521
    goto :goto_9

    .line 522
    :cond_11
    check-cast v4, Lk7/i;

    .line 523
    .line 524
    invoke-virtual {v4, v2}, Lk7/i;->a(Landroid/content/Context;)J

    .line 525
    .line 526
    .line 527
    move-result-wide v4

    .line 528
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 529
    .line 530
    .line 531
    move-result v2

    .line 532
    invoke-virtual {v13, v8, v2}, Landroid/widget/RemoteViews;->setTextColor(II)V

    .line 533
    .line 534
    .line 535
    goto :goto_9

    .line 536
    :cond_12
    instance-of v6, v4, Le7/a;

    .line 537
    .line 538
    if-eqz v6, :cond_14

    .line 539
    .line 540
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 541
    .line 542
    if-lt v6, v5, :cond_13

    .line 543
    .line 544
    check-cast v4, Le7/a;

    .line 545
    .line 546
    iget-wide v5, v4, Le7/a;->a:J

    .line 547
    .line 548
    invoke-static {v5, v6}, Le3/j0;->z(J)I

    .line 549
    .line 550
    .line 551
    move-result v2

    .line 552
    iget-wide v4, v4, Le7/a;->b:J

    .line 553
    .line 554
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 555
    .line 556
    .line 557
    move-result v4

    .line 558
    invoke-static {v13, v8, v9, v2, v4}, Lh6/h;->f(Landroid/widget/RemoteViews;ILjava/lang/String;II)V

    .line 559
    .line 560
    .line 561
    goto :goto_9

    .line 562
    :cond_13
    check-cast v4, Le7/a;

    .line 563
    .line 564
    invoke-virtual {v4, v2}, Le7/a;->a(Landroid/content/Context;)J

    .line 565
    .line 566
    .line 567
    move-result-wide v4

    .line 568
    invoke-static {v4, v5}, Le3/j0;->z(J)I

    .line 569
    .line 570
    .line 571
    move-result v2

    .line 572
    invoke-virtual {v13, v8, v2}, Landroid/widget/RemoteViews;->setTextColor(II)V

    .line 573
    .line 574
    .line 575
    goto :goto_9

    .line 576
    :cond_14
    new-instance v2, Ljava/lang/StringBuilder;

    .line 577
    .line 578
    const-string v5, "Unexpected text color: "

    .line 579
    .line 580
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 581
    .line 582
    .line 583
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 584
    .line 585
    .line 586
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 587
    .line 588
    .line 589
    move-result-object v2

    .line 590
    invoke-static {v7, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 591
    .line 592
    .line 593
    :goto_9
    iget-object v0, v0, Lj7/a;->d:Ly6/q;

    .line 594
    .line 595
    invoke-static {v3, v13, v0, v1}, Lev/a;->b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V

    .line 596
    .line 597
    .line 598
    return-void

    .line 599
    :cond_15
    instance-of v1, v0, Ly6/m;

    .line 600
    .line 601
    const/4 v8, 0x1

    .line 602
    if-eqz v1, :cond_25

    .line 603
    .line 604
    check-cast v0, Ly6/m;

    .line 605
    .line 606
    invoke-static {v0}, Llp/ag;->b(Ly6/m;)Z

    .line 607
    .line 608
    .line 609
    move-result v1

    .line 610
    iget v9, v0, Ly6/m;->d:I

    .line 611
    .line 612
    if-nez v9, :cond_17

    .line 613
    .line 614
    if-eqz v1, :cond_16

    .line 615
    .line 616
    sget-object v1, La7/m1;->z:La7/m1;

    .line 617
    .line 618
    goto :goto_b

    .line 619
    :cond_16
    sget-object v1, La7/m1;->w:La7/m1;

    .line 620
    .line 621
    goto :goto_b

    .line 622
    :cond_17
    sget-object v10, La7/m1;->x:La7/m1;

    .line 623
    .line 624
    if-ne v9, v8, :cond_19

    .line 625
    .line 626
    if-eqz v1, :cond_18

    .line 627
    .line 628
    sget-object v1, La7/m1;->A:La7/m1;

    .line 629
    .line 630
    goto :goto_b

    .line 631
    :cond_18
    :goto_a
    move-object v1, v10

    .line 632
    goto :goto_b

    .line 633
    :cond_19
    if-ne v9, v6, :cond_1b

    .line 634
    .line 635
    if-eqz v1, :cond_1a

    .line 636
    .line 637
    sget-object v1, La7/m1;->B:La7/m1;

    .line 638
    .line 639
    goto :goto_b

    .line 640
    :cond_1a
    sget-object v1, La7/m1;->y:La7/m1;

    .line 641
    .line 642
    goto :goto_b

    .line 643
    :cond_1b
    new-instance v1, Ljava/lang/StringBuilder;

    .line 644
    .line 645
    const-string v6, "Unsupported ContentScale user: "

    .line 646
    .line 647
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 648
    .line 649
    .line 650
    iget v6, v0, Ly6/m;->d:I

    .line 651
    .line 652
    invoke-static {v6}, Lf7/j;->a(I)Ljava/lang/String;

    .line 653
    .line 654
    .line 655
    move-result-object v6

    .line 656
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 657
    .line 658
    .line 659
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 660
    .line 661
    .line 662
    move-result-object v1

    .line 663
    invoke-static {v7, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 664
    .line 665
    .line 666
    goto :goto_a

    .line 667
    :goto_b
    iget-object v6, v0, Ly6/m;->a:Ly6/q;

    .line 668
    .line 669
    invoke-static {v13, v3, v1, v6}, La7/j1;->c(Landroid/widget/RemoteViews;La7/e2;La7/m1;Ly6/q;)La7/d1;

    .line 670
    .line 671
    .line 672
    move-result-object v1

    .line 673
    iget v6, v1, La7/d1;->a:I

    .line 674
    .line 675
    iget-object v7, v0, Ly6/m;->b:Ly6/s;

    .line 676
    .line 677
    instance-of v9, v7, Ly6/a;

    .line 678
    .line 679
    if-eqz v9, :cond_1c

    .line 680
    .line 681
    check-cast v7, Ly6/a;

    .line 682
    .line 683
    iget v7, v7, Ly6/a;->a:I

    .line 684
    .line 685
    invoke-virtual {v13, v6, v7}, Landroid/widget/RemoteViews;->setImageViewResource(II)V

    .line 686
    .line 687
    .line 688
    goto :goto_c

    .line 689
    :cond_1c
    instance-of v9, v7, Ly6/f;

    .line 690
    .line 691
    if-eqz v9, :cond_24

    .line 692
    .line 693
    check-cast v7, Ly6/f;

    .line 694
    .line 695
    iget-object v7, v7, Ly6/f;->a:Landroid/graphics/Bitmap;

    .line 696
    .line 697
    invoke-virtual {v13, v6, v7}, Landroid/widget/RemoteViews;->setImageViewBitmap(ILandroid/graphics/Bitmap;)V

    .line 698
    .line 699
    .line 700
    :goto_c
    iget-object v7, v0, Ly6/m;->c:Ly6/t;

    .line 701
    .line 702
    if-eqz v7, :cond_1f

    .line 703
    .line 704
    instance-of v9, v7, Ly6/t;

    .line 705
    .line 706
    if-eqz v9, :cond_1e

    .line 707
    .line 708
    iget-object v7, v7, Ly6/t;->a:Lk7/a;

    .line 709
    .line 710
    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 711
    .line 712
    if-lt v9, v5, :cond_1d

    .line 713
    .line 714
    sget-object v2, Ld7/a;->a:Ld7/a;

    .line 715
    .line 716
    invoke-virtual {v2, v3, v13, v7, v6}, Ld7/a;->a(La7/e2;Landroid/widget/RemoteViews;Lk7/a;I)V

    .line 717
    .line 718
    .line 719
    goto :goto_d

    .line 720
    :cond_1d
    invoke-interface {v7, v2}, Lk7/a;->a(Landroid/content/Context;)J

    .line 721
    .line 722
    .line 723
    move-result-wide v9

    .line 724
    invoke-static {v9, v10}, Le3/j0;->z(J)I

    .line 725
    .line 726
    .line 727
    move-result v2

    .line 728
    const-string v5, "setColorFilter"

    .line 729
    .line 730
    invoke-virtual {v13, v6, v5, v2}, Landroid/widget/RemoteViews;->setInt(ILjava/lang/String;I)V

    .line 731
    .line 732
    .line 733
    goto :goto_d

    .line 734
    :cond_1e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 735
    .line 736
    const-string v1, "An unsupported ColorFilter was used."

    .line 737
    .line 738
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    throw v0

    .line 742
    :cond_1f
    :goto_d
    iget-object v2, v0, Ly6/m;->a:Ly6/q;

    .line 743
    .line 744
    invoke-static {v3, v13, v2, v1}, Lev/a;->b(La7/e2;Landroid/widget/RemoteViews;Ly6/q;La7/d1;)V

    .line 745
    .line 746
    .line 747
    iget v1, v0, Ly6/m;->d:I

    .line 748
    .line 749
    if-ne v1, v8, :cond_23

    .line 750
    .line 751
    iget-object v1, v0, Ly6/m;->a:Ly6/q;

    .line 752
    .line 753
    sget-object v2, Ld7/b;->g:Ld7/b;

    .line 754
    .line 755
    const/4 v3, 0x0

    .line 756
    invoke-interface {v1, v3, v2}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    move-result-object v1

    .line 760
    check-cast v1, Lf7/t;

    .line 761
    .line 762
    if-eqz v1, :cond_20

    .line 763
    .line 764
    iget-object v1, v1, Lf7/t;->a:Lk7/g;

    .line 765
    .line 766
    goto :goto_e

    .line 767
    :cond_20
    move-object v1, v3

    .line 768
    :goto_e
    sget-object v2, Lk7/f;->a:Lk7/f;

    .line 769
    .line 770
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 771
    .line 772
    .line 773
    move-result v1

    .line 774
    if-nez v1, :cond_22

    .line 775
    .line 776
    iget-object v0, v0, Ly6/m;->a:Ly6/q;

    .line 777
    .line 778
    sget-object v1, Ld7/b;->h:Ld7/b;

    .line 779
    .line 780
    invoke-interface {v0, v3, v1}, Ly6/q;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 781
    .line 782
    .line 783
    move-result-object v0

    .line 784
    check-cast v0, Lf7/n;

    .line 785
    .line 786
    if-eqz v0, :cond_21

    .line 787
    .line 788
    iget-object v3, v0, Lf7/n;->a:Lk7/g;

    .line 789
    .line 790
    :cond_21
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 791
    .line 792
    .line 793
    move-result v0

    .line 794
    if-eqz v0, :cond_23

    .line 795
    .line 796
    :cond_22
    move v4, v8

    .line 797
    :cond_23
    const-string v0, "setAdjustViewBounds"

    .line 798
    .line 799
    invoke-virtual {v13, v6, v0, v4}, Landroid/widget/RemoteViews;->setBoolean(ILjava/lang/String;Z)V

    .line 800
    .line 801
    .line 802
    return-void

    .line 803
    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 804
    .line 805
    const-string v1, "An unsupported ImageProvider type was used."

    .line 806
    .line 807
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 808
    .line 809
    .line 810
    throw v0

    .line 811
    :cond_25
    instance-of v1, v0, La7/d0;

    .line 812
    .line 813
    if-eqz v1, :cond_28

    .line 814
    .line 815
    check-cast v0, La7/d0;

    .line 816
    .line 817
    iget-object v0, v0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 818
    .line 819
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 820
    .line 821
    .line 822
    move-result v1

    .line 823
    if-gt v1, v8, :cond_27

    .line 824
    .line 825
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 826
    .line 827
    .line 828
    move-result-object v0

    .line 829
    check-cast v0, Ly6/l;

    .line 830
    .line 831
    if-eqz v0, :cond_26

    .line 832
    .line 833
    invoke-static {v13, v3, v0}, Lip/t;->e(Landroid/widget/RemoteViews;La7/e2;Ly6/l;)V

    .line 834
    .line 835
    .line 836
    :cond_26
    return-void

    .line 837
    :cond_27
    new-instance v1, Ljava/lang/StringBuilder;

    .line 838
    .line 839
    const-string v2, "Size boxes can only have at most one child "

    .line 840
    .line 841
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 842
    .line 843
    .line 844
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 845
    .line 846
    .line 847
    move-result v0

    .line 848
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 849
    .line 850
    .line 851
    const-string v0, ". The normalization of the composition tree failed."

    .line 852
    .line 853
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 854
    .line 855
    .line 856
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 857
    .line 858
    .line 859
    move-result-object v0

    .line 860
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 861
    .line 862
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 863
    .line 864
    .line 865
    move-result-object v0

    .line 866
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 867
    .line 868
    .line 869
    throw v1

    .line 870
    :cond_28
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 871
    .line 872
    new-instance v2, Ljava/lang/StringBuilder;

    .line 873
    .line 874
    const-string v3, "Unknown element type "

    .line 875
    .line 876
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 877
    .line 878
    .line 879
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 880
    .line 881
    .line 882
    move-result-object v0

    .line 883
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 884
    .line 885
    .line 886
    move-result-object v0

    .line 887
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 888
    .line 889
    .line 890
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 891
    .line 892
    .line 893
    move-result-object v0

    .line 894
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 895
    .line 896
    .line 897
    throw v1
.end method

.method public static final f(Landroid/content/Context;ILa7/q1;La7/f1;ILandroid/content/ComponentName;)Landroid/widget/RemoteViews;
    .locals 20

    .line 1
    move/from16 v0, p4

    .line 2
    .line 3
    new-instance v1, La7/e2;

    .line 4
    .line 5
    invoke-virtual/range {p0 .. p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-virtual {v2}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {v2}, Landroid/content/res/Configuration;->getLayoutDirection()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x1

    .line 19
    if-ne v2, v4, :cond_0

    .line 20
    .line 21
    move v2, v4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v2, v3

    .line 24
    :goto_0
    new-instance v8, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 25
    .line 26
    invoke-direct {v8, v4}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 27
    .line 28
    .line 29
    new-instance v9, La7/d1;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v6, 0x7

    .line 33
    invoke-direct {v9, v3, v3, v5, v6}, La7/d1;-><init>(IILjava/util/Map;I)V

    .line 34
    .line 35
    .line 36
    new-instance v10, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 37
    .line 38
    invoke-direct {v10, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 39
    .line 40
    .line 41
    const/4 v13, -0x1

    .line 42
    const/4 v14, 0x0

    .line 43
    const/4 v6, -0x1

    .line 44
    const/4 v7, 0x0

    .line 45
    const-wide v11, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    const/4 v15, 0x0

    .line 51
    move/from16 v3, p1

    .line 52
    .line 53
    move-object/from16 v5, p3

    .line 54
    .line 55
    move-object/from16 v16, p5

    .line 56
    .line 57
    move v4, v2

    .line 58
    move-object/from16 v2, p0

    .line 59
    .line 60
    invoke-direct/range {v1 .. v16}, La7/e2;-><init>(Landroid/content/Context;IZLa7/f1;IZLjava/util/concurrent/atomic/AtomicInteger;La7/d1;Ljava/util/concurrent/atomic/AtomicBoolean;JIZLjava/lang/Integer;Landroid/content/ComponentName;)V

    .line 61
    .line 62
    .line 63
    move-object v2, v1

    .line 64
    move-object/from16 v1, p2

    .line 65
    .line 66
    iget-object v1, v1, Ly6/n;->b:Ljava/util/ArrayList;

    .line 67
    .line 68
    if-eqz v1, :cond_2

    .line 69
    .line 70
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-eqz v3, :cond_2

    .line 75
    .line 76
    :cond_1
    const/4 v4, 0x0

    .line 77
    const/4 v6, 0x1

    .line 78
    goto :goto_1

    .line 79
    :cond_2
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    :cond_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    if-eqz v4, :cond_1

    .line 88
    .line 89
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, Ly6/l;

    .line 94
    .line 95
    instance-of v4, v4, La7/d0;

    .line 96
    .line 97
    if-nez v4, :cond_3

    .line 98
    .line 99
    invoke-static {v1}, Lmx0/q;->i0(Ljava/util/List;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Ly6/l;

    .line 104
    .line 105
    invoke-interface {v1}, Ly6/l;->b()Ly6/q;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-static {v2, v3, v0}, La7/j1;->a(La7/e2;Ly6/q;I)La7/p1;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    iget-object v3, v0, La7/p1;->a:Landroid/widget/RemoteViews;

    .line 114
    .line 115
    iget-object v0, v0, La7/p1;->b:La7/d1;

    .line 116
    .line 117
    const/4 v4, 0x0

    .line 118
    invoke-virtual {v2, v0, v4}, La7/e2;->b(La7/d1;I)La7/e2;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    new-instance v9, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 123
    .line 124
    invoke-direct {v9, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 125
    .line 126
    .line 127
    new-instance v7, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 128
    .line 129
    const/4 v6, 0x1

    .line 130
    invoke-direct {v7, v6}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 131
    .line 132
    .line 133
    const/4 v12, 0x0

    .line 134
    const/16 v13, 0x7ebf

    .line 135
    .line 136
    const/4 v6, 0x0

    .line 137
    const/4 v8, 0x0

    .line 138
    const-wide/16 v10, 0x0

    .line 139
    .line 140
    invoke-static/range {v5 .. v13}, La7/e2;->a(La7/e2;ILjava/util/concurrent/atomic/AtomicInteger;La7/d1;Ljava/util/concurrent/atomic/AtomicBoolean;JLjava/lang/Integer;I)La7/e2;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-static {v3, v0, v1}, Lip/t;->e(Landroid/widget/RemoteViews;La7/e2;Ly6/l;)V

    .line 145
    .line 146
    .line 147
    return-object v3

    .line 148
    :goto_1
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    const-string v5, "null cannot be cast to non-null type androidx.glance.appwidget.EmittableSizeBox"

    .line 153
    .line 154
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    check-cast v3, La7/d0;

    .line 158
    .line 159
    iget-object v3, v3, La7/d0;->d:La7/a2;

    .line 160
    .line 161
    new-instance v7, Ljava/util/ArrayList;

    .line 162
    .line 163
    const/16 v8, 0xa

    .line 164
    .line 165
    invoke-static {v1, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 166
    .line 167
    .line 168
    move-result v9

    .line 169
    invoke-direct {v7, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 170
    .line 171
    .line 172
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    if-eqz v9, :cond_4

    .line 181
    .line 182
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v9

    .line 186
    check-cast v9, Ly6/l;

    .line 187
    .line 188
    invoke-static {v9, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    move-object v10, v9

    .line 192
    check-cast v10, La7/d0;

    .line 193
    .line 194
    iget-wide v10, v10, La7/d0;->c:J

    .line 195
    .line 196
    invoke-interface {v9}, Ly6/l;->b()Ly6/q;

    .line 197
    .line 198
    .line 199
    move-result-object v12

    .line 200
    invoke-static {v2, v12, v0}, La7/j1;->a(La7/e2;Ly6/q;I)La7/p1;

    .line 201
    .line 202
    .line 203
    move-result-object v12

    .line 204
    iget-object v13, v12, La7/p1;->a:Landroid/widget/RemoteViews;

    .line 205
    .line 206
    iget-object v12, v12, La7/p1;->b:La7/d1;

    .line 207
    .line 208
    invoke-virtual {v2, v12, v4}, La7/e2;->b(La7/d1;I)La7/e2;

    .line 209
    .line 210
    .line 211
    move-result-object v12

    .line 212
    new-instance v15, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 213
    .line 214
    invoke-direct {v15, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 215
    .line 216
    .line 217
    move-object v14, v13

    .line 218
    new-instance v13, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 219
    .line 220
    invoke-direct {v13, v6}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 221
    .line 222
    .line 223
    const/16 v18, 0x0

    .line 224
    .line 225
    const/16 v19, 0x7cbf

    .line 226
    .line 227
    move-wide/from16 v16, v10

    .line 228
    .line 229
    move-object v11, v12

    .line 230
    const/4 v12, 0x0

    .line 231
    move-object v10, v14

    .line 232
    const/4 v14, 0x0

    .line 233
    invoke-static/range {v11 .. v19}, La7/e2;->a(La7/e2;ILjava/util/concurrent/atomic/AtomicInteger;La7/d1;Ljava/util/concurrent/atomic/AtomicBoolean;JLjava/lang/Integer;I)La7/e2;

    .line 234
    .line 235
    .line 236
    move-result-object v11

    .line 237
    invoke-static {v10, v11, v9}, Lip/t;->e(Landroid/widget/RemoteViews;La7/e2;Ly6/l;)V

    .line 238
    .line 239
    .line 240
    new-instance v9, Landroid/util/SizeF;

    .line 241
    .line 242
    invoke-static/range {v16 .. v17}, Lt4/h;->c(J)F

    .line 243
    .line 244
    .line 245
    move-result v11

    .line 246
    invoke-static/range {v16 .. v17}, Lt4/h;->b(J)F

    .line 247
    .line 248
    .line 249
    move-result v12

    .line 250
    invoke-direct {v9, v11, v12}, Landroid/util/SizeF;-><init>(FF)V

    .line 251
    .line 252
    .line 253
    new-instance v11, Llx0/l;

    .line 254
    .line 255
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v7, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    goto :goto_2

    .line 262
    :cond_4
    instance-of v0, v3, La7/z1;

    .line 263
    .line 264
    if-eqz v0, :cond_5

    .line 265
    .line 266
    invoke-static {v7}, Lmx0/q;->i0(Ljava/util/List;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    check-cast v0, Llx0/l;

    .line 271
    .line 272
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v0, Landroid/widget/RemoteViews;

    .line 275
    .line 276
    return-object v0

    .line 277
    :cond_5
    instance-of v0, v3, La7/y1;

    .line 278
    .line 279
    if-eqz v0, :cond_6

    .line 280
    .line 281
    move v0, v6

    .line 282
    goto :goto_3

    .line 283
    :cond_6
    sget-object v0, La7/x1;->a:La7/x1;

    .line 284
    .line 285
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    :goto_3
    if-eqz v0, :cond_e

    .line 290
    .line 291
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 292
    .line 293
    const/16 v1, 0x1f

    .line 294
    .line 295
    if-lt v0, v1, :cond_7

    .line 296
    .line 297
    sget-object v0, La7/b;->a:La7/b;

    .line 298
    .line 299
    invoke-static {v7}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    invoke-virtual {v0, v1}, La7/b;->a(Ljava/util/Map;)Landroid/widget/RemoteViews;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    return-object v0

    .line 308
    :cond_7
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 309
    .line 310
    .line 311
    move-result v0

    .line 312
    const/4 v1, 0x2

    .line 313
    if-eq v0, v6, :cond_9

    .line 314
    .line 315
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    if-ne v0, v1, :cond_8

    .line 320
    .line 321
    goto :goto_4

    .line 322
    :cond_8
    move v3, v4

    .line 323
    goto :goto_5

    .line 324
    :cond_9
    :goto_4
    move v3, v6

    .line 325
    :goto_5
    if-eqz v3, :cond_d

    .line 326
    .line 327
    new-instance v0, Ljava/util/ArrayList;

    .line 328
    .line 329
    invoke-static {v7, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v2

    .line 340
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 341
    .line 342
    .line 343
    move-result v3

    .line 344
    if-eqz v3, :cond_a

    .line 345
    .line 346
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    check-cast v3, Llx0/l;

    .line 351
    .line 352
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v3, Landroid/widget/RemoteViews;

    .line 355
    .line 356
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    goto :goto_6

    .line 360
    :cond_a
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 361
    .line 362
    .line 363
    move-result v2

    .line 364
    if-eq v2, v6, :cond_c

    .line 365
    .line 366
    if-ne v2, v1, :cond_b

    .line 367
    .line 368
    new-instance v1, Landroid/widget/RemoteViews;

    .line 369
    .line 370
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v2

    .line 374
    check-cast v2, Landroid/widget/RemoteViews;

    .line 375
    .line 376
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    check-cast v0, Landroid/widget/RemoteViews;

    .line 381
    .line 382
    invoke-direct {v1, v2, v0}, Landroid/widget/RemoteViews;-><init>(Landroid/widget/RemoteViews;Landroid/widget/RemoteViews;)V

    .line 383
    .line 384
    .line 385
    return-object v1

    .line 386
    :cond_b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 387
    .line 388
    const-string v1, "There must be between 1 and 2 views."

    .line 389
    .line 390
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    throw v0

    .line 394
    :cond_c
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    check-cast v0, Landroid/widget/RemoteViews;

    .line 399
    .line 400
    return-object v0

    .line 401
    :cond_d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 402
    .line 403
    const-string v1, "unsupported views size"

    .line 404
    .line 405
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    throw v0

    .line 409
    :cond_e
    new-instance v0, La8/r0;

    .line 410
    .line 411
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 412
    .line 413
    .line 414
    throw v0
.end method

.method public static final g(Lm70/g0;Lss0/b;Lij0/a;)Lm70/g0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "capabilities"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v3, "stringResource"

    .line 18
    .line 19
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0, v2}, Lip/t;->i(Lm70/g0;Lij0/a;)Lm70/g0;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    sget-object v0, Lss0/e;->K1:Lss0/e;

    .line 27
    .line 28
    invoke-static {v1, v0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-static {v1, v0}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 33
    .line 34
    .line 35
    move-result-object v17

    .line 36
    const/16 v18, 0xffe

    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    const/4 v7, 0x0

    .line 40
    const/4 v8, 0x0

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    const/4 v11, 0x0

    .line 44
    const/4 v12, 0x0

    .line 45
    const/4 v13, 0x0

    .line 46
    const/4 v14, 0x0

    .line 47
    const/4 v15, 0x0

    .line 48
    const/16 v16, 0x0

    .line 49
    .line 50
    invoke-static/range {v4 .. v18}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    return-object v0
.end method

.method public static final h(Lm70/g0;Lij0/a;)Lm70/g0;
    .locals 16

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "stringResource"

    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static/range {p0 .. p1}, Lip/t;->i(Lm70/g0;Lij0/a;)Lm70/g0;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v14, 0x0

    .line 20
    const/16 v15, 0x1eff

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/4 v5, 0x0

    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x0

    .line 28
    const/4 v8, 0x0

    .line 29
    const/4 v9, 0x0

    .line 30
    const/4 v10, 0x0

    .line 31
    const/4 v11, 0x0

    .line 32
    const/4 v12, 0x0

    .line 33
    const/4 v13, 0x0

    .line 34
    invoke-static/range {v1 .. v15}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    return-object v0
.end method

.method public static final i(Lm70/g0;Lij0/a;)Lm70/g0;
    .locals 15

    .line 1
    iget-object v1, p0, Lm70/g0;->h:Lm70/f0;

    .line 2
    .line 3
    iget-object v2, v1, Lm70/f0;->a:Ljava/util/List;

    .line 4
    .line 5
    check-cast v2, Ljava/util/Collection;

    .line 6
    .line 7
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v1, 0x0

    .line 15
    :goto_0
    const/4 v2, 0x0

    .line 16
    const/16 v3, 0xa

    .line 17
    .line 18
    if-nez v1, :cond_3

    .line 19
    .line 20
    sget-object v1, Ll70/a0;->h:Ll70/a0;

    .line 21
    .line 22
    invoke-static {v1}, Llp/dd;->b(Ll70/a0;)Ljava/util/List;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Ljava/lang/Iterable;

    .line 27
    .line 28
    new-instance v4, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    check-cast v5, Ll70/q;

    .line 52
    .line 53
    new-instance v6, Ll70/s;

    .line 54
    .line 55
    sget-object v7, Ll70/q;->k:Ll70/q;

    .line 56
    .line 57
    if-ne v5, v7, :cond_1

    .line 58
    .line 59
    const/4 v7, 0x1

    .line 60
    goto :goto_2

    .line 61
    :cond_1
    move v7, v2

    .line 62
    :goto_2
    invoke-direct {v6, v5, v7}, Ll70/s;-><init>(Ll70/q;Z)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    new-instance v1, Lm70/f0;

    .line 70
    .line 71
    invoke-direct {v1, v4}, Lm70/f0;-><init>(Ljava/util/List;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    move-object v8, v1

    .line 75
    iget-object v1, v8, Lm70/f0;->a:Ljava/util/List;

    .line 76
    .line 77
    check-cast v1, Ljava/lang/Iterable;

    .line 78
    .line 79
    new-instance v4, La5/f;

    .line 80
    .line 81
    const/16 v5, 0x17

    .line 82
    .line 83
    invoke-direct {v4, v5}, La5/f;-><init>(I)V

    .line 84
    .line 85
    .line 86
    invoke-static {v1, v4}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Ljava/lang/Iterable;

    .line 91
    .line 92
    new-instance v4, Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    if-eqz v5, :cond_4

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    check-cast v5, Ll70/s;

    .line 116
    .line 117
    iget-object v5, v5, Ll70/s;->a:Ll70/q;

    .line 118
    .line 119
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_4
    new-instance v11, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-static {v4, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    invoke-direct {v11, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-eqz v3, :cond_5

    .line 141
    .line 142
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    check-cast v3, Ll70/q;

    .line 147
    .line 148
    new-instance v4, Ll70/x;

    .line 149
    .line 150
    invoke-static {v3}, Lj0/g;->b(Ll70/q;)I

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    new-array v6, v2, [Ljava/lang/Object;

    .line 155
    .line 156
    move-object/from16 v7, p1

    .line 157
    .line 158
    check-cast v7, Ljj0/f;

    .line 159
    .line 160
    const v9, 0x7f1201aa

    .line 161
    .line 162
    .line 163
    invoke-virtual {v7, v9, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v6

    .line 167
    invoke-direct {v4, v3, v5, v6}, Ll70/x;-><init>(Ll70/q;ILjava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_5
    sget-object v3, Lqr0/s;->d:Lqr0/s;

    .line 175
    .line 176
    new-array v1, v2, [Ljava/lang/Object;

    .line 177
    .line 178
    move-object/from16 v2, p1

    .line 179
    .line 180
    check-cast v2, Ljj0/f;

    .line 181
    .line 182
    const v4, 0x7f120257

    .line 183
    .line 184
    .line 185
    invoke-virtual {v2, v4, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v10

    .line 189
    const/4 v13, 0x0

    .line 190
    const/16 v14, 0x117b

    .line 191
    .line 192
    const/4 v1, 0x0

    .line 193
    const/4 v2, 0x0

    .line 194
    const/4 v4, 0x0

    .line 195
    const/4 v5, 0x0

    .line 196
    const/4 v6, 0x0

    .line 197
    const/4 v7, 0x0

    .line 198
    const/4 v9, 0x0

    .line 199
    const/4 v12, 0x0

    .line 200
    move-object v0, p0

    .line 201
    invoke-static/range {v0 .. v14}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    return-object v0
.end method

.method public static final j(Lm70/g0;Lij0/a;)Lm70/g0;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "stringResource"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Ll70/y;

    .line 11
    .line 12
    iget-object v3, v0, Lm70/g0;->s:Ll70/v;

    .line 13
    .line 14
    iget-object v4, v3, Ll70/v;->a:Ll70/w;

    .line 15
    .line 16
    iget v5, v0, Lm70/g0;->e:I

    .line 17
    .line 18
    invoke-direct {v2, v4, v5}, Ll70/y;-><init>(Ll70/w;I)V

    .line 19
    .line 20
    .line 21
    iget-object v4, v0, Lm70/g0;->b:Ljava/util/Map;

    .line 22
    .line 23
    invoke-interface {v4, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lne0/s;

    .line 28
    .line 29
    instance-of v4, v2, Lne0/e;

    .line 30
    .line 31
    if-eqz v4, :cond_e

    .line 32
    .line 33
    check-cast v2, Lne0/e;

    .line 34
    .line 35
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v2, Ll70/p;

    .line 38
    .line 39
    iget-object v6, v0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    const/4 v5, 0x1

    .line 43
    if-eqz v6, :cond_0

    .line 44
    .line 45
    move v7, v5

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move v7, v4

    .line 48
    :goto_0
    iget-object v8, v0, Lm70/g0;->c:Lqr0/s;

    .line 49
    .line 50
    iget-object v3, v3, Ll70/v;->a:Ll70/w;

    .line 51
    .line 52
    const/4 v9, 0x2

    .line 53
    if-eqz v7, :cond_3

    .line 54
    .line 55
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_2

    .line 60
    .line 61
    if-eq v3, v5, :cond_2

    .line 62
    .line 63
    if-ne v3, v9, :cond_1

    .line 64
    .line 65
    const v3, 0x7f120254

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    new-instance v0, La8/r0;

    .line 70
    .line 71
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw v0

    .line 75
    :cond_2
    const v3, 0x7f12024d

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_3
    const v3, 0x7f120257

    .line 80
    .line 81
    .line 82
    :goto_1
    new-array v7, v4, [Ljava/lang/Object;

    .line 83
    .line 84
    move-object v10, v1

    .line 85
    check-cast v10, Ljj0/f;

    .line 86
    .line 87
    invoke-virtual {v10, v3, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    iget-object v7, v0, Lm70/g0;->h:Lm70/f0;

    .line 92
    .line 93
    iget-object v7, v7, Lm70/f0;->a:Ljava/util/List;

    .line 94
    .line 95
    check-cast v7, Ljava/lang/Iterable;

    .line 96
    .line 97
    new-instance v11, La5/f;

    .line 98
    .line 99
    const/16 v12, 0x17

    .line 100
    .line 101
    invoke-direct {v11, v12}, La5/f;-><init>(I)V

    .line 102
    .line 103
    .line 104
    invoke-static {v7, v11}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    check-cast v7, Ljava/lang/Iterable;

    .line 109
    .line 110
    new-instance v11, Ljava/util/ArrayList;

    .line 111
    .line 112
    const/16 v12, 0xa

    .line 113
    .line 114
    invoke-static {v7, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 115
    .line 116
    .line 117
    move-result v12

    .line 118
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 126
    .line 127
    .line 128
    move-result v12

    .line 129
    if-eqz v12, :cond_d

    .line 130
    .line 131
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v12

    .line 135
    check-cast v12, Ll70/s;

    .line 136
    .line 137
    iget-object v12, v12, Ll70/s;->a:Ll70/q;

    .line 138
    .line 139
    const/4 v13, 0x6

    .line 140
    const-string v14, "<this>"

    .line 141
    .line 142
    const-string v15, "unitsType"

    .line 143
    .line 144
    const/16 v16, 0x0

    .line 145
    .line 146
    if-eqz v6, :cond_5

    .line 147
    .line 148
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 149
    .line 150
    .line 151
    move-result v9

    .line 152
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string v14, "dataType"

    .line 156
    .line 157
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    iget-object v14, v2, Ll70/p;->k:Ljava/lang/Object;

    .line 164
    .line 165
    invoke-static {v9, v14}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v9

    .line 169
    check-cast v9, Ll70/r;

    .line 170
    .line 171
    if-eqz v9, :cond_4

    .line 172
    .line 173
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 174
    .line 175
    .line 176
    move-result v14

    .line 177
    packed-switch v14, :pswitch_data_0

    .line 178
    .line 179
    .line 180
    new-instance v0, La8/r0;

    .line 181
    .line 182
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 183
    .line 184
    .line 185
    throw v0

    .line 186
    :pswitch_0
    iget-wide v13, v9, Ll70/r;->h:D

    .line 187
    .line 188
    invoke-static {v13, v14, v8}, Lkp/o6;->a(DLqr0/s;)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v16

    .line 192
    goto :goto_3

    .line 193
    :pswitch_1
    iget v9, v9, Ll70/r;->d:I

    .line 194
    .line 195
    sget-object v14, Lmy0/e;->i:Lmy0/e;

    .line 196
    .line 197
    invoke-static {v9, v14}, Lmy0/h;->s(ILmy0/e;)J

    .line 198
    .line 199
    .line 200
    move-result-wide v14

    .line 201
    invoke-static {v14, v15, v1, v4, v13}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v16

    .line 205
    goto :goto_3

    .line 206
    :pswitch_2
    iget-wide v13, v9, Ll70/r;->c:D

    .line 207
    .line 208
    sget-object v9, Lqr0/e;->e:Lqr0/e;

    .line 209
    .line 210
    invoke-static {v13, v14, v8, v9}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v16

    .line 214
    goto :goto_3

    .line 215
    :pswitch_3
    iget-wide v13, v9, Ll70/r;->f:D

    .line 216
    .line 217
    invoke-static {v13, v14, v8}, Lkp/g6;->b(DLqr0/s;)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v16

    .line 221
    goto :goto_3

    .line 222
    :pswitch_4
    iget-wide v13, v9, Ll70/r;->e:D

    .line 223
    .line 224
    invoke-static {v13, v14, v8}, Lkp/i6;->b(DLqr0/s;)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v16

    .line 228
    goto :goto_3

    .line 229
    :pswitch_5
    iget-wide v13, v9, Ll70/r;->g:D

    .line 230
    .line 231
    invoke-static {v13, v14}, Lkp/j6;->b(D)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v16

    .line 235
    goto :goto_3

    .line 236
    :pswitch_6
    iget-object v9, v9, Ll70/r;->i:Ll70/u;

    .line 237
    .line 238
    if-eqz v9, :cond_4

    .line 239
    .line 240
    invoke-static {v9}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v16

    .line 244
    :cond_4
    :goto_3
    const/4 v15, 0x2

    .line 245
    goto/16 :goto_4

    .line 246
    .line 247
    :cond_5
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 248
    .line 249
    .line 250
    move-result v9

    .line 251
    const/16 v5, 0x8

    .line 252
    .line 253
    const/4 v4, 0x7

    .line 254
    if-eq v9, v4, :cond_6

    .line 255
    .line 256
    if-eq v9, v5, :cond_6

    .line 257
    .line 258
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 265
    .line 266
    .line 267
    move-result v4

    .line 268
    packed-switch v4, :pswitch_data_1

    .line 269
    .line 270
    .line 271
    new-instance v0, La8/r0;

    .line 272
    .line 273
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :pswitch_7
    iget-wide v4, v2, Ll70/p;->i:D

    .line 278
    .line 279
    invoke-static {v4, v5, v8}, Lkp/o6;->a(DLqr0/s;)Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object v16

    .line 283
    goto :goto_3

    .line 284
    :pswitch_8
    iget v4, v2, Ll70/p;->e:I

    .line 285
    .line 286
    sget-object v5, Lmy0/e;->i:Lmy0/e;

    .line 287
    .line 288
    invoke-static {v4, v5}, Lmy0/h;->s(ILmy0/e;)J

    .line 289
    .line 290
    .line 291
    move-result-wide v4

    .line 292
    const/4 v9, 0x0

    .line 293
    invoke-static {v4, v5, v1, v9, v13}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v16

    .line 297
    goto :goto_3

    .line 298
    :pswitch_9
    iget-wide v4, v2, Ll70/p;->d:D

    .line 299
    .line 300
    sget-object v9, Lqr0/e;->e:Lqr0/e;

    .line 301
    .line 302
    invoke-static {v4, v5, v8, v9}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v16

    .line 306
    goto :goto_3

    .line 307
    :pswitch_a
    iget-object v4, v2, Ll70/p;->g:Lqr0/g;

    .line 308
    .line 309
    iget-wide v4, v4, Lqr0/g;->a:D

    .line 310
    .line 311
    invoke-static {v4, v5, v8}, Lkp/g6;->b(DLqr0/s;)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v16

    .line 315
    goto :goto_3

    .line 316
    :pswitch_b
    iget-object v4, v2, Ll70/p;->f:Lqr0/i;

    .line 317
    .line 318
    iget-wide v4, v4, Lqr0/i;->a:D

    .line 319
    .line 320
    invoke-static {v4, v5, v8}, Lkp/i6;->b(DLqr0/s;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v16

    .line 324
    goto :goto_3

    .line 325
    :pswitch_c
    iget-object v4, v2, Ll70/p;->h:Lqr0/j;

    .line 326
    .line 327
    iget-wide v4, v4, Lqr0/j;->a:D

    .line 328
    .line 329
    invoke-static {v4, v5}, Lkp/j6;->b(D)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v16

    .line 333
    goto :goto_3

    .line 334
    :pswitch_d
    iget-object v4, v2, Ll70/p;->a:Ll70/u;

    .line 335
    .line 336
    if-eqz v4, :cond_4

    .line 337
    .line 338
    invoke-static {v4}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v16

    .line 342
    goto :goto_3

    .line 343
    :cond_6
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 350
    .line 351
    .line 352
    move-result v9

    .line 353
    if-eqz v9, :cond_9

    .line 354
    .line 355
    const/4 v14, 0x1

    .line 356
    if-eq v9, v14, :cond_9

    .line 357
    .line 358
    const/4 v15, 0x2

    .line 359
    if-eq v9, v15, :cond_a

    .line 360
    .line 361
    const/4 v14, 0x3

    .line 362
    if-eq v9, v14, :cond_a

    .line 363
    .line 364
    if-eq v9, v4, :cond_8

    .line 365
    .line 366
    if-eq v9, v5, :cond_7

    .line 367
    .line 368
    goto :goto_4

    .line 369
    :cond_7
    iget v4, v2, Ll70/p;->c:I

    .line 370
    .line 371
    sget-object v5, Lmy0/e;->i:Lmy0/e;

    .line 372
    .line 373
    invoke-static {v4, v5}, Lmy0/h;->s(ILmy0/e;)J

    .line 374
    .line 375
    .line 376
    move-result-wide v4

    .line 377
    const/4 v9, 0x0

    .line 378
    invoke-static {v4, v5, v1, v9, v13}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v16

    .line 382
    goto :goto_4

    .line 383
    :cond_8
    iget-wide v4, v2, Ll70/p;->b:D

    .line 384
    .line 385
    sget-object v9, Lqr0/e;->e:Lqr0/e;

    .line 386
    .line 387
    invoke-static {v4, v5, v8, v9}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v16

    .line 391
    goto :goto_4

    .line 392
    :cond_9
    const/4 v15, 0x2

    .line 393
    :cond_a
    iget-object v4, v2, Ll70/p;->a:Ll70/u;

    .line 394
    .line 395
    if-eqz v4, :cond_b

    .line 396
    .line 397
    invoke-static {v4}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v16

    .line 401
    :cond_b
    :goto_4
    new-instance v4, Ll70/x;

    .line 402
    .line 403
    invoke-static {v12}, Lj0/g;->b(Ll70/q;)I

    .line 404
    .line 405
    .line 406
    move-result v5

    .line 407
    if-nez v16, :cond_c

    .line 408
    .line 409
    const v9, 0x7f1201aa

    .line 410
    .line 411
    .line 412
    const/4 v13, 0x0

    .line 413
    new-array v14, v13, [Ljava/lang/Object;

    .line 414
    .line 415
    invoke-virtual {v10, v9, v14}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v16

    .line 419
    :goto_5
    move-object/from16 v9, v16

    .line 420
    .line 421
    goto :goto_6

    .line 422
    :cond_c
    const/4 v13, 0x0

    .line 423
    goto :goto_5

    .line 424
    :goto_6
    invoke-direct {v4, v12, v5, v9}, Ll70/x;-><init>(Ll70/q;ILjava/lang/String;)V

    .line 425
    .line 426
    .line 427
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 428
    .line 429
    .line 430
    move v4, v13

    .line 431
    move v9, v15

    .line 432
    const/4 v5, 0x1

    .line 433
    goto/16 :goto_2

    .line 434
    .line 435
    :cond_d
    invoke-static {v11}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 436
    .line 437
    .line 438
    move-result-object v11

    .line 439
    move-object v10, v3

    .line 440
    iget-object v3, v0, Lm70/g0;->c:Lqr0/s;

    .line 441
    .line 442
    const/4 v13, 0x0

    .line 443
    const/16 v14, 0x10db

    .line 444
    .line 445
    const/4 v1, 0x0

    .line 446
    const/4 v2, 0x0

    .line 447
    const/4 v4, 0x0

    .line 448
    const/4 v5, 0x0

    .line 449
    const/4 v7, 0x0

    .line 450
    const/4 v8, 0x0

    .line 451
    const/4 v9, 0x0

    .line 452
    const/4 v12, 0x0

    .line 453
    invoke-static/range {v0 .. v14}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    return-object v0

    .line 458
    :cond_e
    sget-object v0, Lne0/d;->a:Lne0/d;

    .line 459
    .line 460
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    if-eqz v0, :cond_f

    .line 465
    .line 466
    const/4 v13, 0x0

    .line 467
    const/16 v14, 0x17ff

    .line 468
    .line 469
    const/4 v1, 0x0

    .line 470
    const/4 v2, 0x0

    .line 471
    const/4 v3, 0x0

    .line 472
    const/4 v4, 0x0

    .line 473
    const/4 v5, 0x0

    .line 474
    const/4 v6, 0x0

    .line 475
    const/4 v7, 0x0

    .line 476
    const/4 v8, 0x0

    .line 477
    const/4 v9, 0x0

    .line 478
    const/4 v10, 0x0

    .line 479
    const/4 v11, 0x0

    .line 480
    const/4 v12, 0x1

    .line 481
    move-object/from16 v0, p0

    .line 482
    .line 483
    invoke-static/range {v0 .. v14}, Lm70/g0;->a(Lm70/g0;Ler0/g;Ljava/util/Map;Lqr0/s;Ljava/util/List;ILjava/lang/Integer;ZLm70/f0;ZLjava/lang/String;Ljava/util/ArrayList;ZLlf0/i;I)Lm70/g0;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    return-object v0

    .line 488
    :cond_f
    instance-of v0, v2, Lne0/c;

    .line 489
    .line 490
    if-nez v0, :cond_11

    .line 491
    .line 492
    if-nez v2, :cond_10

    .line 493
    .line 494
    goto :goto_7

    .line 495
    :cond_10
    new-instance v0, La8/r0;

    .line 496
    .line 497
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 498
    .line 499
    .line 500
    throw v0

    .line 501
    :cond_11
    :goto_7
    invoke-static/range {p0 .. p1}, Lip/t;->i(Lm70/g0;Lij0/a;)Lm70/g0;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    return-object v0

    .line 506
    nop

    .line 507
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 508
    .line 509
    .line 510
    .line 511
    .line 512
    .line 513
    .line 514
    .line 515
    .line 516
    .line 517
    .line 518
    .line 519
    .line 520
    .line 521
    .line 522
    .line 523
    .line 524
    .line 525
    .line 526
    .line 527
    .line 528
    .line 529
    .line 530
    .line 531
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
    .end packed-switch
.end method
