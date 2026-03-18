.class public abstract Ljp/ue;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lua/a;)V
    .locals 4

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-string v1, "SELECT name FROM sqlite_master WHERE type = \'trigger\'"

    .line 11
    .line 12
    invoke-interface {p0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :goto_0
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v0, v2}, Lnx0/c;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_2

    .line 33
    :cond_0
    const/4 v2, 0x0

    .line 34
    invoke-static {v1, v2}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {v0, v3}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    :cond_1
    :goto_1
    move-object v1, v0

    .line 46
    check-cast v1, Lnx0/a;

    .line 47
    .line 48
    invoke-virtual {v1}, Lnx0/a;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    invoke-virtual {v1}, Lnx0/a;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v1, Ljava/lang/String;

    .line 59
    .line 60
    const-string v2, "room_fts_content_sync_"

    .line 61
    .line 62
    invoke-static {v1, v2, v3}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_1

    .line 67
    .line 68
    const-string v2, "DROP TRIGGER IF EXISTS "

    .line 69
    .line 70
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-static {p0, v1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    return-void

    .line 79
    :goto_2
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 80
    :catchall_1
    move-exception v0

    .line 81
    invoke-static {v1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    throw v0
.end method

.method public static final b(Lua/a;Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "PRAGMA foreign_key_check(`"

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const-string p1, "`)"

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {p0, p1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :try_start_0
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 30
    .line 31
    .line 32
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    if-nez p1, :cond_0

    .line 34
    .line 35
    const/4 p1, 0x0

    .line 36
    invoke-static {p0, p1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    :try_start_1
    invoke-static {p0}, Ljp/we;->b(Lua/c;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    new-instance v0, Landroid/database/SQLException;

    .line 45
    .line 46
    invoke-direct {v0, p1}, Landroid/database/SQLException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 52
    :catchall_1
    move-exception v0

    .line 53
    invoke-static {p0, p1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    throw v0
.end method

.method public static c(Ljava/lang/String;)Ld01/d0;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ld01/d0;->e:Lly0/n;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {v0, v1, p0}, Lly0/n;->b(ILjava/lang/String;)Lly0/l;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    const/16 v2, 0x22

    .line 14
    .line 15
    if-eqz v0, :cond_7

    .line 16
    .line 17
    invoke-virtual {v0}, Lly0/l;->a()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    check-cast v3, Lly0/j;

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    invoke-virtual {v3, v4}, Lly0/j;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    check-cast v3, Ljava/lang/String;

    .line 29
    .line 30
    sget-object v5, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 31
    .line 32
    invoke-virtual {v3, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    const-string v6, "toLowerCase(...)"

    .line 37
    .line 38
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lly0/l;->a()Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    check-cast v7, Lly0/j;

    .line 46
    .line 47
    const/4 v8, 0x2

    .line 48
    invoke-virtual {v7, v8}, Lly0/j;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    check-cast v7, Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v7, v5}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    new-instance v6, Ljava/util/ArrayList;

    .line 62
    .line 63
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Lly0/l;->b()Lgy0/j;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    iget v0, v0, Lgy0/h;->e:I

    .line 71
    .line 72
    :goto_0
    add-int/2addr v0, v4

    .line 73
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    if-ge v0, v7, :cond_6

    .line 78
    .line 79
    sget-object v7, Ld01/d0;->f:Lly0/n;

    .line 80
    .line 81
    invoke-virtual {v7, v0, p0}, Lly0/n;->b(ILjava/lang/String;)Lly0/l;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    const-string v9, "substring(...)"

    .line 86
    .line 87
    if-eqz v7, :cond_5

    .line 88
    .line 89
    iget-object v0, v7, Lly0/l;->c:Lly0/k;

    .line 90
    .line 91
    invoke-virtual {v0, v4}, Lly0/k;->e(I)Lly0/i;

    .line 92
    .line 93
    .line 94
    move-result-object v10

    .line 95
    const/4 v11, 0x0

    .line 96
    if-eqz v10, :cond_0

    .line 97
    .line 98
    iget-object v10, v10, Lly0/i;->a:Ljava/lang/String;

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_0
    move-object v10, v11

    .line 102
    :goto_1
    if-nez v10, :cond_1

    .line 103
    .line 104
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iget v0, v0, Lgy0/h;->e:I

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_1
    invoke-virtual {v0, v8}, Lly0/k;->e(I)Lly0/i;

    .line 112
    .line 113
    .line 114
    move-result-object v12

    .line 115
    if-eqz v12, :cond_2

    .line 116
    .line 117
    iget-object v11, v12, Lly0/i;->a:Ljava/lang/String;

    .line 118
    .line 119
    :cond_2
    if-nez v11, :cond_3

    .line 120
    .line 121
    const/4 v9, 0x3

    .line 122
    invoke-virtual {v0, v9}, Lly0/k;->e(I)Lly0/i;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iget-object v11, v0, Lly0/i;->a:Ljava/lang/String;

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_3
    const/16 v0, 0x27

    .line 133
    .line 134
    invoke-static {v11, v0}, Lly0/p;->b0(Ljava/lang/String;C)Z

    .line 135
    .line 136
    .line 137
    move-result v12

    .line 138
    if-eqz v12, :cond_4

    .line 139
    .line 140
    invoke-static {v11, v0}, Lly0/p;->D(Ljava/lang/CharSequence;C)Z

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    if-eqz v0, :cond_4

    .line 145
    .line 146
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    if-le v0, v8, :cond_4

    .line 151
    .line 152
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    sub-int/2addr v0, v4

    .line 157
    invoke-virtual {v11, v4, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v11

    .line 161
    invoke-static {v11, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    :cond_4
    :goto_2
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    iget v0, v0, Lgy0/h;->e:I

    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 178
    .line 179
    const-string v3, "Parameter is not formatted correctly: \""

    .line 180
    .line 181
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    const-string v0, "\" for: \""

    .line 195
    .line 196
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    invoke-static {v1, p0, v2}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 204
    .line 205
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    throw v0

    .line 213
    :cond_6
    new-instance v0, Ld01/d0;

    .line 214
    .line 215
    new-array v1, v1, [Ljava/lang/String;

    .line 216
    .line 217
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    check-cast v1, [Ljava/lang/String;

    .line 222
    .line 223
    invoke-direct {v0, p0, v3, v5, v1}, Ld01/d0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    return-object v0

    .line 227
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 228
    .line 229
    const-string v1, "No subtype found for: \""

    .line 230
    .line 231
    invoke-static {v2, v1, p0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    throw v0
.end method

.method public static final d(Lla/u;ZLrx0/c;)Lpx0/g;
    .locals 3

    .line 1
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    sget-object v0, Lla/z;->e:Lla/y;

    .line 6
    .line 7
    invoke-interface {p2, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    check-cast p2, Lla/z;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    iget-object p2, p2, Lla/z;->d:Lpx0/d;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object p2, v0

    .line 20
    :goto_0
    invoke-virtual {p0}, Lla/u;->l()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    const-string v2, "coroutineScope"

    .line 25
    .line 26
    if-eqz v1, :cond_6

    .line 27
    .line 28
    if-eqz p2, :cond_2

    .line 29
    .line 30
    iget-object p0, p0, Lla/u;->a:Lpw0/a;

    .line 31
    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 35
    .line 36
    invoke-interface {p0, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw v0

    .line 45
    :cond_2
    if-eqz p1, :cond_4

    .line 46
    .line 47
    iget-object p0, p0, Lla/u;->b:Lpx0/g;

    .line 48
    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_3
    const-string p0, "transactionContext"

    .line 53
    .line 54
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_4
    iget-object p0, p0, Lla/u;->a:Lpw0/a;

    .line 59
    .line 60
    if-eqz p0, :cond_5

    .line 61
    .line 62
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_5
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_6
    iget-object p0, p0, Lla/u;->a:Lpw0/a;

    .line 70
    .line 71
    if-eqz p0, :cond_8

    .line 72
    .line 73
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 74
    .line 75
    if-eqz p2, :cond_7

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_7
    sget-object p2, Lpx0/h;->d:Lpx0/h;

    .line 79
    .line 80
    :goto_1
    invoke-interface {p0, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :cond_8
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0
.end method

.method public static e(Ljava/lang/String;)Ld01/d0;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-static {p0}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 7
    .line 8
    .line 9
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    return-object p0

    .line 11
    :catch_0
    const/4 p0, 0x0

    .line 12
    return-object p0
.end method

.method public static final f(Lla/u;ZZLay0/k;)Ljava/lang/Object;
    .locals 8

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lla/u;->a()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lla/u;->b()V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lla/u;->i:Ljava/lang/ThreadLocal;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Lpx0/g;

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 23
    .line 24
    :cond_0
    move-object v2, v0

    .line 25
    new-instance v1, Lm80/i;

    .line 26
    .line 27
    const/4 v7, 0x0

    .line 28
    move-object v3, p0

    .line 29
    move v5, p1

    .line 30
    move v4, p2

    .line 31
    move-object v6, p3

    .line 32
    invoke-direct/range {v1 .. v7}, Lm80/i;-><init>(Lpx0/g;Lla/u;ZZLay0/k;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1}, Ljp/ha;->b(Lay0/n;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public static final g(Lla/u;Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lqa/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lqa/d;

    .line 7
    .line 8
    iget v1, v0, Lqa/d;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lqa/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqa/d;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lqa/d;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqa/d;->g:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    const/4 v7, 0x0

    .line 36
    if-eqz v2, :cond_5

    .line 37
    .line 38
    if-eq v2, v6, :cond_4

    .line 39
    .line 40
    if-eq v2, v5, :cond_3

    .line 41
    .line 42
    if-eq v2, v4, :cond_2

    .line 43
    .line 44
    if-ne v2, v3, :cond_1

    .line 45
    .line 46
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object p2

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    iget-object p0, v0, Lqa/d;->e:Lrx0/i;

    .line 59
    .line 60
    move-object p1, p0

    .line 61
    check-cast p1, Lay0/k;

    .line 62
    .line 63
    iget-object p0, v0, Lqa/d;->d:Lla/u;

    .line 64
    .line 65
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    return-object p2

    .line 73
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-object p2

    .line 77
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0}, Lla/u;->l()Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    if-eqz p2, :cond_7

    .line 85
    .line 86
    new-instance p2, Lla/v;

    .line 87
    .line 88
    const/4 v2, 0x1

    .line 89
    invoke-direct {p2, v2, p1, v7, p0}, Lla/v;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 90
    .line 91
    .line 92
    iput v6, v0, Lqa/d;->g:I

    .line 93
    .line 94
    invoke-static {p2, v0, p0}, Llp/gf;->c(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v1, :cond_6

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_6
    return-object p0

    .line 102
    :cond_7
    invoke-virtual {p0}, Lla/u;->l()Z

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    if-eqz p2, :cond_9

    .line 107
    .line 108
    invoke-virtual {p0}, Lla/u;->o()Z

    .line 109
    .line 110
    .line 111
    move-result p2

    .line 112
    if-eqz p2, :cond_9

    .line 113
    .line 114
    invoke-virtual {p0}, Lla/u;->m()Z

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    if-eqz p2, :cond_9

    .line 119
    .line 120
    new-instance p2, Lqa/e;

    .line 121
    .line 122
    const/4 v2, 0x1

    .line 123
    invoke-direct {p2, v2, p1, v7, p0}, Lqa/e;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 124
    .line 125
    .line 126
    iput v5, v0, Lqa/d;->g:I

    .line 127
    .line 128
    const/4 p1, 0x0

    .line 129
    invoke-virtual {p0, p1, p2, v0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    if-ne p0, v1, :cond_8

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_8
    return-object p0

    .line 137
    :cond_9
    iput-object p0, v0, Lqa/d;->d:Lla/u;

    .line 138
    .line 139
    move-object p2, p1

    .line 140
    check-cast p2, Lrx0/i;

    .line 141
    .line 142
    iput-object p2, v0, Lqa/d;->e:Lrx0/i;

    .line 143
    .line 144
    iput v4, v0, Lqa/d;->g:I

    .line 145
    .line 146
    invoke-static {p0, v6, v0}, Ljp/ue;->d(Lla/u;ZLrx0/c;)Lpx0/g;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    if-ne p2, v1, :cond_a

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_a
    :goto_1
    check-cast p2, Lpx0/g;

    .line 154
    .line 155
    new-instance v2, Lna/e;

    .line 156
    .line 157
    invoke-direct {v2, p1, v7, p0}, Lna/e;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 158
    .line 159
    .line 160
    iput-object v7, v0, Lqa/d;->d:Lla/u;

    .line 161
    .line 162
    iput-object v7, v0, Lqa/d;->e:Lrx0/i;

    .line 163
    .line 164
    iput v3, v0, Lqa/d;->g:I

    .line 165
    .line 166
    invoke-static {p2, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    if-ne p0, v1, :cond_b

    .line 171
    .line 172
    :goto_2
    return-object v1

    .line 173
    :cond_b
    return-object p0
.end method

.method public static final h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p0, Lqa/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Lqa/f;

    .line 7
    .line 8
    iget v1, v0, Lqa/f;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lqa/f;->i:I

    .line 18
    .line 19
    :goto_0
    move-object p0, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lqa/f;

    .line 22
    .line 23
    invoke-direct {v0, p0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p0, Lqa/f;->h:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, p0, Lqa/f;->i:I

    .line 32
    .line 33
    const/4 v2, 0x3

    .line 34
    const/4 v3, 0x2

    .line 35
    const/4 v8, 0x1

    .line 36
    if-eqz v1, :cond_4

    .line 37
    .line 38
    if-eq v1, v8, :cond_3

    .line 39
    .line 40
    if-eq v1, v3, :cond_2

    .line 41
    .line 42
    if-ne v1, v2, :cond_1

    .line 43
    .line 44
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-boolean v1, p0, Lqa/f;->g:Z

    .line 57
    .line 58
    iget-boolean v3, p0, Lqa/f;->f:Z

    .line 59
    .line 60
    iget-object v4, p0, Lqa/f;->e:Lay0/k;

    .line 61
    .line 62
    iget-object v5, p0, Lqa/f;->d:Lla/u;

    .line 63
    .line 64
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move v12, v1

    .line 68
    move v11, v3

    .line 69
    move-object v13, v4

    .line 70
    move-object v10, v5

    .line 71
    goto :goto_2

    .line 72
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    return-object v0

    .line 76
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1}, Lla/u;->l()Z

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-eqz v0, :cond_6

    .line 84
    .line 85
    invoke-virtual {p1}, Lla/u;->o()Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-eqz v0, :cond_6

    .line 90
    .line 91
    invoke-virtual {p1}, Lla/u;->m()Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_6

    .line 96
    .line 97
    new-instance v0, Lqa/b;

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    const/4 v6, 0x1

    .line 101
    move-object v3, p1

    .line 102
    move/from16 v2, p2

    .line 103
    .line 104
    move/from16 v1, p3

    .line 105
    .line 106
    move-object/from16 v5, p4

    .line 107
    .line 108
    invoke-direct/range {v0 .. v6}, Lqa/b;-><init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 109
    .line 110
    .line 111
    move v1, v2

    .line 112
    move-object v2, v0

    .line 113
    iput v8, p0, Lqa/f;->i:I

    .line 114
    .line 115
    invoke-virtual {p1, v1, v2, p0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v7, :cond_5

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_5
    return-object p0

    .line 123
    :cond_6
    move/from16 v1, p2

    .line 124
    .line 125
    move/from16 v4, p3

    .line 126
    .line 127
    iput-object p1, p0, Lqa/f;->d:Lla/u;

    .line 128
    .line 129
    move-object/from16 v5, p4

    .line 130
    .line 131
    iput-object v5, p0, Lqa/f;->e:Lay0/k;

    .line 132
    .line 133
    iput-boolean v1, p0, Lqa/f;->f:Z

    .line 134
    .line 135
    iput-boolean v4, p0, Lqa/f;->g:Z

    .line 136
    .line 137
    iput v3, p0, Lqa/f;->i:I

    .line 138
    .line 139
    invoke-static {p1, v4, p0}, Ljp/ue;->d(Lla/u;ZLrx0/c;)Lpx0/g;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    if-ne v3, v7, :cond_7

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_7
    move-object v10, p1

    .line 147
    move v11, v1

    .line 148
    move-object v0, v3

    .line 149
    move v12, v4

    .line 150
    move-object v13, v5

    .line 151
    :goto_2
    check-cast v0, Lpx0/g;

    .line 152
    .line 153
    new-instance v8, Lqa/c;

    .line 154
    .line 155
    const/4 v9, 0x0

    .line 156
    invoke-direct/range {v8 .. v13}, Lqa/c;-><init>(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)V

    .line 157
    .line 158
    .line 159
    const/4 v1, 0x0

    .line 160
    iput-object v1, p0, Lqa/f;->d:Lla/u;

    .line 161
    .line 162
    iput-object v1, p0, Lqa/f;->e:Lay0/k;

    .line 163
    .line 164
    iput v2, p0, Lqa/f;->i:I

    .line 165
    .line 166
    invoke-static {v0, v8, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    if-ne p0, v7, :cond_8

    .line 171
    .line 172
    :goto_3
    return-object v7

    .line 173
    :cond_8
    return-object p0
.end method
