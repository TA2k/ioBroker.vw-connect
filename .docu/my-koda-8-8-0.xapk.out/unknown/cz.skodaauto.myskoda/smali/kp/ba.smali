.class public abstract Lkp/ba;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lcom/google/firebase/messaging/w;


# direct methods
.method public static final a(Lh0/z;Lb0/d1;Ld0/c;)V
    .locals 12

    .line 1
    sget-object v0, Lkp/ba;->a:Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-interface {p0}, Lh0/z;->f()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v1, "getCameraId(...)"

    .line 10
    .line 11
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lh0/i0;

    .line 17
    .line 18
    invoke-virtual {v1, p0}, Lh0/i0;->b(Ljava/lang/String;)Lh0/b0;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    new-instance v5, Lh0/c;

    .line 23
    .line 24
    invoke-interface {v3}, Lh0/b0;->l()Lh0/z;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    sget-object v1, Lh0/w;->a:Lh0/v;

    .line 29
    .line 30
    invoke-direct {v5, p0, v1}, Lh0/c;-><init>(Lh0/z;Lh0/t;)V

    .line 31
    .line 32
    .line 33
    sget-object v7, Lb0/x;->g:Lb0/x;

    .line 34
    .line 35
    new-instance v2, Ll0/g;

    .line 36
    .line 37
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v9, p0

    .line 40
    check-cast v9, Lz/a;

    .line 41
    .line 42
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v10, p0

    .line 45
    check-cast v10, Lc2/k;

    .line 46
    .line 47
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v11, p0

    .line 50
    check-cast v11, Lh0/r2;

    .line 51
    .line 52
    const/4 v4, 0x0

    .line 53
    const/4 v6, 0x0

    .line 54
    move-object v8, v7

    .line 55
    invoke-direct/range {v2 .. v11}, Ll0/g;-><init>(Lh0/b0;Lh0/b0;Lh0/c;Lh0/c;Lb0/x;Lb0/x;Lz/a;Lc2/k;Lh0/r2;)V

    .line 56
    .line 57
    .line 58
    iget-object p0, v2, Ll0/g;->n:Ljava/lang/Object;

    .line 59
    .line 60
    monitor-enter p0

    .line 61
    :try_start_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 62
    iget-object p0, p1, Lb0/d1;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Ljava/util/List;

    .line 65
    .line 66
    iget-object v1, v2, Ll0/g;->n:Ljava/lang/Object;

    .line 67
    .line 68
    monitor-enter v1

    .line 69
    :try_start_1
    iput-object p0, v2, Ll0/g;->k:Ljava/util/List;

    .line 70
    .line 71
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 72
    iget-object p0, v2, Ll0/g;->n:Ljava/lang/Object;

    .line 73
    .line 74
    monitor-enter p0

    .line 75
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 76
    iget-object p0, p1, Lb0/d1;->h:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Landroid/util/Range;

    .line 79
    .line 80
    iget-object v1, v2, Ll0/g;->n:Ljava/lang/Object;

    .line 81
    .line 82
    monitor-enter v1

    .line 83
    :try_start_3
    iput-object p0, v2, Ll0/g;->l:Landroid/util/Range;

    .line 84
    .line 85
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 86
    iget-object p0, p1, Lb0/d1;->g:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast p0, Ljava/util/List;

    .line 89
    .line 90
    check-cast p0, Ljava/util/Collection;

    .line 91
    .line 92
    const-string p1, "CameraUseCaseAdapter"

    .line 93
    .line 94
    new-instance v0, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    const-string v1, "simulateAddUseCases: appUseCasesToAdd = "

    .line 97
    .line 98
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string v1, ", featureGroup = "

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    iget-object p1, v2, Ll0/g;->n:Ljava/lang/Object;

    .line 120
    .line 121
    monitor-enter p1

    .line 122
    :try_start_4
    iget-object v0, v2, Ll0/g;->d:Lh0/d;

    .line 123
    .line 124
    iget-object v1, v2, Ll0/g;->m:Lh0/t;

    .line 125
    .line 126
    invoke-virtual {v0, v1}, Lh0/d;->i(Lh0/t;)V

    .line 127
    .line 128
    .line 129
    iget-object v0, v2, Ll0/g;->e:Lh0/d;

    .line 130
    .line 131
    if-eqz v0, :cond_0

    .line 132
    .line 133
    invoke-virtual {v0, v1}, Lh0/d;->i(Lh0/t;)V

    .line 134
    .line 135
    .line 136
    :cond_0
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 137
    .line 138
    iget-object v1, v2, Ll0/g;->h:Ljava/util/ArrayList;

    .line 139
    .line 140
    invoke-direct {v0, v1}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 141
    .line 142
    .line 143
    invoke-interface {v0, p0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 144
    .line 145
    .line 146
    invoke-static {v0, p2}, Ll0/g;->m(Ljava/util/LinkedHashSet;Ld0/c;)Ljava/util/HashMap;

    .line 147
    .line 148
    .line 149
    move-result-object p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 150
    :try_start_5
    iget-object p2, v2, Ll0/g;->e:Lh0/d;

    .line 151
    .line 152
    if-eqz p2, :cond_1

    .line 153
    .line 154
    const/4 p2, 0x1

    .line 155
    goto :goto_0

    .line 156
    :cond_1
    const/4 p2, 0x0

    .line 157
    :goto_0
    invoke-virtual {v2, v0, p2}, Ll0/g;->s(Ljava/util/LinkedHashSet;Z)Ll0/b;

    .line 158
    .line 159
    .line 160
    move-result-object p2
    :try_end_5
    .catch Ljava/lang/IllegalArgumentException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 161
    :try_start_6
    invoke-static {p0}, Ll0/g;->D(Ljava/util/HashMap;)V

    .line 162
    .line 163
    .line 164
    monitor-exit p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 165
    const-string p0, "simulateAddUseCases(...)"

    .line 166
    .line 167
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    return-void

    .line 171
    :catchall_0
    move-exception v0

    .line 172
    move-object p0, v0

    .line 173
    goto :goto_2

    .line 174
    :catchall_1
    move-exception v0

    .line 175
    move-object p2, v0

    .line 176
    goto :goto_1

    .line 177
    :catch_0
    move-exception v0

    .line 178
    move-object p2, v0

    .line 179
    :try_start_7
    new-instance v0, Ll0/e;

    .line 180
    .line 181
    invoke-direct {v0, p2}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 182
    .line 183
    .line 184
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 185
    :goto_1
    :try_start_8
    invoke-static {p0}, Ll0/g;->D(Ljava/util/HashMap;)V

    .line 186
    .line 187
    .line 188
    throw p2

    .line 189
    :goto_2
    monitor-exit p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 190
    throw p0

    .line 191
    :catchall_2
    move-exception v0

    .line 192
    move-object p0, v0

    .line 193
    :try_start_9
    monitor-exit v1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 194
    throw p0

    .line 195
    :catchall_3
    move-exception v0

    .line 196
    move-object p1, v0

    .line 197
    :try_start_a
    monitor-exit p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 198
    throw p1

    .line 199
    :catchall_4
    move-exception v0

    .line 200
    move-object p0, v0

    .line 201
    :try_start_b
    monitor-exit v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 202
    throw p0

    .line 203
    :catchall_5
    move-exception v0

    .line 204
    move-object p1, v0

    .line 205
    :try_start_c
    monitor-exit p0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_5

    .line 206
    throw p1

    .line 207
    :cond_2
    const-string p0, "mCameraUseCaseAdapterProvider must be initialized first!"

    .line 208
    .line 209
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 210
    .line 211
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p1
.end method

.method public static final b(Lbh/c;Lay0/k;)Lth/a;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "getImage"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lth/a;

    .line 12
    .line 13
    iget-object v2, p0, Lbh/c;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p0, Lbh/c;->b:Ljava/lang/String;

    .line 16
    .line 17
    iget-boolean v4, p0, Lbh/c;->e:Z

    .line 18
    .line 19
    iget-boolean v5, p0, Lbh/c;->c:Z

    .line 20
    .line 21
    iget-object p0, p0, Lbh/c;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    move-object v6, p0

    .line 28
    check-cast v6, Lkc/e;

    .line 29
    .line 30
    invoke-direct/range {v1 .. v6}, Lth/a;-><init>(Ljava/lang/String;Ljava/lang/String;ZZLkc/e;)V

    .line 31
    .line 32
    .line 33
    return-object v1
.end method

.method public static final c(Lth/j;Lid/a;)Lth/g;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "getImageRequest"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lth/j;->a:Ljava/util/List;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/Iterable;

    .line 14
    .line 15
    new-instance v1, Ljava/util/ArrayList;

    .line 16
    .line 17
    const/16 v2, 0xa

    .line 18
    .line 19
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_0

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lbh/c;

    .line 41
    .line 42
    invoke-static {v2, p1}, Lkp/ba;->b(Lbh/c;Lay0/k;)Lth/a;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    iget-boolean v0, p0, Lth/j;->b:Z

    .line 51
    .line 52
    iget-object v2, p0, Lth/j;->c:Lbh/c;

    .line 53
    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    invoke-static {v2, p1}, Lkp/ba;->b(Lbh/c;Lay0/k;)Lth/a;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    const/4 p1, 0x0

    .line 62
    :goto_1
    iget-object p0, p0, Lth/j;->d:Llc/l;

    .line 63
    .line 64
    new-instance v2, Lth/g;

    .line 65
    .line 66
    invoke-direct {v2, v1, v0, p1, p0}, Lth/g;-><init>(Ljava/util/ArrayList;ZLth/a;Llc/l;)V

    .line 67
    .line 68
    .line 69
    return-object v2
.end method
