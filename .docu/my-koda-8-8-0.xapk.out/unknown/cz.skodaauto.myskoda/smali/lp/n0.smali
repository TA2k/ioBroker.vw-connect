.class public abstract Llp/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/Collection;Lwq/f;)Lqz0/a;
    .locals 5

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    invoke-static {p0}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/16 v2, 0xa

    .line 10
    .line 11
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-static {v3, p1}, Llp/n0;->c(Ljava/lang/Object;Lwq/f;)Lqz0/a;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-instance p1, Ljava/util/HashSet;

    .line 41
    .line 42
    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    .line 43
    .line 44
    .line 45
    new-instance v0, Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    :cond_1
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-eqz v3, :cond_2

    .line 59
    .line 60
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    move-object v4, v3

    .line 65
    check-cast v4, Lqz0/a;

    .line 66
    .line 67
    invoke-interface {v4}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-interface {v4}, Lsz0/g;->h()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-virtual {p1, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_1

    .line 80
    .line 81
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    const/4 v1, 0x1

    .line 90
    if-le p1, v1, :cond_4

    .line 91
    .line 92
    new-instance p0, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    const-string p1, "Serializing collections of different element types is not yet supported. Selected serializers: "

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    new-instance p1, Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-eqz v1, :cond_3

    .line 117
    .line 118
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    check-cast v1, Lqz0/a;

    .line 123
    .line 124
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-interface {v1}, Lsz0/g;->h()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_3
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 144
    .line 145
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    throw p1

    .line 153
    :cond_4
    invoke-static {v0}, Lmx0/q;->k0(Ljava/util/List;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    check-cast p1, Lqz0/a;

    .line 158
    .line 159
    if-nez p1, :cond_5

    .line 160
    .line 161
    sget-object p1, Luz0/q1;->a:Luz0/q1;

    .line 162
    .line 163
    :cond_5
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    invoke-interface {v0}, Lsz0/g;->b()Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-eqz v0, :cond_6

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_6
    instance-of v0, p0, Ljava/util/Collection;

    .line 175
    .line 176
    if-eqz v0, :cond_7

    .line 177
    .line 178
    move-object v0, p0

    .line 179
    check-cast v0, Ljava/util/Collection;

    .line 180
    .line 181
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    if-eqz v0, :cond_7

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_7
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    :cond_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-eqz v0, :cond_9

    .line 197
    .line 198
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-nez v0, :cond_8

    .line 203
    .line 204
    invoke-static {p1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    return-object p0

    .line 209
    :cond_9
    :goto_3
    return-object p1
.end method

.method public static final b(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p0, Lh7/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Lh7/c;

    .line 7
    .line 8
    iget v1, v0, Lh7/c;->i:I

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
    iput v1, v0, Lh7/c;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh7/c;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lh7/c;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh7/c;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v5, :cond_1

    .line 37
    .line 38
    iget-object v2, v0, Lh7/c;->g:Lxy0/c;

    .line 39
    .line 40
    iget-object v6, v0, Lh7/c;->f:Lxy0/z;

    .line 41
    .line 42
    iget-object v7, v0, Lh7/c;->e:Lrx/b;

    .line 43
    .line 44
    iget-object v8, v0, Lh7/c;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 45
    .line 46
    :try_start_0
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    goto :goto_2

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    goto/16 :goto_4

    .line 52
    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x6

    .line 65
    invoke-static {v5, p0, v4}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    new-instance p0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 70
    .line 71
    invoke-direct {p0, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 72
    .line 73
    .line 74
    new-instance v2, Lb1/e;

    .line 75
    .line 76
    const/4 v7, 0x4

    .line 77
    invoke-direct {v2, v7, p0, v6}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    sget-object v7, Lv2/l;->c:Ljava/lang/Object;

    .line 81
    .line 82
    monitor-enter v7

    .line 83
    :try_start_1
    sget-object v8, Lv2/l;->i:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v8, Ljava/util/Collection;

    .line 86
    .line 87
    invoke-static {v8, v2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    sput-object v8, Lv2/l;->i:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 92
    .line 93
    monitor-exit v7

    .line 94
    invoke-static {}, Lv2/l;->a()V

    .line 95
    .line 96
    .line 97
    new-instance v7, Lrx/b;

    .line 98
    .line 99
    const/16 v8, 0xa

    .line 100
    .line 101
    invoke-direct {v7, v2, v8}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 102
    .line 103
    .line 104
    :try_start_2
    new-instance v2, Lxy0/c;

    .line 105
    .line 106
    invoke-direct {v2, v6}, Lxy0/c;-><init>(Lxy0/j;)V

    .line 107
    .line 108
    .line 109
    move-object v8, p0

    .line 110
    :cond_3
    :goto_1
    iput-object v8, v0, Lh7/c;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 111
    .line 112
    iput-object v7, v0, Lh7/c;->e:Lrx/b;

    .line 113
    .line 114
    iput-object v6, v0, Lh7/c;->f:Lxy0/z;

    .line 115
    .line 116
    iput-object v2, v0, Lh7/c;->g:Lxy0/c;

    .line 117
    .line 118
    iput v5, v0, Lh7/c;->i:I

    .line 119
    .line 120
    invoke-virtual {v2, v0}, Lxy0/c;->a(Lrx0/c;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-ne p0, v1, :cond_4

    .line 125
    .line 126
    return-object v1

    .line 127
    :cond_4
    :goto_2
    check-cast p0, Ljava/lang/Boolean;

    .line 128
    .line 129
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    if-eqz p0, :cond_6

    .line 134
    .line 135
    invoke-virtual {v2}, Lxy0/c;->c()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Llx0/b0;

    .line 140
    .line 141
    invoke-virtual {v8, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 142
    .line 143
    .line 144
    sget-object p0, Lv2/l;->c:Ljava/lang/Object;

    .line 145
    .line 146
    monitor-enter p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 147
    :try_start_3
    sget-object v9, Lv2/l;->j:Lv2/a;

    .line 148
    .line 149
    iget-object v9, v9, Lv2/b;->h:Landroidx/collection/r0;

    .line 150
    .line 151
    if-eqz v9, :cond_5

    .line 152
    .line 153
    invoke-virtual {v9}, Landroidx/collection/r0;->h()Z

    .line 154
    .line 155
    .line 156
    move-result v9
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 157
    if-ne v9, v5, :cond_5

    .line 158
    .line 159
    move v9, v5

    .line 160
    goto :goto_3

    .line 161
    :cond_5
    move v9, v3

    .line 162
    :goto_3
    :try_start_4
    monitor-exit p0

    .line 163
    if-eqz v9, :cond_3

    .line 164
    .line 165
    invoke-static {}, Lv2/l;->a()V

    .line 166
    .line 167
    .line 168
    goto :goto_1

    .line 169
    :catchall_1
    move-exception v0

    .line 170
    monitor-exit p0

    .line 171
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 172
    :cond_6
    :try_start_5
    invoke-interface {v6, v4}, Lxy0/z;->d(Ljava/util/concurrent/CancellationException;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 173
    .line 174
    .line 175
    invoke-virtual {v7}, Lrx/b;->d()V

    .line 176
    .line 177
    .line 178
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object p0

    .line 181
    :catchall_2
    move-exception p0

    .line 182
    goto :goto_5

    .line 183
    :goto_4
    :try_start_6
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 184
    :catchall_3
    move-exception v0

    .line 185
    :try_start_7
    invoke-static {v6, p0}, Llp/kf;->d(Lxy0/z;Ljava/lang/Throwable;)V

    .line 186
    .line 187
    .line 188
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 189
    :goto_5
    invoke-virtual {v7}, Lrx/b;->d()V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :catchall_4
    move-exception p0

    .line 194
    monitor-exit v7

    .line 195
    throw p0
.end method

.method public static final c(Ljava/lang/Object;Lwq/f;)Lqz0/a;
    .locals 2

    .line 1
    const-string v0, "module"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 9
    .line 10
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    instance-of v0, p0, Ljava/util/List;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    check-cast p0, Ljava/util/Collection;

    .line 20
    .line 21
    invoke-static {p0, p1}, Llp/n0;->a(Ljava/util/Collection;Lwq/f;)Lqz0/a;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_1
    instance-of v0, p0, [Ljava/lang/Object;

    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    check-cast p0, [Ljava/lang/Object;

    .line 35
    .line 36
    invoke-static {p0}, Lmx0/n;->w([Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    if-eqz p0, :cond_2

    .line 41
    .line 42
    invoke-static {p0, p1}, Llp/n0;->c(Ljava/lang/Object;Lwq/f;)Lqz0/a;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :cond_2
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 48
    .line 49
    invoke-static {p0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_3
    instance-of v0, p0, Ljava/util/Set;

    .line 55
    .line 56
    if-eqz v0, :cond_4

    .line 57
    .line 58
    check-cast p0, Ljava/util/Collection;

    .line 59
    .line 60
    invoke-static {p0, p1}, Llp/n0;->a(Ljava/util/Collection;Lwq/f;)Lqz0/a;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    new-instance p1, Luz0/d;

    .line 65
    .line 66
    const/4 v0, 0x2

    .line 67
    invoke-direct {p1, p0, v0}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 68
    .line 69
    .line 70
    return-object p1

    .line 71
    :cond_4
    instance-of v0, p0, Ljava/util/Map;

    .line 72
    .line 73
    if-eqz v0, :cond_5

    .line 74
    .line 75
    check-cast p0, Ljava/util/Map;

    .line 76
    .line 77
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    check-cast v0, Ljava/util/Collection;

    .line 82
    .line 83
    invoke-static {v0, p1}, Llp/n0;->a(Ljava/util/Collection;Lwq/f;)Lqz0/a;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-static {p0, p1}, Llp/n0;->a(Ljava/util/Collection;Lwq/f;)Lqz0/a;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-static {v0, p0}, Lkp/u6;->b(Lqz0/a;Lqz0/a;)Luz0/e0;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 105
    .line 106
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    const-string v1, "kClass"

    .line 111
    .line 112
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {p0}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0
.end method

.method public static final d(Lwq/f;Lzw0/a;)Lqz0/a;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "typeInfo"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p1, Lzw0/a;->a:Lhy0/d;

    .line 12
    .line 13
    iget-object p1, p1, Lzw0/a;->b:Lhy0/a0;

    .line 14
    .line 15
    if-eqz p1, :cond_1

    .line 16
    .line 17
    invoke-interface {p1}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-static {p0, p1}, Ljp/mg;->g(Lwq/f;Lhy0/a0;)Lqz0/a;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    :goto_0
    if-eqz p0, :cond_1

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_1
    const-string p0, "kClass"

    .line 37
    .line 38
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v0}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-eqz p1, :cond_2

    .line 46
    .line 47
    invoke-interface {p1}, Lhy0/a0;->isMarkedNullable()Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    const/4 v0, 0x1

    .line 52
    if-ne p1, v0, :cond_2

    .line 53
    .line 54
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    :cond_2
    return-object p0
.end method
