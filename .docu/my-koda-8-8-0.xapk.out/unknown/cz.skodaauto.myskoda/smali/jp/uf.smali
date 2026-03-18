.class public final Ljp/uf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/io/Serializable;

.field public j:Ljava/lang/Object;

.field public k:Ljava/util/RandomAccess;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ln2/b;

    .line 5
    .line 6
    const/16 v1, 0x10

    .line 7
    .line 8
    new-array v2, v1, [Ll2/a2;

    .line 9
    .line 10
    invoke-direct {v0, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Ljp/uf;->c:Ljava/lang/Object;

    .line 14
    .line 15
    sget-object v2, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 16
    .line 17
    new-instance v2, Landroidx/collection/r0;

    .line 18
    .line 19
    invoke-direct {v2}, Landroidx/collection/r0;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v2, p0, Ljp/uf;->d:Ljava/lang/Object;

    .line 23
    .line 24
    iput-object v0, p0, Ljp/uf;->e:Ljava/lang/Object;

    .line 25
    .line 26
    new-instance v0, Ln2/b;

    .line 27
    .line 28
    new-array v2, v1, [Ljava/lang/Object;

    .line 29
    .line 30
    invoke-direct {v0, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 34
    .line 35
    new-instance v0, Ln2/b;

    .line 36
    .line 37
    new-array v1, v1, [Lay0/a;

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iput-object v0, p0, Ljp/uf;->f:Ljava/lang/Object;

    .line 43
    .line 44
    return-void
.end method

.method public static final f(Ll2/a2;Ln2/b;)Z
    .locals 5

    .line 1
    iget-object v0, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p1, Ln2/b;->f:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    if-ge v2, p1, :cond_2

    .line 8
    .line 9
    aget-object v3, v0, v2

    .line 10
    .line 11
    check-cast v3, Ll2/a2;

    .line 12
    .line 13
    iget-object v3, v3, Ll2/a2;->a:Ll2/z1;

    .line 14
    .line 15
    instance-of v4, v3, Lt2/e;

    .line 16
    .line 17
    if-eqz v4, :cond_1

    .line 18
    .line 19
    check-cast v3, Lt2/e;

    .line 20
    .line 21
    iget-object v3, v3, Lt2/e;->e:Ln2/b;

    .line 22
    .line 23
    invoke-virtual {v3, p0}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    invoke-static {p0, v3}, Ljp/uf;->f(Ll2/a2;Ln2/b;)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    :goto_1
    const/4 p0, 0x1

    .line 37
    return p0

    .line 38
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    return v1
.end method


# virtual methods
.method public a()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 3
    .line 4
    iput-object v0, p0, Ljp/uf;->b:Ljava/lang/Object;

    .line 5
    .line 6
    iget-object v1, p0, Ljp/uf;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Ln2/b;

    .line 9
    .line 10
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 11
    .line 12
    .line 13
    iget-object v2, p0, Ljp/uf;->d:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Landroidx/collection/r0;

    .line 16
    .line 17
    invoke-virtual {v2}, Landroidx/collection/r0;->b()V

    .line 18
    .line 19
    .line 20
    iput-object v1, p0, Ljp/uf;->e:Ljava/lang/Object;

    .line 21
    .line 22
    iget-object v1, p0, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 23
    .line 24
    check-cast v1, Ln2/b;

    .line 25
    .line 26
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Ljp/uf;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Ln2/b;

    .line 32
    .line 33
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Ljp/uf;->g:Ljava/lang/Object;

    .line 37
    .line 38
    iput-object v0, p0, Ljp/uf;->h:Ljava/lang/Object;

    .line 39
    .line 40
    iput-object v0, p0, Ljp/uf;->i:Ljava/io/Serializable;

    .line 41
    .line 42
    return-void
.end method

.method public b()V
    .locals 1

    .line 1
    iget-object p0, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/Set;

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_2

    .line 16
    .line 17
    const-string v0, "Compose:abandons"

    .line 18
    .line 19
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :try_start_0
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Ll2/z1;

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 39
    .line 40
    .line 41
    invoke-interface {v0}, Ll2/z1;->e()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    :goto_1
    return-void
.end method

.method public c()V
    .locals 7

    .line 1
    iget-object v0, p0, Ljp/uf;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ln2/b;

    .line 4
    .line 5
    iget-object v1, p0, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 6
    .line 7
    check-cast v1, Ln2/b;

    .line 8
    .line 9
    iget-object v2, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Ljava/util/Set;

    .line 12
    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    goto/16 :goto_9

    .line 16
    .line 17
    :cond_0
    const/4 v3, 0x0

    .line 18
    iput-object v3, p0, Ljp/uf;->j:Ljava/lang/Object;

    .line 19
    .line 20
    iget v3, v1, Ln2/b;->f:I

    .line 21
    .line 22
    if-eqz v3, :cond_6

    .line 23
    .line 24
    const-string v3, "Compose:onForgotten"

    .line 25
    .line 26
    invoke-static {v3}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    :try_start_0
    iget-object v3, p0, Ljp/uf;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v3, Landroidx/collection/r0;

    .line 32
    .line 33
    iget v4, v1, Ln2/b;->f:I

    .line 34
    .line 35
    add-int/lit8 v4, v4, -0x1

    .line 36
    .line 37
    :goto_0
    const/4 v5, -0x1

    .line 38
    if-ge v5, v4, :cond_5

    .line 39
    .line 40
    iget-object v5, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 41
    .line 42
    aget-object v5, v5, v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 43
    .line 44
    :try_start_1
    instance-of v6, v5, Ll2/a2;

    .line 45
    .line 46
    if-eqz v6, :cond_1

    .line 47
    .line 48
    move-object v6, v5

    .line 49
    check-cast v6, Ll2/a2;

    .line 50
    .line 51
    iget-object v6, v6, Ll2/a2;->a:Ll2/z1;

    .line 52
    .line 53
    invoke-interface {v2, v6}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    invoke-interface {v6}, Ll2/z1;->h()V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :catchall_0
    move-exception v0

    .line 61
    goto :goto_3

    .line 62
    :cond_1
    :goto_1
    instance-of v6, v5, Ll2/j;

    .line 63
    .line 64
    if-eqz v6, :cond_3

    .line 65
    .line 66
    if-eqz v3, :cond_2

    .line 67
    .line 68
    invoke-virtual {v3, v5}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_2

    .line 73
    .line 74
    move-object v6, v5

    .line 75
    check-cast v6, Ll2/j;

    .line 76
    .line 77
    invoke-interface {v6}, Ll2/j;->f()V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_2
    move-object v6, v5

    .line 82
    check-cast v6, Ll2/j;

    .line 83
    .line 84
    invoke-interface {v6}, Ll2/j;->a()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    .line 86
    .line 87
    :cond_3
    :goto_2
    add-int/lit8 v4, v4, -0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :goto_3
    :try_start_2
    iget-object p0, p0, Ljp/uf;->b:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p0, Lw2/b;

    .line 93
    .line 94
    if-eqz p0, :cond_4

    .line 95
    .line 96
    new-instance v1, Lvu/d;

    .line 97
    .line 98
    const/4 v2, 0x4

    .line 99
    invoke-direct {v1, v2, p0, v5}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    invoke-static {v0, v1}, Llp/tc;->c(Ljava/lang/Throwable;Lay0/a;)Z

    .line 103
    .line 104
    .line 105
    :cond_4
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 106
    :cond_5
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 107
    .line 108
    .line 109
    goto :goto_4

    .line 110
    :catchall_1
    move-exception p0

    .line 111
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_6
    :goto_4
    iget v1, v0, Ln2/b;->f:I

    .line 116
    .line 117
    if-eqz v1, :cond_a

    .line 118
    .line 119
    const-string v1, "Compose:onRemembered"

    .line 120
    .line 121
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    :try_start_3
    iget-object v1, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v1, Ljava/util/Set;

    .line 127
    .line 128
    if-nez v1, :cond_7

    .line 129
    .line 130
    goto :goto_7

    .line 131
    :cond_7
    iget-object v2, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 132
    .line 133
    iget v0, v0, Ln2/b;->f:I

    .line 134
    .line 135
    const/4 v3, 0x0

    .line 136
    :goto_5
    if-ge v3, v0, :cond_9

    .line 137
    .line 138
    aget-object v4, v2, v3

    .line 139
    .line 140
    check-cast v4, Ll2/a2;

    .line 141
    .line 142
    iget-object v5, v4, Ll2/a2;->a:Ll2/z1;

    .line 143
    .line 144
    invoke-interface {v1, v5}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 145
    .line 146
    .line 147
    :try_start_4
    invoke-interface {v5}, Ll2/z1;->c()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 148
    .line 149
    .line 150
    add-int/lit8 v3, v3, 0x1

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :catchall_2
    move-exception v0

    .line 154
    :try_start_5
    iget-object p0, p0, Ljp/uf;->b:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast p0, Lw2/b;

    .line 157
    .line 158
    if-eqz p0, :cond_8

    .line 159
    .line 160
    new-instance v1, Lvu/d;

    .line 161
    .line 162
    const/4 v2, 0x4

    .line 163
    invoke-direct {v1, v2, p0, v4}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v0, v1}, Llp/tc;->c(Ljava/lang/Throwable;Lay0/a;)Z

    .line 167
    .line 168
    .line 169
    goto :goto_6

    .line 170
    :catchall_3
    move-exception p0

    .line 171
    goto :goto_8

    .line 172
    :cond_8
    :goto_6
    throw v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 173
    :cond_9
    :goto_7
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :goto_8
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :cond_a
    :goto_9
    return-void
.end method

.method public d()V
    .locals 4

    .line 1
    iget-object p0, p0, Ljp/uf;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ln2/b;

    .line 4
    .line 5
    iget v0, p0, Ln2/b;->f:I

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const-string v0, "Compose:sideeffects"

    .line 10
    .line 11
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :try_start_0
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 15
    .line 16
    iget v1, p0, Ln2/b;->f:I

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    :goto_0
    if-ge v2, v1, :cond_0

    .line 20
    .line 21
    aget-object v3, v0, v2

    .line 22
    .line 23
    check-cast v3, Lay0/a;

    .line 24
    .line 25
    invoke-interface {v3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    add-int/lit8 v2, v2, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {p0}, Ln2/b;->i()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    return-void
.end method

.method public e(Ll2/a2;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ljp/uf;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ln2/b;

    .line 4
    .line 5
    iget-object v1, p0, Ljp/uf;->d:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroidx/collection/r0;

    .line 8
    .line 9
    invoke-virtual {v1, p1}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    iget-object v1, p0, Ljp/uf;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Landroidx/collection/r0;

    .line 18
    .line 19
    invoke-virtual {v1, p1}, Landroidx/collection/r0;->l(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Ljp/uf;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Ln2/b;

    .line 25
    .line 26
    invoke-virtual {v1, p1}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-static {p1, v0}, Ljp/uf;->f(Ll2/a2;Ln2/b;)Z

    .line 40
    .line 41
    .line 42
    :cond_1
    :goto_0
    iget-object v0, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Ljava/util/Set;

    .line 45
    .line 46
    if-nez v0, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    iget-object v1, p1, Ll2/a2;->a:Ll2/z1;

    .line 50
    .line 51
    invoke-interface {v0, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    :cond_3
    iget-object v0, p0, Ljp/uf;->j:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v0, Landroidx/collection/r0;

    .line 57
    .line 58
    if-eqz v0, :cond_5

    .line 59
    .line 60
    invoke-virtual {v0, p1}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_4

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    :goto_1
    return-void

    .line 68
    :cond_5
    :goto_2
    iget-object p0, p0, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 69
    .line 70
    check-cast p0, Ln2/b;

    .line 71
    .line 72
    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public g(Ljava/util/Set;Lw2/b;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljp/uf;->a()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljp/uf;->a:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Ljp/uf;->b:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method
