.class public final Ll2/y1;
.super Ll2/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final A:Ljava/util/concurrent/atomic/AtomicReference;

.field public static final z:Lyy0/c2;


# instance fields
.field public a:J

.field public final b:Ll2/f;

.field public final c:Ljava/lang/Object;

.field public d:Lvy0/i1;

.field public e:Ljava/lang/Throwable;

.field public final f:Ljava/util/ArrayList;

.field public g:Ljava/lang/Object;

.field public h:Landroidx/collection/r0;

.field public final i:Ln2/b;

.field public final j:Ljava/util/ArrayList;

.field public final k:Ljava/util/ArrayList;

.field public final l:Landroidx/collection/q0;

.field public final m:Lvp/y1;

.field public final n:Landroidx/collection/q0;

.field public final o:Landroidx/collection/q0;

.field public p:Ljava/util/ArrayList;

.field public q:Ljava/util/LinkedHashSet;

.field public r:Lvy0/l;

.field public s:Lhu/q;

.field public t:Z

.field public final u:Lyy0/c2;

.field public final v:Lrn/i;

.field public final w:Lvy0/k1;

.field public final x:Lpx0/g;

.field public final y:Ll2/x0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lr2/b;->g:Lr2/b;

    .line 2
    .line 3
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Ll2/y1;->z:Lyy0/c2;

    .line 8
    .line 9
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 10
    .line 11
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ll2/y1;->A:Ljava/util/concurrent/atomic/AtomicReference;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Lpx0/g;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ll2/f;

    .line 5
    .line 6
    new-instance v1, Lh50/q0;

    .line 7
    .line 8
    const/16 v2, 0x16

    .line 9
    .line 10
    invoke-direct {v1, p0, v2}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-direct {v0, v1}, Ll2/f;-><init>(Lay0/a;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ll2/y1;->b:Ll2/f;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/Object;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 24
    .line 25
    new-instance v1, Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v1, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 31
    .line 32
    new-instance v1, Landroidx/collection/r0;

    .line 33
    .line 34
    invoke-direct {v1}, Landroidx/collection/r0;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 38
    .line 39
    new-instance v1, Ln2/b;

    .line 40
    .line 41
    const/16 v2, 0x10

    .line 42
    .line 43
    new-array v2, v2, [Ll2/a0;

    .line 44
    .line 45
    invoke-direct {v1, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iput-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 49
    .line 50
    new-instance v1, Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v1, p0, Ll2/y1;->j:Ljava/util/ArrayList;

    .line 56
    .line 57
    new-instance v1, Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object v1, p0, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 63
    .line 64
    new-instance v1, Landroidx/collection/q0;

    .line 65
    .line 66
    invoke-direct {v1}, Landroidx/collection/q0;-><init>()V

    .line 67
    .line 68
    .line 69
    iput-object v1, p0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 70
    .line 71
    new-instance v1, Lvp/y1;

    .line 72
    .line 73
    const/16 v2, 0xe

    .line 74
    .line 75
    invoke-direct {v1, v2}, Lvp/y1;-><init>(I)V

    .line 76
    .line 77
    .line 78
    iput-object v1, p0, Ll2/y1;->m:Lvp/y1;

    .line 79
    .line 80
    new-instance v1, Landroidx/collection/q0;

    .line 81
    .line 82
    invoke-direct {v1}, Landroidx/collection/q0;-><init>()V

    .line 83
    .line 84
    .line 85
    iput-object v1, p0, Ll2/y1;->n:Landroidx/collection/q0;

    .line 86
    .line 87
    new-instance v1, Landroidx/collection/q0;

    .line 88
    .line 89
    invoke-direct {v1}, Landroidx/collection/q0;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object v1, p0, Ll2/y1;->o:Landroidx/collection/q0;

    .line 93
    .line 94
    sget-object v1, Ll2/w1;->f:Ll2/w1;

    .line 95
    .line 96
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    iput-object v1, p0, Ll2/y1;->u:Lyy0/c2;

    .line 101
    .line 102
    new-instance v1, Lrn/i;

    .line 103
    .line 104
    const/16 v2, 0x8

    .line 105
    .line 106
    invoke-direct {v1, v2}, Lrn/i;-><init>(I)V

    .line 107
    .line 108
    .line 109
    iput-object v1, p0, Ll2/y1;->v:Lrn/i;

    .line 110
    .line 111
    sget-object v1, Lvy0/h1;->d:Lvy0/h1;

    .line 112
    .line 113
    invoke-interface {p1, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lvy0/i1;

    .line 118
    .line 119
    new-instance v2, Lvy0/k1;

    .line 120
    .line 121
    invoke-direct {v2, v1}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 122
    .line 123
    .line 124
    new-instance v1, Li40/e1;

    .line 125
    .line 126
    const/16 v3, 0x17

    .line 127
    .line 128
    invoke-direct {v1, p0, v3}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v2, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 132
    .line 133
    .line 134
    iput-object v2, p0, Ll2/y1;->w:Lvy0/k1;

    .line 135
    .line 136
    invoke-interface {p1, v0}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-interface {p1, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    iput-object p1, p0, Ll2/y1;->x:Lpx0/g;

    .line 145
    .line 146
    new-instance p1, Ll2/x0;

    .line 147
    .line 148
    const/16 v0, 0x8

    .line 149
    .line 150
    invoke-direct {p1, v0}, Ll2/x0;-><init>(I)V

    .line 151
    .line 152
    .line 153
    iput-object p1, p0, Ll2/y1;->y:Ll2/x0;

    .line 154
    .line 155
    return-void
.end method

.method public static final B(Ljava/util/ArrayList;Ll2/y1;Ll2/a0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p1, Ll2/y1;->c:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter p0

    .line 7
    :try_start_0
    iget-object p1, p1, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    monitor-exit p0

    .line 20
    return-void

    .line 21
    :cond_0
    :try_start_1
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Ll2/a1;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    const/4 p1, 0x0

    .line 31
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    :catchall_0
    move-exception p1

    .line 33
    monitor-exit p0

    .line 34
    throw p1
.end method

.method public static u(Lv2/b;)V
    .locals 2

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lv2/b;->w()Lv2/p;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v0, v0, Lv2/g;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lv2/b;->c()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    :try_start_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    const-string v1, "Unsupported concurrent change during composition. A state object was modified by composition as well as being modified outside composition."

    .line 16
    .line 17
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    :catchall_0
    move-exception v0

    .line 22
    invoke-virtual {p0}, Lv2/b;->c()V

    .line 23
    .line 24
    .line 25
    throw v0
.end method


# virtual methods
.method public final A(Ll2/a0;)V
    .locals 1

    .line 1
    iget-object p1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p1

    .line 4
    :try_start_0
    iget-object p0, p0, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    if-gtz v0, :cond_0

    .line 11
    .line 12
    monitor-exit p1

    .line 13
    return-void

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    :try_start_1
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ll2/a1;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    monitor-exit p1

    .line 28
    throw p0
.end method

.method public final C(Ljava/util/List;Landroidx/collection/r0;)Ljava/util/List;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    new-instance v2, Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    invoke-direct {v2, v3}, Ljava/util/HashMap;-><init>(I)V

    .line 12
    .line 13
    .line 14
    move-object v3, v1

    .line 15
    check-cast v3, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v5, 0x0

    .line 22
    :goto_0
    if-ge v5, v3, :cond_1

    .line 23
    .line 24
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    move-object v7, v6

    .line 29
    check-cast v7, Ll2/a1;

    .line 30
    .line 31
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/4 v7, 0x0

    .line 35
    invoke-virtual {v2, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    if-nez v8, :cond_0

    .line 40
    .line 41
    new-instance v8, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    :cond_0
    check-cast v8, Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-virtual {v8, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    add-int/lit8 v5, v5, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_11

    .line 70
    .line 71
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    check-cast v3, Ljava/util/Map$Entry;

    .line 76
    .line 77
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    check-cast v5, Ll2/a0;

    .line 82
    .line 83
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    check-cast v3, Ljava/util/List;

    .line 88
    .line 89
    iget-object v6, v5, Ll2/a0;->y:Ll2/t;

    .line 90
    .line 91
    iget-boolean v6, v6, Ll2/t;->F:Z

    .line 92
    .line 93
    if-eqz v6, :cond_2

    .line 94
    .line 95
    const-string v6, "Check failed"

    .line 96
    .line 97
    invoke-static {v6}, Ll2/v;->c(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :cond_2
    new-instance v6, Li40/e1;

    .line 101
    .line 102
    const/16 v7, 0x16

    .line 103
    .line 104
    invoke-direct {v6, v5, v7}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 105
    .line 106
    .line 107
    new-instance v7, Li40/j0;

    .line 108
    .line 109
    const/16 v8, 0x1d

    .line 110
    .line 111
    move-object/from16 v9, p2

    .line 112
    .line 113
    invoke-direct {v7, v8, v5, v9}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    instance-of v10, v8, Lv2/b;

    .line 121
    .line 122
    const/4 v11, 0x0

    .line 123
    if-eqz v10, :cond_3

    .line 124
    .line 125
    check-cast v8, Lv2/b;

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_3
    move-object v8, v11

    .line 129
    :goto_2
    if-eqz v8, :cond_10

    .line 130
    .line 131
    invoke-virtual {v8, v6, v7}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    if-eqz v6, :cond_10

    .line 136
    .line 137
    :try_start_0
    invoke-virtual {v6}, Lv2/f;->j()Lv2/f;

    .line 138
    .line 139
    .line 140
    move-result-object v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 141
    :try_start_1
    iget-object v8, v0, Ll2/y1;->c:Ljava/lang/Object;

    .line 142
    .line 143
    monitor-enter v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 144
    :try_start_2
    new-instance v10, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 147
    .line 148
    .line 149
    move-result v12

    .line 150
    invoke-direct {v10, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 151
    .line 152
    .line 153
    move-object v12, v3

    .line 154
    check-cast v12, Ljava/util/Collection;

    .line 155
    .line 156
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 157
    .line 158
    .line 159
    move-result v12

    .line 160
    const/4 v13, 0x0

    .line 161
    :goto_3
    if-ge v13, v12, :cond_4

    .line 162
    .line 163
    invoke-interface {v3, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v14

    .line 167
    check-cast v14, Ll2/a1;

    .line 168
    .line 169
    iget-object v15, v0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 170
    .line 171
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    invoke-static {v15}, Ln2/a;->a(Landroidx/collection/q0;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v15

    .line 178
    move-object/from16 v16, v15

    .line 179
    .line 180
    check-cast v16, Ll2/a1;

    .line 181
    .line 182
    new-instance v4, Llx0/l;

    .line 183
    .line 184
    invoke-direct {v4, v14, v15}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v10, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    add-int/lit8 v13, v13, 0x1

    .line 191
    .line 192
    goto :goto_3

    .line 193
    :catchall_0
    move-exception v0

    .line 194
    goto/16 :goto_d

    .line 195
    .line 196
    :cond_4
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 197
    .line 198
    .line 199
    move-result v3

    .line 200
    const/4 v4, 0x0

    .line 201
    :goto_4
    if-ge v4, v3, :cond_8

    .line 202
    .line 203
    invoke-virtual {v10, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v12

    .line 207
    check-cast v12, Llx0/l;

    .line 208
    .line 209
    iget-object v13, v12, Llx0/l;->e:Ljava/lang/Object;

    .line 210
    .line 211
    if-nez v13, :cond_7

    .line 212
    .line 213
    iget-object v13, v0, Ll2/y1;->m:Lvp/y1;

    .line 214
    .line 215
    iget-object v12, v12, Llx0/l;->d:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast v12, Ll2/a1;

    .line 218
    .line 219
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 220
    .line 221
    .line 222
    iget-object v12, v13, Lvp/y1;->e:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast v12, Landroidx/collection/q0;

    .line 225
    .line 226
    invoke-virtual {v12, v11}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v12

    .line 230
    if-eqz v12, :cond_7

    .line 231
    .line 232
    new-instance v3, Ljava/util/ArrayList;

    .line 233
    .line 234
    const/16 v4, 0xa

    .line 235
    .line 236
    invoke-static {v10, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 237
    .line 238
    .line 239
    move-result v4

    .line 240
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    :goto_5
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    if-eqz v10, :cond_6

    .line 252
    .line 253
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    check-cast v10, Llx0/l;

    .line 258
    .line 259
    iget-object v11, v10, Llx0/l;->e:Ljava/lang/Object;

    .line 260
    .line 261
    if-nez v11, :cond_5

    .line 262
    .line 263
    iget-object v11, v0, Ll2/y1;->m:Lvp/y1;

    .line 264
    .line 265
    iget-object v12, v10, Llx0/l;->d:Ljava/lang/Object;

    .line 266
    .line 267
    check-cast v12, Ll2/a1;

    .line 268
    .line 269
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 270
    .line 271
    .line 272
    iget-object v12, v11, Lvp/y1;->e:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v12, Landroidx/collection/q0;

    .line 275
    .line 276
    invoke-static {v12}, Ln2/a;->a(Landroidx/collection/q0;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v13

    .line 280
    check-cast v13, Ll2/c1;

    .line 281
    .line 282
    invoke-virtual {v12}, Landroidx/collection/q0;->i()Z

    .line 283
    .line 284
    .line 285
    move-result v12

    .line 286
    if-eqz v12, :cond_5

    .line 287
    .line 288
    iget-object v11, v11, Lvp/y1;->f:Ljava/lang/Object;

    .line 289
    .line 290
    check-cast v11, Landroidx/collection/q0;

    .line 291
    .line 292
    invoke-virtual {v11}, Landroidx/collection/q0;->a()V

    .line 293
    .line 294
    .line 295
    :cond_5
    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 296
    .line 297
    .line 298
    goto :goto_5

    .line 299
    :cond_6
    move-object v10, v3

    .line 300
    goto :goto_6

    .line 301
    :cond_7
    add-int/lit8 v4, v4, 0x1

    .line 302
    .line 303
    goto :goto_4

    .line 304
    :cond_8
    :goto_6
    :try_start_3
    monitor-exit v8

    .line 305
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 306
    .line 307
    .line 308
    move-result v3

    .line 309
    const/4 v4, 0x0

    .line 310
    :goto_7
    if-ge v4, v3, :cond_f

    .line 311
    .line 312
    invoke-interface {v10, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v8

    .line 316
    check-cast v8, Llx0/l;

    .line 317
    .line 318
    iget-object v8, v8, Llx0/l;->e:Ljava/lang/Object;

    .line 319
    .line 320
    if-nez v8, :cond_9

    .line 321
    .line 322
    add-int/lit8 v4, v4, 0x1

    .line 323
    .line 324
    goto :goto_7

    .line 325
    :cond_9
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 326
    .line 327
    .line 328
    move-result v3

    .line 329
    const/4 v4, 0x0

    .line 330
    :goto_8
    if-ge v4, v3, :cond_f

    .line 331
    .line 332
    invoke-interface {v10, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v8

    .line 336
    check-cast v8, Llx0/l;

    .line 337
    .line 338
    iget-object v8, v8, Llx0/l;->e:Ljava/lang/Object;

    .line 339
    .line 340
    if-eqz v8, :cond_a

    .line 341
    .line 342
    add-int/lit8 v4, v4, 0x1

    .line 343
    .line 344
    goto :goto_8

    .line 345
    :cond_a
    new-instance v3, Ljava/util/ArrayList;

    .line 346
    .line 347
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 348
    .line 349
    .line 350
    move-result v4

    .line 351
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 352
    .line 353
    .line 354
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 355
    .line 356
    .line 357
    move-result v4

    .line 358
    const/4 v8, 0x0

    .line 359
    :goto_9
    if-ge v8, v4, :cond_c

    .line 360
    .line 361
    invoke-interface {v10, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v11

    .line 365
    check-cast v11, Llx0/l;

    .line 366
    .line 367
    iget-object v12, v11, Llx0/l;->e:Ljava/lang/Object;

    .line 368
    .line 369
    if-nez v12, :cond_b

    .line 370
    .line 371
    iget-object v11, v11, Llx0/l;->d:Ljava/lang/Object;

    .line 372
    .line 373
    check-cast v11, Ll2/a1;

    .line 374
    .line 375
    goto :goto_a

    .line 376
    :catchall_1
    move-exception v0

    .line 377
    goto :goto_e

    .line 378
    :cond_b
    :goto_a
    add-int/lit8 v8, v8, 0x1

    .line 379
    .line 380
    goto :goto_9

    .line 381
    :cond_c
    iget-object v4, v0, Ll2/y1;->c:Ljava/lang/Object;

    .line 382
    .line 383
    monitor-enter v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 384
    :try_start_4
    iget-object v8, v0, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 385
    .line 386
    invoke-static {v3, v8}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 387
    .line 388
    .line 389
    :try_start_5
    monitor-exit v4

    .line 390
    new-instance v3, Ljava/util/ArrayList;

    .line 391
    .line 392
    invoke-interface {v10}, Ljava/util/List;->size()I

    .line 393
    .line 394
    .line 395
    move-result v4

    .line 396
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 397
    .line 398
    .line 399
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 400
    .line 401
    .line 402
    move-result v4

    .line 403
    const/4 v8, 0x0

    .line 404
    :goto_b
    if-ge v8, v4, :cond_e

    .line 405
    .line 406
    invoke-interface {v10, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v11

    .line 410
    move-object v12, v11

    .line 411
    check-cast v12, Llx0/l;

    .line 412
    .line 413
    iget-object v12, v12, Llx0/l;->e:Ljava/lang/Object;

    .line 414
    .line 415
    if-eqz v12, :cond_d

    .line 416
    .line 417
    invoke-virtual {v3, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 418
    .line 419
    .line 420
    :cond_d
    add-int/lit8 v8, v8, 0x1

    .line 421
    .line 422
    goto :goto_b

    .line 423
    :cond_e
    move-object v10, v3

    .line 424
    goto :goto_c

    .line 425
    :catchall_2
    move-exception v0

    .line 426
    monitor-exit v4

    .line 427
    throw v0

    .line 428
    :cond_f
    :goto_c
    invoke-virtual {v5, v10}, Ll2/a0;->q(Ljava/util/ArrayList;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 429
    .line 430
    .line 431
    :try_start_6
    invoke-static {v7}, Lv2/f;->q(Lv2/f;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 432
    .line 433
    .line 434
    invoke-static {v6}, Ll2/y1;->u(Lv2/b;)V

    .line 435
    .line 436
    .line 437
    goto/16 :goto_1

    .line 438
    .line 439
    :catchall_3
    move-exception v0

    .line 440
    goto :goto_f

    .line 441
    :goto_d
    :try_start_7
    monitor-exit v8

    .line 442
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 443
    :goto_e
    :try_start_8
    invoke-static {v7}, Lv2/f;->q(Lv2/f;)V

    .line 444
    .line 445
    .line 446
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 447
    :goto_f
    invoke-static {v6}, Ll2/y1;->u(Lv2/b;)V

    .line 448
    .line 449
    .line 450
    throw v0

    .line 451
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 452
    .line 453
    const-string v1, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 454
    .line 455
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    throw v0

    .line 459
    :cond_11
    invoke-virtual {v2}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    check-cast v0, Ljava/lang/Iterable;

    .line 464
    .line 465
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 466
    .line 467
    .line 468
    move-result-object v0

    .line 469
    return-object v0
.end method

.method public final D(Ll2/a0;Landroidx/collection/r0;)Ll2/a0;
    .locals 5

    .line 1
    iget-object v0, p1, Ll2/a0;->y:Ll2/t;

    .line 2
    .line 3
    iget-boolean v0, v0, Ll2/t;->F:Z

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_6

    .line 7
    .line 8
    iget v0, p1, Ll2/a0;->z:I

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    if-ne v0, v2, :cond_0

    .line 12
    .line 13
    return-object v1

    .line 14
    :cond_0
    iget-object p0, p0, Ll2/y1;->q:Ljava/util/LinkedHashSet;

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    invoke-interface {p0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-ne p0, v0, :cond_1

    .line 24
    .line 25
    goto/16 :goto_4

    .line 26
    .line 27
    :cond_1
    new-instance p0, Li40/e1;

    .line 28
    .line 29
    const/16 v2, 0x16

    .line 30
    .line 31
    invoke-direct {p0, p1, v2}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    new-instance v2, Li40/j0;

    .line 35
    .line 36
    const/16 v3, 0x1d

    .line 37
    .line 38
    invoke-direct {v2, v3, p1, p2}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    instance-of v4, v3, Lv2/b;

    .line 46
    .line 47
    if-eqz v4, :cond_2

    .line 48
    .line 49
    check-cast v3, Lv2/b;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    move-object v3, v1

    .line 53
    :goto_0
    if-eqz v3, :cond_5

    .line 54
    .line 55
    invoke-virtual {v3, p0, v2}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    if-eqz p0, :cond_5

    .line 60
    .line 61
    :try_start_0
    invoke-virtual {p0}, Lv2/f;->j()Lv2/f;

    .line 62
    .line 63
    .line 64
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 65
    if-eqz p2, :cond_4

    .line 66
    .line 67
    :try_start_1
    invoke-virtual {p2}, Landroidx/collection/r0;->h()Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-ne v3, v0, :cond_4

    .line 72
    .line 73
    new-instance v3, Li2/t;

    .line 74
    .line 75
    const/16 v4, 0x1d

    .line 76
    .line 77
    invoke-direct {v3, v4, p2, p1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget-object p2, p1, Ll2/a0;->y:Ll2/t;

    .line 81
    .line 82
    iget-boolean v4, p2, Ll2/t;->F:Z

    .line 83
    .line 84
    if-eqz v4, :cond_3

    .line 85
    .line 86
    const-string v4, "Preparing a composition while composing is not supported"

    .line 87
    .line 88
    invoke-static {v4}, Ll2/v;->c(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    :cond_3
    iput-boolean v0, p2, Ll2/t;->F:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 92
    .line 93
    const/4 v0, 0x0

    .line 94
    :try_start_2
    invoke-virtual {v3}, Li2/t;->invoke()Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 95
    .line 96
    .line 97
    :try_start_3
    iput-boolean v0, p2, Ll2/t;->F:Z

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :catchall_0
    move-exception p1

    .line 101
    iput-boolean v0, p2, Ll2/t;->F:Z

    .line 102
    .line 103
    throw p1

    .line 104
    :catchall_1
    move-exception p1

    .line 105
    goto :goto_2

    .line 106
    :cond_4
    :goto_1
    invoke-virtual {p1}, Ll2/a0;->w()Z

    .line 107
    .line 108
    .line 109
    move-result p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 110
    :try_start_4
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 111
    .line 112
    .line 113
    invoke-static {p0}, Ll2/y1;->u(Lv2/b;)V

    .line 114
    .line 115
    .line 116
    if-eqz p2, :cond_6

    .line 117
    .line 118
    return-object p1

    .line 119
    :catchall_2
    move-exception p1

    .line 120
    goto :goto_3

    .line 121
    :goto_2
    :try_start_5
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V

    .line 122
    .line 123
    .line 124
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 125
    :goto_3
    invoke-static {p0}, Ll2/y1;->u(Lv2/b;)V

    .line 126
    .line 127
    .line 128
    throw p1

    .line 129
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    const-string p1, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 132
    .line 133
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0

    .line 137
    :cond_6
    :goto_4
    return-object v1
.end method

.method public final E(Ljava/lang/Throwable;Ll2/a0;)V
    .locals 3

    .line 1
    sget-object v0, Ll2/y1;->A:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    instance-of v0, p1, Ll2/m;

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 20
    .line 21
    monitor-enter v0

    .line 22
    :try_start_0
    const-string v1, "Error was captured in composition while live edit was enabled."

    .line 23
    .line 24
    const-string v2, "ComposeInternal"

    .line 25
    .line 26
    invoke-static {v2, v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Ll2/y1;->j:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 35
    .line 36
    invoke-virtual {v1}, Ln2/b;->i()V

    .line 37
    .line 38
    .line 39
    new-instance v1, Landroidx/collection/r0;

    .line 40
    .line 41
    invoke-direct {v1}, Landroidx/collection/r0;-><init>()V

    .line 42
    .line 43
    .line 44
    iput-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 45
    .line 46
    iget-object v1, p0, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 49
    .line 50
    .line 51
    iget-object v1, p0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 52
    .line 53
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Ll2/y1;->n:Landroidx/collection/q0;

    .line 57
    .line 58
    invoke-virtual {v1}, Landroidx/collection/q0;->a()V

    .line 59
    .line 60
    .line 61
    new-instance v1, Lhu/q;

    .line 62
    .line 63
    const/16 v2, 0xf

    .line 64
    .line 65
    invoke-direct {v1, p1, v2}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    iput-object v1, p0, Ll2/y1;->s:Lhu/q;

    .line 69
    .line 70
    if-eqz p2, :cond_0

    .line 71
    .line 72
    invoke-virtual {p0, p2}, Ll2/y1;->G(Ll2/a0;)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :catchall_0
    move-exception p0

    .line 77
    goto :goto_1

    .line 78
    :cond_0
    :goto_0
    invoke-virtual {p0}, Ll2/y1;->w()Lvy0/k;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 79
    .line 80
    .line 81
    monitor-exit v0

    .line 82
    return-void

    .line 83
    :goto_1
    monitor-exit v0

    .line 84
    throw p0

    .line 85
    :cond_1
    iget-object p2, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 86
    .line 87
    monitor-enter p2

    .line 88
    :try_start_1
    iget-object v0, p0, Ll2/y1;->s:Lhu/q;

    .line 89
    .line 90
    if-nez v0, :cond_2

    .line 91
    .line 92
    new-instance v0, Lhu/q;

    .line 93
    .line 94
    const/16 v1, 0xf

    .line 95
    .line 96
    invoke-direct {v0, p1, v1}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    iput-object v0, p0, Ll2/y1;->s:Lhu/q;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 100
    .line 101
    monitor-exit p2

    .line 102
    throw p1

    .line 103
    :catchall_1
    move-exception p0

    .line 104
    goto :goto_2

    .line 105
    :cond_2
    :try_start_2
    iget-object p0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Ljava/lang/Throwable;

    .line 108
    .line 109
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 110
    :goto_2
    monitor-exit p2

    .line 111
    throw p0
.end method

.method public final F()Z
    .locals 8

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 5
    .line 6
    invoke-virtual {v1}, Landroidx/collection/r0;->g()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x1

    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v1, :cond_3

    .line 13
    .line 14
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 15
    .line 16
    iget v1, v1, Ln2/b;->f:I

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p0}, Ll2/y1;->x()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_2

    .line 26
    .line 27
    iget-object p0, p0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 28
    .line 29
    invoke-virtual {p0}, Landroidx/collection/q0;->j()Z

    .line 30
    .line 31
    .line 32
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move v2, v3

    .line 37
    :cond_2
    :goto_0
    monitor-exit v0

    .line 38
    return v2

    .line 39
    :cond_3
    :try_start_1
    invoke-virtual {p0}, Ll2/y1;->z()Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-object v4, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 44
    .line 45
    new-instance v5, Ln2/d;

    .line 46
    .line 47
    invoke-direct {v5, v4}, Ln2/d;-><init>(Landroidx/collection/r0;)V

    .line 48
    .line 49
    .line 50
    new-instance v4, Landroidx/collection/r0;

    .line 51
    .line 52
    invoke-direct {v4}, Landroidx/collection/r0;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v4, p0, Ll2/y1;->h:Landroidx/collection/r0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 56
    .line 57
    monitor-exit v0

    .line 58
    :try_start_2
    move-object v0, v1

    .line 59
    check-cast v0, Ljava/util/Collection;

    .line 60
    .line 61
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    move v4, v3

    .line 66
    :goto_1
    if-ge v4, v0, :cond_4

    .line 67
    .line 68
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    check-cast v6, Ll2/a0;

    .line 73
    .line 74
    invoke-virtual {v6, v5}, Ll2/a0;->x(Ln2/d;)V

    .line 75
    .line 76
    .line 77
    iget-object v6, p0, Ll2/y1;->u:Lyy0/c2;

    .line 78
    .line 79
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v6

    .line 83
    check-cast v6, Ll2/w1;

    .line 84
    .line 85
    sget-object v7, Ll2/w1;->e:Ll2/w1;

    .line 86
    .line 87
    invoke-virtual {v6, v7}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 88
    .line 89
    .line 90
    move-result v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 91
    if-lez v6, :cond_4

    .line 92
    .line 93
    add-int/lit8 v4, v4, 0x1

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :catchall_0
    move-exception v0

    .line 97
    goto :goto_3

    .line 98
    :cond_4
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 99
    .line 100
    monitor-enter v0

    .line 101
    :try_start_3
    invoke-virtual {p0}, Ll2/y1;->w()Lvy0/k;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    if-nez v1, :cond_8

    .line 106
    .line 107
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 108
    .line 109
    iget v1, v1, Ln2/b;->f:I

    .line 110
    .line 111
    if-eqz v1, :cond_5

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_5
    invoke-virtual {p0}, Ll2/y1;->x()Z

    .line 115
    .line 116
    .line 117
    move-result v1

    .line 118
    if-nez v1, :cond_7

    .line 119
    .line 120
    iget-object p0, p0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 121
    .line 122
    invoke-virtual {p0}, Landroidx/collection/q0;->j()Z

    .line 123
    .line 124
    .line 125
    move-result p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 126
    if-eqz p0, :cond_6

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_6
    move v2, v3

    .line 130
    :cond_7
    :goto_2
    monitor-exit v0

    .line 131
    return v2

    .line 132
    :cond_8
    :try_start_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 133
    .line 134
    const-string v1, "called outside of runRecomposeAndApplyChanges"

    .line 135
    .line 136
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 140
    :catchall_1
    move-exception p0

    .line 141
    monitor-exit v0

    .line 142
    throw p0

    .line 143
    :goto_3
    iget-object v1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 144
    .line 145
    monitor-enter v1

    .line 146
    :try_start_5
    iget-object p0, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    if-eqz v3, :cond_9

    .line 160
    .line 161
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    invoke-virtual {p0, v3}, Landroidx/collection/r0;->k(Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 166
    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_9
    monitor-exit v1

    .line 170
    throw v0

    .line 171
    :catchall_2
    move-exception p0

    .line 172
    monitor-exit v1

    .line 173
    throw p0

    .line 174
    :catchall_3
    move-exception p0

    .line 175
    monitor-exit v0

    .line 176
    throw p0
.end method

.method public final G(Ll2/a0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->p:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ll2/y1;->p:Ljava/util/ArrayList;

    .line 11
    .line 12
    :cond_0
    invoke-interface {v0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    invoke-interface {v0, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    :cond_1
    iget-object v0, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-eqz p1, :cond_2

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    iput-object p1, p0, Ll2/y1;->g:Ljava/lang/Object;

    .line 31
    .line 32
    :cond_2
    return-void
.end method

.method public final H(Lrx0/i;)Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v3, Ll2/x1;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    invoke-direct {v3, p0, v5}, Ll2/x1;-><init>(Ll2/y1;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p1}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 12
    .line 13
    .line 14
    move-result-object v4

    .line 15
    new-instance v0, Laa/i0;

    .line 16
    .line 17
    const/16 v1, 0xf

    .line 18
    .line 19
    move-object v2, p0

    .line 20
    invoke-direct/range {v0 .. v5}, Laa/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, v2, Ll2/y1;->b:Ll2/f;

    .line 24
    .line 25
    invoke-static {p0, v0, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    if-ne p0, p1, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object p0, v0

    .line 37
    :goto_0
    if-ne p0, p1, :cond_1

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    return-object v0
.end method

.method public final a(Ll2/a0;Lay0/n;)V
    .locals 8

    .line 1
    iget-object v0, p1, Ll2/a0;->y:Ll2/t;

    .line 2
    .line 3
    iget-boolean v0, v0, Ll2/t;->F:Z

    .line 4
    .line 5
    iget-object v1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    iget-object v2, p0, Ll2/y1;->u:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    check-cast v2, Ll2/w1;

    .line 15
    .line 16
    sget-object v3, Ll2/w1;->e:Ll2/w1;

    .line 17
    .line 18
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v4, 0x1

    .line 23
    if-lez v2, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ll2/y1;->z()Ljava/util/List;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-interface {v2, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    xor-int/2addr v4, v2

    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto/16 :goto_6

    .line 37
    .line 38
    :cond_0
    :goto_0
    monitor-exit v1

    .line 39
    :try_start_1
    new-instance v1, Li40/e1;

    .line 40
    .line 41
    const/16 v2, 0x16

    .line 42
    .line 43
    invoke-direct {v1, p1, v2}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    new-instance v2, Li40/j0;

    .line 47
    .line 48
    const/16 v5, 0x1d

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    invoke-direct {v2, v5, p1, v6}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    instance-of v7, v5, Lv2/b;

    .line 59
    .line 60
    if-eqz v7, :cond_1

    .line 61
    .line 62
    check-cast v5, Lv2/b;

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    move-object v5, v6

    .line 66
    :goto_1
    if-eqz v5, :cond_5

    .line 67
    .line 68
    invoke-virtual {v5, v1, v2}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 69
    .line 70
    .line 71
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 72
    if-eqz v1, :cond_5

    .line 73
    .line 74
    :try_start_2
    invoke-virtual {v1}, Lv2/f;->j()Lv2/f;

    .line 75
    .line 76
    .line 77
    move-result-object v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    .line 78
    :try_start_3
    invoke-virtual {p1, p2}, Ll2/a0;->j(Lay0/n;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_6

    .line 79
    .line 80
    .line 81
    :try_start_4
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 82
    .line 83
    .line 84
    :try_start_5
    invoke-static {v1}, Ll2/y1;->u(Lv2/b;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 85
    .line 86
    .line 87
    iget-object p2, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 88
    .line 89
    monitor-enter p2

    .line 90
    :try_start_6
    iget-object v1, p0, Ll2/y1;->u:Lyy0/c2;

    .line 91
    .line 92
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Ll2/w1;

    .line 97
    .line 98
    invoke-virtual {v1, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-lez v1, :cond_2

    .line 103
    .line 104
    invoke-virtual {p0}, Ll2/y1;->z()Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-interface {v1, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_2

    .line 113
    .line 114
    iget-object v1, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 115
    .line 116
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    iput-object v6, p0, Ll2/y1;->g:Ljava/lang/Object;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :catchall_1
    move-exception p0

    .line 123
    goto :goto_3

    .line 124
    :cond_2
    :goto_2
    monitor-exit p2

    .line 125
    if-nez v0, :cond_3

    .line 126
    .line 127
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 128
    .line 129
    .line 130
    move-result-object p2

    .line 131
    invoke-virtual {p2}, Lv2/f;->m()V

    .line 132
    .line 133
    .line 134
    :cond_3
    :try_start_7
    invoke-virtual {p0, p1}, Ll2/y1;->A(Ll2/a0;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 135
    .line 136
    .line 137
    :try_start_8
    invoke-virtual {p1}, Ll2/a0;->d()V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1}, Ll2/a0;->f()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 141
    .line 142
    .line 143
    if-nez v0, :cond_4

    .line 144
    .line 145
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-virtual {p0}, Lv2/f;->m()V

    .line 150
    .line 151
    .line 152
    :cond_4
    return-void

    .line 153
    :catchall_2
    move-exception p1

    .line 154
    invoke-virtual {p0, p1, v6}, Ll2/y1;->E(Ljava/lang/Throwable;Ll2/a0;)V

    .line 155
    .line 156
    .line 157
    return-void

    .line 158
    :catchall_3
    move-exception p2

    .line 159
    invoke-virtual {p0, p2, p1}, Ll2/y1;->E(Ljava/lang/Throwable;Ll2/a0;)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :goto_3
    monitor-exit p2

    .line 164
    throw p0

    .line 165
    :catchall_4
    move-exception p2

    .line 166
    goto :goto_5

    .line 167
    :catchall_5
    move-exception p2

    .line 168
    goto :goto_4

    .line 169
    :catchall_6
    move-exception p2

    .line 170
    :try_start_9
    invoke-static {v2}, Lv2/f;->q(Lv2/f;)V

    .line 171
    .line 172
    .line 173
    throw p2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_5

    .line 174
    :goto_4
    :try_start_a
    invoke-static {v1}, Ll2/y1;->u(Lv2/b;)V

    .line 175
    .line 176
    .line 177
    throw p2

    .line 178
    :cond_5
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 179
    .line 180
    const-string v0, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 181
    .line 182
    invoke-direct {p2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw p2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 186
    :goto_5
    if-eqz v4, :cond_6

    .line 187
    .line 188
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 189
    .line 190
    monitor-enter v0

    .line 191
    monitor-exit v0

    .line 192
    :cond_6
    invoke-virtual {p0, p2, p1}, Ll2/y1;->E(Ljava/lang/Throwable;Ll2/a0;)V

    .line 193
    .line 194
    .line 195
    return-void

    .line 196
    :goto_6
    monitor-exit v1

    .line 197
    throw p0
.end method

.method public final b(Ll2/a0;Lt0/c;Lay0/n;)Landroidx/collection/r0;
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/y1;->v:Lrn/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    iget-object v2, p1, Ll2/a0;->s:Lt0/c;

    .line 5
    .line 6
    iput-object p2, p1, Ll2/a0;->s:Lt0/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    :try_start_1
    invoke-virtual {p0, p1, p3}, Ll2/y1;->a(Ll2/a0;Lay0/n;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lrn/i;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Landroidx/collection/r0;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object p0, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 21
    .line 22
    const-string p2, "null cannot be cast to non-null type androidx.collection.ScatterSet<E of androidx.collection.ScatterSetKt.emptyScatterSet>"

    .line 23
    .line 24
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 25
    .line 26
    .line 27
    :goto_0
    :try_start_2
    iput-object v2, p1, Ll2/a0;->s:Lt0/c;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :catchall_1
    move-exception p0

    .line 36
    :try_start_3
    iput-object v2, p1, Ll2/a0;->s:Lt0/c;

    .line 37
    .line 38
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 39
    :goto_1
    invoke-virtual {v0, v1}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public final d()Z
    .locals 0

    .line 1
    sget-object p0, Ll2/y1;->A:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final f()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final g()J
    .locals 2

    .line 1
    const/16 p0, 0x3e8

    .line 2
    .line 3
    int-to-long v0, p0

    .line 4
    return-wide v0
.end method

.method public final h()Ll2/w;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final j()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/y1;->x:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(Ll2/a0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ln2/b;->j(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 13
    .line 14
    invoke-virtual {v1, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ll2/y1;->w()Lvy0/k;

    .line 18
    .line 19
    .line 20
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    :goto_0
    monitor-exit v0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    check-cast p0, Lvy0/l;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    return-void

    .line 36
    :goto_1
    monitor-exit v0

    .line 37
    throw p0
.end method

.method public final l(Ll2/a1;)Ll2/z0;
    .locals 1

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Ll2/y1;->n:Landroidx/collection/q0;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ll2/z0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0

    .line 16
    throw p0
.end method

.method public final m(Ll2/a0;Lt0/c;Landroidx/collection/r0;)Landroidx/collection/r0;
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/y1;->v:Lrn/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Ll2/y1;->F()Z

    .line 5
    .line 6
    .line 7
    new-instance v2, Ln2/d;

    .line 8
    .line 9
    invoke-direct {v2, p3}, Ln2/d;-><init>(Landroidx/collection/r0;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, v2}, Ll2/a0;->x(Ln2/d;)V

    .line 13
    .line 14
    .line 15
    iget-object p3, p1, Ll2/a0;->s:Lt0/c;

    .line 16
    .line 17
    iput-object p2, p1, Ll2/a0;->s:Lt0/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 18
    .line 19
    :try_start_1
    invoke-virtual {p0, p1, v1}, Ll2/y1;->D(Ll2/a0;Landroidx/collection/r0;)Ll2/a0;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ll2/y1;->A(Ll2/a0;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2}, Ll2/a0;->d()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2}, Ll2/a0;->f()V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_2

    .line 37
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lrn/i;->get()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Landroidx/collection/r0;

    .line 42
    .line 43
    if-eqz p0, :cond_1

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    sget-object p0, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 47
    .line 48
    const-string p2, "null cannot be cast to non-null type androidx.collection.ScatterSet<E of androidx.collection.ScatterSetKt.emptyScatterSet>"

    .line 49
    .line 50
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    .line 52
    .line 53
    :goto_1
    :try_start_2
    iput-object p3, p1, Ll2/a0;->s:Lt0/c;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object p0

    .line 59
    :catchall_1
    move-exception p0

    .line 60
    goto :goto_3

    .line 61
    :goto_2
    :try_start_3
    iput-object p3, p1, Ll2/a0;->s:Lt0/c;

    .line 62
    .line 63
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 64
    :goto_3
    invoke-virtual {v0, v1}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    throw p0
.end method

.method public final n(Ljava/util/Set;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final p(Ll2/u1;)V
    .locals 1

    .line 1
    iget-object p0, p0, Ll2/y1;->v:Lrn/i;

    .line 2
    .line 3
    invoke-virtual {p0}, Lrn/i;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroidx/collection/r0;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object v0, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 12
    .line 13
    new-instance v0, Landroidx/collection/r0;

    .line 14
    .line 15
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {v0, p1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final q(Ll2/a0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->q:Ljava/util/LinkedHashSet;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v1, p0, Ll2/y1;->q:Ljava/util/LinkedHashSet;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-void

    .line 23
    :goto_1
    monitor-exit v0

    .line 24
    throw p0
.end method

.method public final t(Ll2/a0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    iput-object v1, p0, Ll2/y1;->g:Ljava/lang/Object;

    .line 14
    .line 15
    :cond_0
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 16
    .line 17
    invoke-virtual {v1, p1}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Ll2/y1;->j:Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    .line 25
    monitor-exit v0

    .line 26
    return-void

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    monitor-exit v0

    .line 29
    throw p0
.end method

.method public final v()V
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->u:Lyy0/c2;

    .line 5
    .line 6
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Ll2/w1;

    .line 11
    .line 12
    sget-object v2, Ll2/w1;->h:Ll2/w1;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/4 v2, 0x0

    .line 19
    if-ltz v1, :cond_0

    .line 20
    .line 21
    iget-object v1, p0, Ll2/y1;->u:Lyy0/c2;

    .line 22
    .line 23
    sget-object v3, Ll2/w1;->e:Ll2/w1;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    :goto_0
    monitor-exit v0

    .line 35
    iget-object p0, p0, Ll2/y1;->w:Lvy0/k1;

    .line 36
    .line 37
    invoke-virtual {p0, v2}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :goto_1
    monitor-exit v0

    .line 42
    throw p0
.end method

.method public final w()Lvy0/k;
    .locals 6

    .line 1
    iget-object v0, p0, Ll2/y1;->u:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ll2/w1;

    .line 8
    .line 9
    sget-object v2, Ll2/w1;->e:Ll2/w1;

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    iget-object v2, p0, Ll2/y1;->k:Ljava/util/ArrayList;

    .line 16
    .line 17
    iget-object v3, p0, Ll2/y1;->j:Ljava/util/ArrayList;

    .line 18
    .line 19
    iget-object v4, p0, Ll2/y1;->i:Ln2/b;

    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    if-gtz v1, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0}, Ll2/y1;->z()Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Ljava/lang/Iterable;

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Ll2/a0;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    iget-object v0, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 50
    .line 51
    .line 52
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 53
    .line 54
    iput-object v0, p0, Ll2/y1;->g:Ljava/lang/Object;

    .line 55
    .line 56
    new-instance v0, Landroidx/collection/r0;

    .line 57
    .line 58
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 59
    .line 60
    .line 61
    iput-object v0, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 62
    .line 63
    invoke-virtual {v4}, Ln2/b;->i()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 70
    .line 71
    .line 72
    iput-object v5, p0, Ll2/y1;->p:Ljava/util/ArrayList;

    .line 73
    .line 74
    iget-object v0, p0, Ll2/y1;->r:Lvy0/l;

    .line 75
    .line 76
    if-eqz v0, :cond_1

    .line 77
    .line 78
    invoke-virtual {v0, v5}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 79
    .line 80
    .line 81
    :cond_1
    iput-object v5, p0, Ll2/y1;->r:Lvy0/l;

    .line 82
    .line 83
    iput-object v5, p0, Ll2/y1;->s:Lhu/q;

    .line 84
    .line 85
    return-object v5

    .line 86
    :cond_2
    iget-object v1, p0, Ll2/y1;->s:Lhu/q;

    .line 87
    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    sget-object v1, Ll2/w1;->f:Ll2/w1;

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_3
    iget-object v1, p0, Ll2/y1;->d:Lvy0/i1;

    .line 94
    .line 95
    if-nez v1, :cond_5

    .line 96
    .line 97
    new-instance v1, Landroidx/collection/r0;

    .line 98
    .line 99
    invoke-direct {v1}, Landroidx/collection/r0;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 103
    .line 104
    invoke-virtual {v4}, Ln2/b;->i()V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p0}, Ll2/y1;->x()Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_4

    .line 112
    .line 113
    sget-object v1, Ll2/w1;->g:Ll2/w1;

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    sget-object v1, Ll2/w1;->f:Ll2/w1;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    iget v1, v4, Ln2/b;->f:I

    .line 120
    .line 121
    if-eqz v1, :cond_6

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_6
    iget-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 125
    .line 126
    invoke-virtual {v1}, Landroidx/collection/r0;->h()Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-nez v1, :cond_8

    .line 131
    .line 132
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-eqz v1, :cond_8

    .line 137
    .line 138
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-eqz v1, :cond_8

    .line 143
    .line 144
    invoke-virtual {p0}, Ll2/y1;->x()Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_8

    .line 149
    .line 150
    iget-object v1, p0, Ll2/y1;->l:Landroidx/collection/q0;

    .line 151
    .line 152
    invoke-virtual {v1}, Landroidx/collection/q0;->j()Z

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    if-eqz v1, :cond_7

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_7
    sget-object v1, Ll2/w1;->h:Ll2/w1;

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_8
    :goto_1
    sget-object v1, Ll2/w1;->i:Ll2/w1;

    .line 163
    .line 164
    :goto_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v0, v5, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    sget-object v0, Ll2/w1;->i:Ll2/w1;

    .line 171
    .line 172
    if-ne v1, v0, :cond_9

    .line 173
    .line 174
    iget-object v0, p0, Ll2/y1;->r:Lvy0/l;

    .line 175
    .line 176
    iput-object v5, p0, Ll2/y1;->r:Lvy0/l;

    .line 177
    .line 178
    return-object v0

    .line 179
    :cond_9
    return-object v5
.end method

.method public final x()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Ll2/y1;->t:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Ll2/y1;->b:Ll2/f;

    .line 6
    .line 7
    iget-object p0, p0, Ll2/f;->g:Lt2/a;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const v0, 0x7ffffff

    .line 14
    .line 15
    .line 16
    and-int/2addr p0, v0

    .line 17
    if-lez p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final y()Z
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Ll2/y1;->h:Landroidx/collection/r0;

    .line 5
    .line 6
    invoke-virtual {v1}, Landroidx/collection/r0;->h()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-nez v1, :cond_2

    .line 11
    .line 12
    iget-object v1, p0, Ll2/y1;->i:Ln2/b;

    .line 13
    .line 14
    iget v1, v1, Ln2/b;->f:I

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {p0}, Ll2/y1;->x()Z

    .line 20
    .line 21
    .line 22
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 p0, 0x0

    .line 27
    goto :goto_1

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_2

    .line 30
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 31
    :goto_1
    monitor-exit v0

    .line 32
    return p0

    .line 33
    :goto_2
    monitor-exit v0

    .line 34
    throw p0
.end method

.method public final z()Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/y1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget-object v0, p0, Ll2/y1;->f:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    move-object v0, v1

    .line 23
    :goto_0
    iput-object v0, p0, Ll2/y1;->g:Ljava/lang/Object;

    .line 24
    .line 25
    return-object v0
.end method
