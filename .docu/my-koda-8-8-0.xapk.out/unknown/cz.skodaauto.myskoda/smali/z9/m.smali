.class public final Lz9/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lst/b;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/c2;

.field public d:Z

.field public final e:Lyy0/l1;

.field public final f:Lyy0/l1;

.field public final g:Lz9/j0;

.field public final synthetic h:Lz9/y;


# direct methods
.method public constructor <init>(Lz9/y;Lz9/j0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "navigator"

    .line 5
    .line 6
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lz9/m;->h:Lz9/y;

    .line 10
    .line 11
    new-instance p1, Lst/b;

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    invoke-direct {p1, v0}, Lst/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lz9/m;->a:Lst/b;

    .line 18
    .line 19
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 20
    .line 21
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lz9/m;->b:Lyy0/c2;

    .line 26
    .line 27
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 28
    .line 29
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, Lz9/m;->c:Lyy0/c2;

    .line 34
    .line 35
    new-instance v1, Lyy0/l1;

    .line 36
    .line 37
    invoke-direct {v1, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 38
    .line 39
    .line 40
    iput-object v1, p0, Lz9/m;->e:Lyy0/l1;

    .line 41
    .line 42
    new-instance p1, Lyy0/l1;

    .line 43
    .line 44
    invoke-direct {p1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lz9/m;->f:Lyy0/l1;

    .line 48
    .line 49
    iput-object p2, p0, Lz9/m;->g:Lz9/j0;

    .line 50
    .line 51
    return-void
.end method


# virtual methods
.method public final a(Lz9/k;)V
    .locals 2

    .line 1
    const-string v0, "backStackEntry"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz9/m;->a:Lst/b;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    iget-object p0, p0, Lz9/m;->b:Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-static {v1, p1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-virtual {p0, v1, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    monitor-exit v0

    .line 29
    return-void

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    monitor-exit v0

    .line 32
    throw p0
.end method

.method public final b(Lz9/u;Landroid/os/Bundle;)Lz9/k;
    .locals 2

    .line 1
    iget-object p0, p0, Lz9/m;->h:Lz9/y;

    .line 2
    .line 3
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lca/g;->a:Lz9/y;

    .line 9
    .line 10
    iget-object v0, v0, Lz9/y;->c:Lca/d;

    .line 11
    .line 12
    invoke-virtual {p0}, Lca/g;->j()Landroidx/lifecycle/q;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iget-object p0, p0, Lca/g;->o:Lz9/n;

    .line 17
    .line 18
    invoke-static {v0, p1, p2, v1, p0}, Lz9/h0;->a(Lca/d;Lz9/u;Landroid/os/Bundle;Landroidx/lifecycle/q;Lz9/n;)Lz9/k;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final c(Lz9/k;)V
    .locals 8

    .line 1
    const-string v0, "entry"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz9/m;->h:Lz9/y;

    .line 7
    .line 8
    iget-object v0, v0, Lz9/y;->b:Lca/g;

    .line 9
    .line 10
    iget-object v1, v0, Lca/g;->h:Lyy0/c2;

    .line 11
    .line 12
    iget-object v2, p1, Lz9/k;->i:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v3, v0, Lca/g;->w:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v3, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 21
    .line 22
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    iget-object v5, p0, Lz9/m;->c:Lyy0/c2;

    .line 27
    .line 28
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    check-cast v6, Ljava/util/Set;

    .line 33
    .line 34
    invoke-static {v6, p1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const/4 v7, 0x0

    .line 39
    invoke-virtual {v5, v7, v6}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    invoke-interface {v3, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    iget-object v3, v0, Lca/g;->f:Lmx0/l;

    .line 46
    .line 47
    invoke-virtual {v3, p1}, Lmx0/l;->contains(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    if-nez v5, :cond_5

    .line 52
    .line 53
    invoke-virtual {v0, p1}, Lca/g;->u(Lz9/k;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p1, Lz9/k;->k:Lca/c;

    .line 57
    .line 58
    iget-object p0, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 59
    .line 60
    iget-object p0, p0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 61
    .line 62
    sget-object v5, Landroidx/lifecycle/q;->f:Landroidx/lifecycle/q;

    .line 63
    .line 64
    invoke-virtual {p0, v5}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-ltz p0, :cond_0

    .line 69
    .line 70
    sget-object p0, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 71
    .line 72
    invoke-virtual {p1, p0}, Lz9/k;->a(Landroidx/lifecycle/q;)V

    .line 73
    .line 74
    .line 75
    :cond_0
    invoke-virtual {v3}, Lmx0/l;->isEmpty()Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    invoke-virtual {v3}, Ljava/util/AbstractList;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    if-eqz p1, :cond_3

    .line 91
    .line 92
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    check-cast p1, Lz9/k;

    .line 97
    .line 98
    iget-object p1, p1, Lz9/k;->i:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-eqz p1, :cond_2

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_3
    :goto_0
    if-nez v4, :cond_4

    .line 108
    .line 109
    iget-object p0, v0, Lca/g;->o:Lz9/n;

    .line 110
    .line 111
    if-eqz p0, :cond_4

    .line 112
    .line 113
    const-string p1, "backStackEntryId"

    .line 114
    .line 115
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    iget-object p0, p0, Lz9/n;->d:Ljava/util/LinkedHashMap;

    .line 119
    .line 120
    invoke-interface {p0, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    check-cast p0, Landroidx/lifecycle/h1;

    .line 125
    .line 126
    if-eqz p0, :cond_4

    .line 127
    .line 128
    invoke-virtual {p0}, Landroidx/lifecycle/h1;->a()V

    .line 129
    .line 130
    .line 131
    :cond_4
    :goto_1
    invoke-virtual {v0}, Lca/g;->v()V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v0}, Lca/g;->s()Ljava/util/ArrayList;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1, v7, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :cond_5
    iget-boolean p0, p0, Lz9/m;->d:Z

    .line 146
    .line 147
    if-nez p0, :cond_6

    .line 148
    .line 149
    invoke-virtual {v0}, Lca/g;->v()V

    .line 150
    .line 151
    .line 152
    iget-object p0, v0, Lca/g;->g:Lyy0/c2;

    .line 153
    .line 154
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    invoke-virtual {p0, v7, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0}, Lca/g;->s()Ljava/util/ArrayList;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v1, v7, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    :cond_6
    return-void
.end method

.method public final d(Lz9/k;Z)V
    .locals 5

    .line 1
    iget-object v0, p0, Lz9/m;->h:Lz9/y;

    .line 2
    .line 3
    iget-object v0, v0, Lz9/y;->b:Lca/g;

    .line 4
    .line 5
    new-instance v1, Lyj/b;

    .line 6
    .line 7
    invoke-direct {v1, p0, p1, p2}, Lyj/b;-><init>(Lz9/m;Lz9/k;Z)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget-object v2, v0, Lca/g;->s:Lz9/k0;

    .line 14
    .line 15
    iget-object v3, p1, Lz9/k;->e:Lz9/u;

    .line 16
    .line 17
    iget-object v3, v3, Lz9/u;->d:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v2, v3}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    iget-object v4, v0, Lca/g;->w:Ljava/util/LinkedHashMap;

    .line 28
    .line 29
    invoke-interface {v4, p1, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lz9/m;->g:Lz9/j0;

    .line 33
    .line 34
    invoke-virtual {v2, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_3

    .line 39
    .line 40
    iget-object p0, v0, Lca/g;->v:Lca/e;

    .line 41
    .line 42
    if-eqz p0, :cond_0

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lca/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    iget-object p0, v0, Lca/g;->f:Lmx0/l;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lmx0/l;->indexOf(Ljava/lang/Object;)I

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-gez p2, :cond_1

    .line 58
    .line 59
    new-instance p0, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string p2, "Ignoring pop of "

    .line 62
    .line 63
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string p1, " as it was not found on the current back stack"

    .line 70
    .line 71
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    const-string p1, "message"

    .line 79
    .line 80
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const-string p1, "NavController"

    .line 84
    .line 85
    invoke-static {p1, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :cond_1
    const/4 v2, 0x1

    .line 90
    add-int/2addr p2, v2

    .line 91
    iget v3, p0, Lmx0/l;->f:I

    .line 92
    .line 93
    if-eq p2, v3, :cond_2

    .line 94
    .line 95
    invoke-virtual {p0, p2}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lz9/k;

    .line 100
    .line 101
    iget-object p0, p0, Lz9/k;->e:Lz9/u;

    .line 102
    .line 103
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 104
    .line 105
    iget p0, p0, Lca/j;->a:I

    .line 106
    .line 107
    const/4 p2, 0x0

    .line 108
    invoke-virtual {v0, p0, v2, p2}, Lca/g;->o(IZZ)Z

    .line 109
    .line 110
    .line 111
    :cond_2
    invoke-static {v0, p1}, Lca/g;->r(Lca/g;Lz9/k;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    iget-object p0, v0, Lca/g;->b:Lle/a;

    .line 118
    .line 119
    invoke-virtual {p0}, Lle/a;->invoke()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0}, Lca/g;->b()Z

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    :cond_3
    iget-object p0, v0, Lca/g;->t:Ljava/util/LinkedHashMap;

    .line 127
    .line 128
    invoke-virtual {p0, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    check-cast p0, Lz9/m;

    .line 136
    .line 137
    invoke-virtual {p0, p1, p2}, Lz9/m;->d(Lz9/k;Z)V

    .line 138
    .line 139
    .line 140
    return-void
.end method

.method public final e(Lz9/k;Z)V
    .locals 7

    .line 1
    iget-object v0, p0, Lz9/m;->c:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/Iterable;

    .line 8
    .line 9
    instance-of v2, v1, Ljava/util/Collection;

    .line 10
    .line 11
    iget-object v3, p0, Lz9/m;->e:Lyy0/l1;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Ljava/util/Collection;

    .line 17
    .line 18
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    :cond_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_5

    .line 34
    .line 35
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lz9/k;

    .line 40
    .line 41
    if-ne v2, p1, :cond_1

    .line 42
    .line 43
    iget-object v1, v3, Lyy0/l1;->d:Lyy0/a2;

    .line 44
    .line 45
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Ljava/lang/Iterable;

    .line 50
    .line 51
    instance-of v2, v1, Ljava/util/Collection;

    .line 52
    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    move-object v2, v1

    .line 56
    check-cast v2, Ljava/util/Collection;

    .line 57
    .line 58
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_2

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    :cond_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_4

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lz9/k;

    .line 80
    .line 81
    if-ne v2, p1, :cond_3

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    :goto_0
    return-void

    .line 85
    :cond_5
    :goto_1
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Ljava/util/Set;

    .line 90
    .line 91
    invoke-static {v1, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    const/4 v2, 0x0

    .line 96
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    iget-object v1, v3, Lyy0/l1;->d:Lyy0/a2;

    .line 100
    .line 101
    iget-object v3, v3, Lyy0/l1;->d:Lyy0/a2;

    .line 102
    .line 103
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    check-cast v1, Ljava/util/List;

    .line 108
    .line 109
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    invoke-interface {v1, v4}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    :cond_6
    invoke-interface {v1}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 118
    .line 119
    .line 120
    move-result v4

    .line 121
    if-eqz v4, :cond_7

    .line 122
    .line 123
    invoke-interface {v1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    move-object v5, v4

    .line 128
    check-cast v5, Lz9/k;

    .line 129
    .line 130
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    if-nez v6, :cond_6

    .line 135
    .line 136
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v6

    .line 140
    check-cast v6, Ljava/util/List;

    .line 141
    .line 142
    invoke-interface {v6, v5}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 143
    .line 144
    .line 145
    move-result v5

    .line 146
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    check-cast v6, Ljava/util/List;

    .line 151
    .line 152
    invoke-interface {v6, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 153
    .line 154
    .line 155
    move-result v6

    .line 156
    if-ge v5, v6, :cond_6

    .line 157
    .line 158
    goto :goto_2

    .line 159
    :cond_7
    move-object v4, v2

    .line 160
    :goto_2
    check-cast v4, Lz9/k;

    .line 161
    .line 162
    if-eqz v4, :cond_8

    .line 163
    .line 164
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    check-cast v1, Ljava/util/Set;

    .line 169
    .line 170
    invoke-static {v1, v4}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    :cond_8
    invoke-virtual {p0, p1, p2}, Lz9/m;->d(Lz9/k;Z)V

    .line 178
    .line 179
    .line 180
    return-void
.end method

.method public final f(Lz9/k;)V
    .locals 3

    .line 1
    const-string v0, "backStackEntry"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lz9/m;->h:Lz9/y;

    .line 7
    .line 8
    iget-object v0, v0, Lz9/y;->b:Lca/g;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget-object v1, v0, Lca/g;->s:Lz9/k0;

    .line 14
    .line 15
    iget-object v2, p1, Lz9/k;->e:Lz9/u;

    .line 16
    .line 17
    iget-object v2, v2, Lz9/u;->d:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v1, v2}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget-object v2, p0, Lz9/m;->g:Lz9/j0;

    .line 24
    .line 25
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    iget-object v0, v0, Lca/g;->u:Lay0/k;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lz9/m;->a(Lz9/k;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v0, "Ignoring add of destination "

    .line 45
    .line 46
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, p1, Lz9/k;->e:Lz9/u;

    .line 50
    .line 51
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string p1, " outside of the call to navigate(). "

    .line 55
    .line 56
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string p1, "message"

    .line 64
    .line 65
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string p1, "NavController"

    .line 69
    .line 70
    invoke-static {p1, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :cond_1
    iget-object p0, v0, Lca/g;->t:Ljava/util/LinkedHashMap;

    .line 75
    .line 76
    invoke-virtual {p0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-eqz p0, :cond_2

    .line 81
    .line 82
    check-cast p0, Lz9/m;

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Lz9/m;->f(Lz9/k;)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v0, "NavigatorBackStack for "

    .line 91
    .line 92
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object p1, p1, Lz9/k;->e:Lz9/u;

    .line 96
    .line 97
    iget-object p1, p1, Lz9/u;->d:Ljava/lang/String;

    .line 98
    .line 99
    const-string v0, " should already be created"

    .line 100
    .line 101
    invoke-static {p0, p1, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p1
.end method
