.class public final Llo/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/j;
.implements Lko/k;


# instance fields
.field public final c:Ljava/util/LinkedList;

.field public final d:Lko/c;

.field public final e:Llo/b;

.field public final f:Lvp/y1;

.field public final g:Ljava/util/HashSet;

.field public final h:Ljava/util/HashMap;

.field public final i:I

.field public final j:Llo/b0;

.field public k:Z

.field public final l:Ljava/util/ArrayList;

.field public m:Ljo/b;

.field public n:I

.field public final synthetic o:Llo/g;


# direct methods
.method public constructor <init>(Llo/g;Lko/i;)V
    .locals 9

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llo/s;->o:Llo/g;

    .line 5
    .line 6
    new-instance v0, Ljava/util/LinkedList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/LinkedList;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 12
    .line 13
    new-instance v0, Ljava/util/HashSet;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Llo/s;->g:Ljava/util/HashSet;

    .line 19
    .line 20
    new-instance v0, Ljava/util/HashMap;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Llo/s;->h:Ljava/util/HashMap;

    .line 26
    .line 27
    new-instance v0, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Llo/s;->l:Ljava/util/ArrayList;

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iput-object v0, p0, Llo/s;->m:Ljo/b;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    iput v1, p0, Llo/s;->n:I

    .line 39
    .line 40
    iget-object v1, p1, Llo/g;->q:Lbp/c;

    .line 41
    .line 42
    invoke-virtual {v1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    invoke-virtual {p2}, Lko/i;->b()Lil/g;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    new-instance v5, Lin/z1;

    .line 51
    .line 52
    iget-object v2, v1, Lil/g;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v2, Landroidx/collection/g;

    .line 55
    .line 56
    iget-object v3, v1, Lil/g;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v3, Ljava/lang/String;

    .line 59
    .line 60
    iget-object v1, v1, Lil/g;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Ljava/lang/String;

    .line 63
    .line 64
    invoke-direct {v5, v3, v1, v2}, Lin/z1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 65
    .line 66
    .line 67
    iget-object v1, p2, Lko/i;->f:Lc2/k;

    .line 68
    .line 69
    iget-object v1, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 70
    .line 71
    move-object v2, v1

    .line 72
    check-cast v2, Llp/wd;

    .line 73
    .line 74
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object v6, p2, Lko/i;->g:Lko/b;

    .line 78
    .line 79
    iget-object v3, p2, Lko/i;->d:Landroid/content/Context;

    .line 80
    .line 81
    move-object v8, p0

    .line 82
    move-object v7, p0

    .line 83
    invoke-virtual/range {v2 .. v8}, Llp/wd;->a(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Lko/j;Lko/k;)Lko/c;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    iget-object v1, p2, Lko/i;->e:Ljava/lang/String;

    .line 88
    .line 89
    if-eqz v1, :cond_0

    .line 90
    .line 91
    instance-of v2, p0, Lno/e;

    .line 92
    .line 93
    if-eqz v2, :cond_0

    .line 94
    .line 95
    move-object v2, p0

    .line 96
    check-cast v2, Lno/e;

    .line 97
    .line 98
    iput-object v1, v2, Lno/e;->s:Ljava/lang/String;

    .line 99
    .line 100
    :cond_0
    if-eqz v1, :cond_2

    .line 101
    .line 102
    instance-of v1, p0, Llo/m;

    .line 103
    .line 104
    if-nez v1, :cond_1

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_1
    invoke-static {p0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    throw v0

    .line 111
    :cond_2
    :goto_0
    iput-object p0, v7, Llo/s;->d:Lko/c;

    .line 112
    .line 113
    iget-object v1, p2, Lko/i;->h:Llo/b;

    .line 114
    .line 115
    iput-object v1, v7, Llo/s;->e:Llo/b;

    .line 116
    .line 117
    new-instance v1, Lvp/y1;

    .line 118
    .line 119
    const/16 v2, 0xf

    .line 120
    .line 121
    invoke-direct {v1, v2}, Lvp/y1;-><init>(I)V

    .line 122
    .line 123
    .line 124
    iput-object v1, v7, Llo/s;->f:Lvp/y1;

    .line 125
    .line 126
    iget v1, p2, Lko/i;->j:I

    .line 127
    .line 128
    iput v1, v7, Llo/s;->i:I

    .line 129
    .line 130
    invoke-interface {p0}, Lko/c;->h()Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-eqz p0, :cond_3

    .line 135
    .line 136
    iget-object p0, p1, Llo/g;->h:Landroid/content/Context;

    .line 137
    .line 138
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 139
    .line 140
    new-instance v0, Llo/b0;

    .line 141
    .line 142
    invoke-virtual {p2}, Lko/i;->b()Lil/g;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    new-instance v1, Lin/z1;

    .line 147
    .line 148
    iget-object v2, p2, Lil/g;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v2, Landroidx/collection/g;

    .line 151
    .line 152
    iget-object v3, p2, Lil/g;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v3, Ljava/lang/String;

    .line 155
    .line 156
    iget-object p2, p2, Lil/g;->g:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p2, Ljava/lang/String;

    .line 159
    .line 160
    invoke-direct {v1, v3, p2, v2}, Lin/z1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 161
    .line 162
    .line 163
    invoke-direct {v0, p0, p1, v1}, Llo/b0;-><init>(Landroid/content/Context;Lbp/c;Lin/z1;)V

    .line 164
    .line 165
    .line 166
    iput-object v0, v7, Llo/s;->j:Llo/b0;

    .line 167
    .line 168
    return-void

    .line 169
    :cond_3
    iput-object v0, v7, Llo/s;->j:Llo/b0;

    .line 170
    .line 171
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 6
    .line 7
    iget-object v1, v1, Llo/g;->q:Lbp/c;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    if-ne v0, v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Llo/s;->i()V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance v0, Laq/p;

    .line 20
    .line 21
    const/16 v2, 0xf

    .line 22
    .line 23
    invoke-direct {v0, p0, v2}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final b(Ljo/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final c(I)V
    .locals 3

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 6
    .line 7
    iget-object v1, v1, Llo/g;->q:Lbp/c;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    if-ne v0, v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Llo/s;->j(I)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance v0, Lcom/google/android/material/datepicker/n;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-direct {v0, p0, p1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final d([Ljo/d;)Ljo/d;
    .locals 7

    .line 1
    if-eqz p1, :cond_5

    .line 2
    .line 3
    array-length v0, p1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_3

    .line 7
    :cond_0
    iget-object p0, p0, Llo/s;->d:Lko/c;

    .line 8
    .line 9
    invoke-interface {p0}, Lko/c;->k()[Ljo/d;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const/4 v0, 0x0

    .line 14
    if-nez p0, :cond_1

    .line 15
    .line 16
    new-array p0, v0, [Ljo/d;

    .line 17
    .line 18
    :cond_1
    new-instance v1, Landroidx/collection/f;

    .line 19
    .line 20
    array-length v2, p0

    .line 21
    invoke-direct {v1, v2}, Landroidx/collection/a1;-><init>(I)V

    .line 22
    .line 23
    .line 24
    move v2, v0

    .line 25
    :goto_0
    array-length v3, p0

    .line 26
    if-ge v2, v3, :cond_2

    .line 27
    .line 28
    aget-object v3, p0, v2

    .line 29
    .line 30
    iget-object v4, v3, Ljo/d;->d:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v3}, Ljo/d;->x0()J

    .line 33
    .line 34
    .line 35
    move-result-wide v5

    .line 36
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-interface {v1, v4, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    add-int/lit8 v2, v2, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    array-length p0, p1

    .line 47
    :goto_1
    if-ge v0, p0, :cond_5

    .line 48
    .line 49
    aget-object v2, p1, v0

    .line 50
    .line 51
    iget-object v3, v2, Ljo/d;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-interface {v1, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    check-cast v3, Ljava/lang/Long;

    .line 58
    .line 59
    if-eqz v3, :cond_4

    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 62
    .line 63
    .line 64
    move-result-wide v3

    .line 65
    invoke-virtual {v2}, Ljo/d;->x0()J

    .line 66
    .line 67
    .line 68
    move-result-wide v5

    .line 69
    cmp-long v3, v3, v5

    .line 70
    .line 71
    if-gez v3, :cond_3

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    add-int/lit8 v0, v0, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_4
    :goto_2
    return-object v2

    .line 78
    :cond_5
    :goto_3
    const/4 p0, 0x0

    .line 79
    return-object p0
.end method

.method public final e(Ljo/b;)V
    .locals 3

    .line 1
    iget-object v0, p0, Llo/s;->g:Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    sget-object v0, Ljo/b;->h:Ljo/b;

    .line 20
    .line 21
    invoke-static {p1, v0}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    iget-object p0, p0, Llo/s;->d:Lko/c;

    .line 28
    .line 29
    invoke-interface {p0}, Lko/c;->c()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    throw p0

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_2
    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final f(Lcom/google/android/gms/common/api/Status;)V
    .locals 2

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-virtual {p0, p1, v0, v1}, Llo/s;->g(Lcom/google/android/gms/common/api/Status;Ljava/lang/Exception;Z)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final g(Lcom/google/android/gms/common/api/Status;Ljava/lang/Exception;Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    move v2, v1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v2, v0

    .line 15
    :goto_0
    if-eqz p2, :cond_1

    .line 16
    .line 17
    move v0, v1

    .line 18
    :cond_1
    if-eq v2, v0, :cond_6

    .line 19
    .line 20
    iget-object p0, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_5

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Llo/f0;

    .line 37
    .line 38
    if-eqz p3, :cond_3

    .line 39
    .line 40
    iget v1, v0, Llo/f0;->a:I

    .line 41
    .line 42
    const/4 v2, 0x2

    .line 43
    if-ne v1, v2, :cond_2

    .line 44
    .line 45
    :cond_3
    if-eqz p1, :cond_4

    .line 46
    .line 47
    invoke-virtual {v0, p1}, Llo/f0;->a(Lcom/google/android/gms/common/api/Status;)V

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_4
    invoke-virtual {v0, p2}, Llo/f0;->b(Ljava/lang/Exception;)V

    .line 52
    .line 53
    .line 54
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_5
    return-void

    .line 59
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 60
    .line 61
    const-string p1, "Status XOR exception should be null"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0
.end method

.method public final h()V
    .locals 6

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object v1, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, 0x0

    .line 13
    :goto_0
    if-ge v3, v2, :cond_2

    .line 14
    .line 15
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    check-cast v4, Llo/f0;

    .line 20
    .line 21
    iget-object v5, p0, Llo/s;->d:Lko/c;

    .line 22
    .line 23
    invoke-interface {v5}, Lko/c;->isConnected()Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    if-nez v5, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    invoke-virtual {p0, v4}, Llo/s;->l(Llo/f0;)Z

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    invoke-virtual {v1, v4}, Ljava/util/LinkedList;->remove(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    :goto_1
    return-void
.end method

.method public final i()V
    .locals 4

    .line 1
    iget-object v0, p0, Llo/s;->d:Lko/c;

    .line 2
    .line 3
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 4
    .line 5
    iget-object v2, v1, Llo/g;->q:Lbp/c;

    .line 6
    .line 7
    invoke-static {v2}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    iput-object v2, p0, Llo/s;->m:Ljo/b;

    .line 12
    .line 13
    sget-object v2, Ljo/b;->h:Ljo/b;

    .line 14
    .line 15
    invoke-virtual {p0, v2}, Llo/s;->e(Ljo/b;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, v1, Llo/g;->q:Lbp/c;

    .line 19
    .line 20
    iget-boolean v2, p0, Llo/s;->k:Z

    .line 21
    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    const/16 v2, 0xb

    .line 25
    .line 26
    iget-object v3, p0, Llo/s;->e:Llo/b;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    const/16 v2, 0x9

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    iput-boolean v1, p0, Llo/s;->k:Z

    .line 38
    .line 39
    :cond_0
    iget-object v1, p0, Llo/s;->h:Ljava/util/HashMap;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Llo/z;

    .line 60
    .line 61
    iget-object v3, v2, Llo/z;->a:Lw7/o;

    .line 62
    .line 63
    iget-object v3, v3, Lw7/o;->d:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v3, [Ljo/d;

    .line 66
    .line 67
    invoke-virtual {p0, v3}, Llo/s;->d([Ljo/d;)Ljo/d;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    if-eqz v3, :cond_1

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_1
    :try_start_0
    iget-object v2, v2, Llo/z;->a:Lw7/o;

    .line 78
    .line 79
    new-instance v3, Laq/k;

    .line 80
    .line 81
    invoke-direct {v3}, Laq/k;-><init>()V

    .line 82
    .line 83
    .line 84
    iget-object v2, v2, Lw7/o;->e:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v2, Lf8/d;

    .line 87
    .line 88
    iget-object v2, v2, Lf8/d;->f:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v2, Llo/n;

    .line 91
    .line 92
    invoke-interface {v2, v0, v3}, Llo/n;->accept(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/os/DeadObjectException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :catch_0
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :catch_1
    const/4 v1, 0x3

    .line 101
    invoke-virtual {p0, v1}, Llo/s;->c(I)V

    .line 102
    .line 103
    .line 104
    const-string v1, "DeadObjectException thrown while calling register listener method."

    .line 105
    .line 106
    invoke-interface {v0, v1}, Lko/c;->a(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    :cond_2
    invoke-virtual {p0}, Llo/s;->h()V

    .line 110
    .line 111
    .line 112
    invoke-virtual {p0}, Llo/s;->k()V

    .line 113
    .line 114
    .line 115
    return-void
.end method

.method public final j(I)V
    .locals 8

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v1, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    iget-object v2, v0, Llo/g;->q:Lbp/c;

    .line 6
    .line 7
    invoke-static {v2}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 8
    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    iput-object v2, p0, Llo/s;->m:Ljo/b;

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    iput-boolean v3, p0, Llo/s;->k:Z

    .line 15
    .line 16
    iget-object v4, p0, Llo/s;->d:Lko/c;

    .line 17
    .line 18
    invoke-interface {v4}, Lko/c;->l()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    iget-object v5, p0, Llo/s;->f:Lvp/y1;

    .line 23
    .line 24
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    new-instance v6, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v7, "The connection to Google Play services was lost"

    .line 30
    .line 31
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    if-ne p1, v3, :cond_0

    .line 35
    .line 36
    const-string p1, " due to service disconnection."

    .line 37
    .line 38
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v7, 0x3

    .line 43
    if-ne p1, v7, :cond_1

    .line 44
    .line 45
    const-string p1, " due to dead object exception."

    .line 46
    .line 47
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    :cond_1
    :goto_0
    if-eqz v4, :cond_2

    .line 51
    .line 52
    const-string p1, " Last reason for disconnect: "

    .line 53
    .line 54
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    :cond_2
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    new-instance v4, Lcom/google/android/gms/common/api/Status;

    .line 65
    .line 66
    const/16 v6, 0x14

    .line 67
    .line 68
    invoke-direct {v4, v6, p1, v2, v2}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v5, v3, v4}, Lvp/y1;->W(ZLcom/google/android/gms/common/api/Status;)V

    .line 72
    .line 73
    .line 74
    const/16 p1, 0x9

    .line 75
    .line 76
    iget-object v2, p0, Llo/s;->e:Llo/b;

    .line 77
    .line 78
    invoke-static {v1, p1, v2}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    const-wide/16 v3, 0x1388

    .line 83
    .line 84
    invoke-virtual {v1, p1, v3, v4}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 85
    .line 86
    .line 87
    const/16 p1, 0xb

    .line 88
    .line 89
    invoke-static {v1, p1, v2}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    const-wide/32 v2, 0x1d4c0

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1, p1, v2, v3}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 97
    .line 98
    .line 99
    iget-object p1, v0, Llo/g;->j:Lc2/k;

    .line 100
    .line 101
    iget-object p1, p1, Lc2/k;->e:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast p1, Landroid/util/SparseIntArray;

    .line 104
    .line 105
    invoke-virtual {p1}, Landroid/util/SparseIntArray;->clear()V

    .line 106
    .line 107
    .line 108
    iget-object p0, p0, Llo/s;->h:Ljava/util/HashMap;

    .line 109
    .line 110
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-eqz p1, :cond_3

    .line 123
    .line 124
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    check-cast p1, Llo/z;

    .line 129
    .line 130
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_3
    return-void
.end method

.method public final k()V
    .locals 4

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v1, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    const/16 v2, 0xc

    .line 6
    .line 7
    iget-object p0, p0, Llo/s;->e:Llo/b;

    .line 8
    .line 9
    invoke-virtual {v1, v2, p0}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v2, p0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    iget-wide v2, v0, Llo/g;->d:J

    .line 17
    .line 18
    invoke-virtual {v1, p0, v2, v3}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final l(Llo/f0;)Z
    .locals 7

    .line 1
    instance-of v0, p1, Llo/v;

    .line 2
    .line 3
    const-string v1, "DeadObjectException thrown while running ApiCallRunner."

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Llo/s;->f:Lvp/y1;

    .line 9
    .line 10
    iget-object v3, p0, Llo/s;->d:Lko/c;

    .line 11
    .line 12
    invoke-interface {v3}, Lko/c;->h()Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    invoke-virtual {p1, v0, v4}, Llo/f0;->d(Lvp/y1;Z)V

    .line 17
    .line 18
    .line 19
    :try_start_0
    invoke-virtual {p1, p0}, Llo/f0;->c(Llo/s;)V
    :try_end_0
    .catch Landroid/os/DeadObjectException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return v2

    .line 23
    :catch_0
    invoke-virtual {p0, v2}, Llo/s;->c(I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v3, v1}, Lko/c;->a(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    return v2

    .line 30
    :cond_0
    move-object v0, p1

    .line 31
    check-cast v0, Llo/v;

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Llo/v;->g(Llo/s;)[Ljo/d;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-virtual {p0, v3}, Llo/s;->d([Ljo/d;)Ljo/d;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    if-nez v3, :cond_1

    .line 42
    .line 43
    iget-object v0, p0, Llo/s;->f:Lvp/y1;

    .line 44
    .line 45
    iget-object v3, p0, Llo/s;->d:Lko/c;

    .line 46
    .line 47
    invoke-interface {v3}, Lko/c;->h()Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    invoke-virtual {p1, v0, v4}, Llo/f0;->d(Lvp/y1;Z)V

    .line 52
    .line 53
    .line 54
    :try_start_1
    invoke-virtual {p1, p0}, Llo/f0;->c(Llo/s;)V
    :try_end_1
    .catch Landroid/os/DeadObjectException; {:try_start_1 .. :try_end_1} :catch_1

    .line 55
    .line 56
    .line 57
    return v2

    .line 58
    :catch_1
    invoke-virtual {p0, v2}, Llo/s;->c(I)V

    .line 59
    .line 60
    .line 61
    invoke-interface {v3, v1}, Lko/c;->a(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return v2

    .line 65
    :cond_1
    iget-object p1, p0, Llo/s;->d:Lko/c;

    .line 66
    .line 67
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    iget-object v1, v3, Ljo/d;->d:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {v3}, Ljo/d;->x0()J

    .line 78
    .line 79
    .line 80
    move-result-wide v4

    .line 81
    new-instance v6, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string p1, " could not execute call because it requires feature ("

    .line 90
    .line 91
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string p1, ", "

    .line 98
    .line 99
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v6, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string p1, ")."

    .line 106
    .line 107
    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    const-string v1, "GoogleApiManager"

    .line 115
    .line 116
    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 117
    .line 118
    .line 119
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 120
    .line 121
    iget-boolean p1, p1, Llo/g;->r:Z

    .line 122
    .line 123
    if-eqz p1, :cond_4

    .line 124
    .line 125
    invoke-virtual {v0, p0}, Llo/v;->f(Llo/s;)Z

    .line 126
    .line 127
    .line 128
    move-result p1

    .line 129
    if-eqz p1, :cond_4

    .line 130
    .line 131
    iget-object p1, p0, Llo/s;->e:Llo/b;

    .line 132
    .line 133
    new-instance v0, Llo/t;

    .line 134
    .line 135
    invoke-direct {v0, p1, v3}, Llo/t;-><init>(Llo/b;Ljo/d;)V

    .line 136
    .line 137
    .line 138
    iget-object p1, p0, Llo/s;->l:Ljava/util/ArrayList;

    .line 139
    .line 140
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 141
    .line 142
    .line 143
    move-result p1

    .line 144
    const-wide/16 v1, 0x1388

    .line 145
    .line 146
    const/16 v3, 0xf

    .line 147
    .line 148
    if-ltz p1, :cond_2

    .line 149
    .line 150
    iget-object v0, p0, Llo/s;->l:Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    check-cast p1, Llo/t;

    .line 157
    .line 158
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 159
    .line 160
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 161
    .line 162
    invoke-virtual {v0, v3, p1}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    iget-object p0, p0, Llo/s;->o:Llo/g;

    .line 166
    .line 167
    iget-object p0, p0, Llo/g;->q:Lbp/c;

    .line 168
    .line 169
    invoke-static {p0, v3, p1}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    invoke-virtual {p0, p1, v1, v2}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 174
    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_2
    iget-object p1, p0, Llo/s;->l:Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 183
    .line 184
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 185
    .line 186
    invoke-static {p1, v3, v0}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    invoke-virtual {p1, v3, v1, v2}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 191
    .line 192
    .line 193
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 194
    .line 195
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 196
    .line 197
    const/16 v1, 0x10

    .line 198
    .line 199
    invoke-static {p1, v1, v0}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    const-wide/32 v1, 0x1d4c0

    .line 204
    .line 205
    .line 206
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 207
    .line 208
    .line 209
    new-instance p1, Ljo/b;

    .line 210
    .line 211
    const/4 v0, 0x2

    .line 212
    const/4 v1, 0x0

    .line 213
    invoke-direct {p1, v0, v1}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {p0, p1}, Llo/s;->m(Ljo/b;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    if-nez v0, :cond_3

    .line 221
    .line 222
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 223
    .line 224
    iget p0, p0, Llo/s;->i:I

    .line 225
    .line 226
    invoke-virtual {v0, p1, p0}, Llo/g;->c(Ljo/b;I)Z

    .line 227
    .line 228
    .line 229
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 230
    return p0

    .line 231
    :cond_4
    new-instance p0, Law0/d;

    .line 232
    .line 233
    invoke-direct {p0, v3}, Law0/d;-><init>(Ljo/d;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v0, p0}, Llo/f0;->b(Ljava/lang/Exception;)V

    .line 237
    .line 238
    .line 239
    return v2
.end method

.method public final m(Ljo/b;)Z
    .locals 5

    .line 1
    sget-object v0, Llo/g;->u:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 5
    .line 6
    iget-object v2, v1, Llo/g;->n:Llo/p;

    .line 7
    .line 8
    if-eqz v2, :cond_3

    .line 9
    .line 10
    iget-object v1, v1, Llo/g;->o:Landroidx/collection/g;

    .line 11
    .line 12
    iget-object v2, p0, Llo/s;->e:Llo/b;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Landroidx/collection/g;->contains(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_3

    .line 19
    .line 20
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 21
    .line 22
    iget-object v1, v1, Llo/g;->n:Llo/p;

    .line 23
    .line 24
    iget p0, p0, Llo/s;->i:I

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    new-instance v2, Llo/g0;

    .line 30
    .line 31
    invoke-direct {v2, p1, p0}, Llo/g0;-><init>(Ljo/b;I)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object p0, v1, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 35
    .line 36
    :cond_1
    const/4 p1, 0x0

    .line 37
    invoke-virtual {p0, p1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    iget-object p0, v1, Llo/p;->g:Lbp/c;

    .line 44
    .line 45
    new-instance p1, Llr/b;

    .line 46
    .line 47
    const/16 v3, 0xe

    .line 48
    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-direct {p1, v1, v2, v4, v3}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, p1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-eqz p1, :cond_1

    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-eqz p0, :cond_0

    .line 68
    .line 69
    :goto_0
    monitor-exit v0

    .line 70
    const/4 p0, 0x1

    .line 71
    return p0

    .line 72
    :catchall_0
    move-exception p0

    .line 73
    goto :goto_1

    .line 74
    :cond_3
    monitor-exit v0

    .line 75
    const/4 p0, 0x0

    .line 76
    return p0

    .line 77
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    throw p0
.end method

.method public final n()V
    .locals 11

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v1, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v1}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Llo/s;->d:Lko/c;

    .line 9
    .line 10
    invoke-interface {v1}, Lko/c;->isConnected()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-nez v2, :cond_b

    .line 15
    .line 16
    invoke-interface {v1}, Lko/c;->b()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    goto/16 :goto_6

    .line 23
    .line 24
    :cond_0
    const/16 v2, 0xa

    .line 25
    .line 26
    :try_start_0
    iget-object v3, v0, Llo/g;->j:Lc2/k;

    .line 27
    .line 28
    iget-object v4, v0, Llo/g;->h:Landroid/content/Context;

    .line 29
    .line 30
    iget-object v5, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v5, Landroid/util/SparseIntArray;

    .line 33
    .line 34
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v1}, Lko/c;->g()Z

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    const/4 v7, 0x0

    .line 42
    if-nez v6, :cond_1

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    invoke-interface {v1}, Lko/c;->j()I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    iget-object v8, v3, Lc2/k;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v8, Landroid/util/SparseIntArray;

    .line 52
    .line 53
    const/4 v9, -0x1

    .line 54
    invoke-virtual {v8, v6, v9}, Landroid/util/SparseIntArray;->get(II)I

    .line 55
    .line 56
    .line 57
    move-result v8

    .line 58
    if-eq v8, v9, :cond_2

    .line 59
    .line 60
    move v7, v8

    .line 61
    goto :goto_2

    .line 62
    :cond_2
    move v8, v7

    .line 63
    :goto_0
    invoke-virtual {v5}, Landroid/util/SparseIntArray;->size()I

    .line 64
    .line 65
    .line 66
    move-result v10

    .line 67
    if-ge v8, v10, :cond_4

    .line 68
    .line 69
    invoke-virtual {v5, v8}, Landroid/util/SparseIntArray;->keyAt(I)I

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    if-le v10, v6, :cond_3

    .line 74
    .line 75
    invoke-virtual {v5, v10}, Landroid/util/SparseIntArray;->get(I)I

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    if-nez v10, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    add-int/lit8 v8, v8, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_4
    move v7, v9

    .line 86
    :goto_1
    if-ne v7, v9, :cond_5

    .line 87
    .line 88
    iget-object v3, v3, Lc2/k;->f:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v3, Ljo/e;

    .line 91
    .line 92
    invoke-virtual {v3, v4, v6}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    move v7, v3

    .line 97
    :cond_5
    invoke-virtual {v5, v6, v7}, Landroid/util/SparseIntArray;->put(II)V

    .line 98
    .line 99
    .line 100
    :goto_2
    if-eqz v7, :cond_6

    .line 101
    .line 102
    new-instance v0, Ljo/b;

    .line 103
    .line 104
    const/4 v3, 0x0

    .line 105
    invoke-direct {v0, v7, v3}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 106
    .line 107
    .line 108
    const-string v4, "GoogleApiManager"

    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-virtual {v0}, Ljo/b;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    new-instance v6, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 125
    .line 126
    .line 127
    const-string v7, "The service for "

    .line 128
    .line 129
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v1, " is not available: "

    .line 136
    .line 137
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-static {v4, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    invoke-virtual {p0, v0, v3}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :catch_0
    move-exception v0

    .line 155
    goto :goto_5

    .line 156
    :cond_6
    new-instance v3, Lh8/o;

    .line 157
    .line 158
    iget-object v4, p0, Llo/s;->e:Llo/b;

    .line 159
    .line 160
    invoke-direct {v3, v0, v1, v4}, Lh8/o;-><init>(Llo/g;Lko/c;Llo/b;)V

    .line 161
    .line 162
    .line 163
    invoke-interface {v1}, Lko/c;->h()Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-eqz v0, :cond_a

    .line 168
    .line 169
    iget-object v9, p0, Llo/s;->j:Llo/b0;

    .line 170
    .line 171
    invoke-static {v9}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    iget-object v0, v9, Llo/b0;->e:Landroid/os/Handler;

    .line 175
    .line 176
    iget-object v7, v9, Llo/b0;->h:Lin/z1;

    .line 177
    .line 178
    iget-object v4, v9, Llo/b0;->i:Lyp/a;

    .line 179
    .line 180
    if-eqz v4, :cond_7

    .line 181
    .line 182
    invoke-interface {v4}, Lko/c;->disconnect()V

    .line 183
    .line 184
    .line 185
    :cond_7
    invoke-static {v9}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 186
    .line 187
    .line 188
    move-result v4

    .line 189
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    iput-object v4, v7, Lin/z1;->f:Ljava/lang/Object;

    .line 194
    .line 195
    iget-object v4, v9, Llo/b0;->f:Lbp/l;

    .line 196
    .line 197
    iget-object v5, v9, Llo/b0;->d:Landroid/content/Context;

    .line 198
    .line 199
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    iget-object v8, v7, Lin/z1;->e:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v8, Lxp/a;

    .line 206
    .line 207
    move-object v10, v9

    .line 208
    invoke-virtual/range {v4 .. v10}, Lbp/l;->a(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Ljava/lang/Object;Lko/j;Lko/k;)Lko/c;

    .line 209
    .line 210
    .line 211
    move-result-object v4

    .line 212
    check-cast v4, Lyp/a;

    .line 213
    .line 214
    iput-object v4, v9, Llo/b0;->i:Lyp/a;

    .line 215
    .line 216
    iput-object v3, v9, Llo/b0;->j:Lh8/o;

    .line 217
    .line 218
    iget-object v4, v9, Llo/b0;->g:Ljava/util/Set;

    .line 219
    .line 220
    if-eqz v4, :cond_9

    .line 221
    .line 222
    invoke-interface {v4}, Ljava/util/Set;->isEmpty()Z

    .line 223
    .line 224
    .line 225
    move-result v4

    .line 226
    if-eqz v4, :cond_8

    .line 227
    .line 228
    goto :goto_3

    .line 229
    :cond_8
    iget-object v0, v9, Llo/b0;->i:Lyp/a;

    .line 230
    .line 231
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 232
    .line 233
    .line 234
    new-instance v4, Lno/n;

    .line 235
    .line 236
    invoke-direct {v4, v0}, Lno/n;-><init>(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v0, v4}, Lno/e;->e(Lno/d;)V

    .line 240
    .line 241
    .line 242
    goto :goto_4

    .line 243
    :cond_9
    :goto_3
    new-instance v4, Laq/p;

    .line 244
    .line 245
    const/16 v5, 0x11

    .line 246
    .line 247
    invoke-direct {v4, v9, v5}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v0, v4}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 251
    .line 252
    .line 253
    :cond_a
    :goto_4
    :try_start_1
    invoke-interface {v1, v3}, Lko/c;->e(Lno/d;)V
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_1

    .line 254
    .line 255
    .line 256
    return-void

    .line 257
    :catch_1
    move-exception v0

    .line 258
    new-instance v1, Ljo/b;

    .line 259
    .line 260
    invoke-direct {v1, v2}, Ljo/b;-><init>(I)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {p0, v1, v0}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 264
    .line 265
    .line 266
    return-void

    .line 267
    :goto_5
    new-instance v1, Ljo/b;

    .line 268
    .line 269
    invoke-direct {v1, v2}, Ljo/b;-><init>(I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {p0, v1, v0}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 273
    .line 274
    .line 275
    :cond_b
    :goto_6
    return-void
.end method

.method public final o(Llo/f0;)V
    .locals 2

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Llo/s;->d:Lko/c;

    .line 9
    .line 10
    invoke-interface {v0}, Lko/c;->isConnected()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iget-object v1, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Llo/s;->l(Llo/f0;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Llo/s;->k()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    invoke-virtual {v1, p1}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    invoke-virtual {v1, p1}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Llo/s;->m:Ljo/b;

    .line 36
    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    iget v0, p1, Ljo/b;->e:I

    .line 40
    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    iget-object v0, p1, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 44
    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    invoke-virtual {p0, p1, v0}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    invoke-virtual {p0}, Llo/s;->n()V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public final p(Ljo/b;Ljava/lang/RuntimeException;)V
    .locals 6

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Llo/s;->j:Llo/b0;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, v0, Llo/b0;->i:Lyp/a;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-interface {v0}, Lko/c;->disconnect()V

    .line 17
    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 20
    .line 21
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 22
    .line 23
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Llo/s;->m:Ljo/b;

    .line 28
    .line 29
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 30
    .line 31
    iget-object v1, v1, Llo/g;->j:Lc2/k;

    .line 32
    .line 33
    iget-object v1, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v1, Landroid/util/SparseIntArray;

    .line 36
    .line 37
    invoke-virtual {v1}, Landroid/util/SparseIntArray;->clear()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, p1}, Llo/s;->e(Ljo/b;)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Llo/s;->d:Lko/c;

    .line 44
    .line 45
    instance-of v1, v1, Lpo/c;

    .line 46
    .line 47
    const/4 v2, 0x1

    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    iget v1, p1, Ljo/b;->e:I

    .line 51
    .line 52
    const/16 v3, 0x18

    .line 53
    .line 54
    if-eq v1, v3, :cond_1

    .line 55
    .line 56
    iget-object v1, p0, Llo/s;->o:Llo/g;

    .line 57
    .line 58
    iput-boolean v2, v1, Llo/g;->e:Z

    .line 59
    .line 60
    iget-object v1, v1, Llo/g;->q:Lbp/c;

    .line 61
    .line 62
    const/16 v3, 0x13

    .line 63
    .line 64
    invoke-virtual {v1, v3}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    const-wide/32 v4, 0x493e0

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, v3, v4, v5}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 72
    .line 73
    .line 74
    :cond_1
    iget v1, p1, Ljo/b;->e:I

    .line 75
    .line 76
    const/4 v3, 0x4

    .line 77
    if-ne v1, v3, :cond_2

    .line 78
    .line 79
    sget-object p1, Llo/g;->t:Lcom/google/android/gms/common/api/Status;

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 82
    .line 83
    .line 84
    return-void

    .line 85
    :cond_2
    iget-object v1, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 86
    .line 87
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_3

    .line 92
    .line 93
    iput-object p1, p0, Llo/s;->m:Ljo/b;

    .line 94
    .line 95
    return-void

    .line 96
    :cond_3
    if-eqz p2, :cond_4

    .line 97
    .line 98
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 99
    .line 100
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 101
    .line 102
    invoke-static {p1}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 103
    .line 104
    .line 105
    const/4 p1, 0x0

    .line 106
    invoke-virtual {p0, v0, p2, p1}, Llo/s;->g(Lcom/google/android/gms/common/api/Status;Ljava/lang/Exception;Z)V

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :cond_4
    iget-object p2, p0, Llo/s;->o:Llo/g;

    .line 111
    .line 112
    iget-boolean p2, p2, Llo/g;->r:Z

    .line 113
    .line 114
    if-eqz p2, :cond_9

    .line 115
    .line 116
    iget-object p2, p0, Llo/s;->e:Llo/b;

    .line 117
    .line 118
    invoke-static {p2, p1}, Llo/g;->d(Llo/b;Ljo/b;)Lcom/google/android/gms/common/api/Status;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    invoke-virtual {p0, p2, v0, v2}, Llo/s;->g(Lcom/google/android/gms/common/api/Status;Ljava/lang/Exception;Z)V

    .line 123
    .line 124
    .line 125
    iget-object p2, p0, Llo/s;->c:Ljava/util/LinkedList;

    .line 126
    .line 127
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eqz p2, :cond_5

    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_5
    invoke-virtual {p0, p1}, Llo/s;->m(Ljo/b;)Z

    .line 135
    .line 136
    .line 137
    move-result p2

    .line 138
    if-nez p2, :cond_8

    .line 139
    .line 140
    iget-object p2, p0, Llo/s;->o:Llo/g;

    .line 141
    .line 142
    iget v0, p0, Llo/s;->i:I

    .line 143
    .line 144
    invoke-virtual {p2, p1, v0}, Llo/g;->c(Ljo/b;I)Z

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    if-nez p2, :cond_8

    .line 149
    .line 150
    iget p2, p1, Ljo/b;->e:I

    .line 151
    .line 152
    const/16 v0, 0x12

    .line 153
    .line 154
    if-ne p2, v0, :cond_6

    .line 155
    .line 156
    iput-boolean v2, p0, Llo/s;->k:Z

    .line 157
    .line 158
    :cond_6
    iget-boolean p2, p0, Llo/s;->k:Z

    .line 159
    .line 160
    if-eqz p2, :cond_7

    .line 161
    .line 162
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 163
    .line 164
    iget-object p0, p0, Llo/s;->e:Llo/b;

    .line 165
    .line 166
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 167
    .line 168
    const/16 p2, 0x9

    .line 169
    .line 170
    invoke-static {p1, p2, p0}, Landroid/os/Message;->obtain(Landroid/os/Handler;ILjava/lang/Object;)Landroid/os/Message;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    const-wide/16 v0, 0x1388

    .line 175
    .line 176
    invoke-virtual {p1, p0, v0, v1}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 177
    .line 178
    .line 179
    return-void

    .line 180
    :cond_7
    iget-object p2, p0, Llo/s;->e:Llo/b;

    .line 181
    .line 182
    invoke-static {p2, p1}, Llo/g;->d(Llo/b;Ljo/b;)Lcom/google/android/gms/common/api/Status;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    invoke-virtual {p0, p1}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 187
    .line 188
    .line 189
    :cond_8
    :goto_0
    return-void

    .line 190
    :cond_9
    iget-object p2, p0, Llo/s;->e:Llo/b;

    .line 191
    .line 192
    invoke-static {p2, p1}, Llo/g;->d(Llo/b;Ljo/b;)Lcom/google/android/gms/common/api/Status;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    invoke-virtual {p0, p1}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 197
    .line 198
    .line 199
    return-void
.end method

.method public final q(Ljo/b;)V
    .locals 5

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Llo/s;->d:Lko/c;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    new-instance v3, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v4, "onSignInFailed for "

    .line 25
    .line 26
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, " with "

    .line 33
    .line 34
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-interface {v0, v1}, Lko/c;->a(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    invoke-virtual {p0, p1, v0}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

.method public final r()V
    .locals 6

    .line 1
    iget-object v0, p0, Llo/s;->o:Llo/g;

    .line 2
    .line 3
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 4
    .line 5
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Llo/g;->s:Lcom/google/android/gms/common/api/Status;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Llo/s;->f:Lvp/y1;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-virtual {v1, v2, v0}, Lvp/y1;->W(ZLcom/google/android/gms/common/api/Status;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Llo/s;->h:Ljava/util/HashMap;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    new-array v1, v2, [Llo/k;

    .line 26
    .line 27
    invoke-interface {v0, v1}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, [Llo/k;

    .line 32
    .line 33
    array-length v1, v0

    .line 34
    :goto_0
    if-ge v2, v1, :cond_0

    .line 35
    .line 36
    aget-object v3, v0, v2

    .line 37
    .line 38
    new-instance v4, Llo/d0;

    .line 39
    .line 40
    new-instance v5, Laq/k;

    .line 41
    .line 42
    invoke-direct {v5}, Laq/k;-><init>()V

    .line 43
    .line 44
    .line 45
    invoke-direct {v4, v3, v5}, Llo/d0;-><init>(Llo/k;Laq/k;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, v4}, Llo/s;->o(Llo/f0;)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v2, v2, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    new-instance v0, Ljo/b;

    .line 55
    .line 56
    const/4 v1, 0x4

    .line 57
    invoke-direct {v0, v1}, Ljo/b;-><init>(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, v0}, Llo/s;->e(Ljo/b;)V

    .line 61
    .line 62
    .line 63
    iget-object v0, p0, Llo/s;->d:Lko/c;

    .line 64
    .line 65
    invoke-interface {v0}, Lko/c;->isConnected()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_1

    .line 70
    .line 71
    new-instance v1, Lhu/q;

    .line 72
    .line 73
    const/16 v2, 0x11

    .line 74
    .line 75
    invoke-direct {v1, p0, v2}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    invoke-interface {v0, v1}, Lko/c;->f(Lhu/q;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    return-void
.end method
