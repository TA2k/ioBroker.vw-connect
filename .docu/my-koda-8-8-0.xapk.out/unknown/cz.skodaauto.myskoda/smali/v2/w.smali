.class public final Lv2/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/List;
.implements Lby0/c;


# instance fields
.field public final d:Lv2/o;

.field public final e:I

.field public f:I

.field public g:I


# direct methods
.method public constructor <init>(Lv2/o;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv2/w;->d:Lv2/o;

    .line 5
    .line 6
    iput p2, p0, Lv2/w;->e:I

    .line 7
    .line 8
    invoke-static {p1}, Lv2/p;->f(Lv2/o;)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput p1, p0, Lv2/w;->f:I

    .line 13
    .line 14
    sub-int/2addr p3, p2

    .line 15
    iput p3, p0, Lv2/w;->g:I

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 1

    .line 8
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 9
    iget v0, p0, Lv2/w;->e:I

    add-int/2addr v0, p1

    iget-object p1, p0, Lv2/w;->d:Lv2/o;

    invoke-virtual {p1, v0, p2}, Lv2/o;->add(ILjava/lang/Object;)V

    .line 10
    iget p2, p0, Lv2/w;->g:I

    add-int/lit8 p2, p2, 0x1

    .line 11
    iput p2, p0, Lv2/w;->g:I

    .line 12
    invoke-static {p1}, Lv2/p;->f(Lv2/o;)I

    move-result p1

    iput p1, p0, Lv2/w;->f:I

    return-void
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 2
    iget v0, p0, Lv2/w;->e:I

    .line 3
    iget v1, p0, Lv2/w;->g:I

    add-int/2addr v0, v1

    .line 4
    iget-object v1, p0, Lv2/w;->d:Lv2/o;

    invoke-virtual {v1, v0, p1}, Lv2/o;->add(ILjava/lang/Object;)V

    .line 5
    iget p1, p0, Lv2/w;->g:I

    const/4 v0, 0x1

    add-int/2addr p1, v0

    .line 6
    iput p1, p0, Lv2/w;->g:I

    .line 7
    invoke-static {v1}, Lv2/p;->f(Lv2/o;)I

    move-result p1

    iput p1, p0, Lv2/w;->f:I

    return v0
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 2

    .line 3
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 4
    iget v0, p0, Lv2/w;->e:I

    add-int/2addr p1, v0

    iget-object v0, p0, Lv2/w;->d:Lv2/o;

    invoke-virtual {v0, p1, p2}, Lv2/o;->addAll(ILjava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 5
    iget v1, p0, Lv2/w;->g:I

    .line 6
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p2

    add-int/2addr p2, v1

    iput p2, p0, Lv2/w;->g:I

    .line 7
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    move-result p2

    iput p2, p0, Lv2/w;->f:I

    :cond_0
    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    .line 1
    iget v0, p0, Lv2/w;->g:I

    .line 2
    invoke-virtual {p0, v0, p1}, Lv2/w;->addAll(ILjava/util/Collection;)Z

    move-result p0

    return p0
.end method

.method public final c()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv2/w;->d:Lv2/o;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget p0, p0, Lv2/w;->f:I

    .line 8
    .line 9
    if-ne v0, p0, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final clear()V
    .locals 3

    .line 1
    iget v0, p0, Lv2/w;->g:I

    .line 2
    .line 3
    if-lez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lv2/w;->g:I

    .line 9
    .line 10
    iget v1, p0, Lv2/w;->e:I

    .line 11
    .line 12
    add-int/2addr v0, v1

    .line 13
    iget-object v2, p0, Lv2/w;->d:Lv2/o;

    .line 14
    .line 15
    invoke-virtual {v2, v1, v0}, Lv2/o;->c(II)V

    .line 16
    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput v0, p0, Lv2/w;->g:I

    .line 20
    .line 21
    invoke-static {v2}, Lv2/p;->f(Lv2/o;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iput v0, p0, Lv2/w;->f:I

    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lv2/w;->indexOf(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-ltz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 2

    .line 1
    check-cast p1, Ljava/lang/Iterable;

    .line 2
    .line 3
    instance-of v0, p1, Ljava/util/Collection;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

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
    if-eqz v0, :cond_0

    .line 16
    .line 17
    return v1

    .line 18
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_2

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {p0, v0}, Lv2/w;->contains(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    return p0

    .line 40
    :cond_2
    return v1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lv2/w;->g:I

    .line 5
    .line 6
    invoke-static {p1, v0}, Lv2/p;->a(II)V

    .line 7
    .line 8
    .line 9
    iget v0, p0, Lv2/w;->e:I

    .line 10
    .line 11
    add-int/2addr v0, p1

    .line 12
    iget-object p0, p0, Lv2/w;->d:Lv2/o;

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lv2/w;->g:I

    .line 5
    .line 6
    iget v1, p0, Lv2/w;->e:I

    .line 7
    .line 8
    add-int/2addr v0, v1

    .line 9
    invoke-static {v1, v0}, Lkp/r9;->m(II)Lgy0/j;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    move-object v2, v0

    .line 24
    check-cast v2, Lmx0/w;

    .line 25
    .line 26
    invoke-virtual {v2}, Lmx0/w;->nextInt()I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    iget-object v3, p0, Lv2/w;->d:Lv2/o;

    .line 31
    .line 32
    invoke-virtual {v3, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_0

    .line 41
    .line 42
    sub-int/2addr v2, v1

    .line 43
    return v2

    .line 44
    :cond_1
    const/4 p0, -0x1

    .line 45
    return p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    iget p0, p0, Lv2/w;->g:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lv2/w;->listIterator(I)Ljava/util/ListIterator;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lv2/w;->g:I

    .line 5
    .line 6
    iget v1, p0, Lv2/w;->e:I

    .line 7
    .line 8
    add-int/2addr v0, v1

    .line 9
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    :goto_0
    if-lt v0, v1, :cond_1

    .line 12
    .line 13
    iget-object v2, p0, Lv2/w;->d:Lv2/o;

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    sub-int/2addr v0, v1

    .line 26
    return v0

    .line 27
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 p0, -0x1

    .line 31
    return p0
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, v0}, Lv2/w;->listIterator(I)Ljava/util/ListIterator;

    move-result-object p0

    return-object p0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    .line 2
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 3
    new-instance v0, Lkotlin/jvm/internal/d0;

    .line 4
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    add-int/lit8 p1, p1, -0x1

    .line 5
    iput p1, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 6
    new-instance p1, Lmx0/y;

    invoke-direct {p1, v0, p0}, Lmx0/y;-><init>(Lkotlin/jvm/internal/d0;Lv2/w;)V

    return-object p1
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 2

    .line 3
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 4
    iget v0, p0, Lv2/w;->e:I

    add-int/2addr v0, p1

    iget-object p1, p0, Lv2/w;->d:Lv2/o;

    invoke-virtual {p1, v0}, Lv2/o;->remove(I)Ljava/lang/Object;

    move-result-object v0

    .line 5
    iget v1, p0, Lv2/w;->g:I

    add-int/lit8 v1, v1, -0x1

    .line 6
    iput v1, p0, Lv2/w;->g:I

    .line 7
    invoke-static {p1}, Lv2/p;->f(Lv2/o;)I

    move-result p1

    iput p1, p0, Lv2/w;->f:I

    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lv2/w;->indexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    .line 2
    invoke-virtual {p0, p1}, Lv2/w;->remove(I)Ljava/lang/Object;

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const/4 v0, 0x0

    .line 6
    :cond_0
    move v1, v0

    .line 7
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_2

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {p0, v2}, Lv2/w;->remove(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-nez v2, :cond_1

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    :cond_1
    const/4 v1, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_2
    return v1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 10

    .line 1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lv2/w;->d:Lv2/o;

    .line 5
    .line 6
    iget v1, p0, Lv2/w;->e:I

    .line 7
    .line 8
    iget v2, p0, Lv2/w;->g:I

    .line 9
    .line 10
    add-int/2addr v2, v1

    .line 11
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    :cond_0
    sget-object v4, Lv2/p;->a:Ljava/lang/Object;

    .line 16
    .line 17
    monitor-enter v4

    .line 18
    :try_start_0
    iget-object v5, v0, Lv2/o;->d:Lv2/s;

    .line 19
    .line 20
    const-string v6, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    .line 21
    .line 22
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {v5}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    check-cast v5, Lv2/s;

    .line 30
    .line 31
    iget v6, v5, Lv2/s;->d:I

    .line 32
    .line 33
    iget-object v5, v5, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 34
    .line 35
    monitor-exit v4

    .line 36
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v5}, Lp2/c;->k()Lp2/f;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-virtual {v4, v1, v2}, Ljava/util/AbstractList;->subList(II)Ljava/util/List;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-interface {v7, p1}, Ljava/util/List;->retainAll(Ljava/util/Collection;)Z

    .line 48
    .line 49
    .line 50
    invoke-virtual {v4}, Lp2/f;->g()Lp2/c;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    const/4 v7, 0x1

    .line 59
    if-nez v5, :cond_1

    .line 60
    .line 61
    iget-object v5, v0, Lv2/o;->d:Lv2/s;

    .line 62
    .line 63
    const-string v8, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    .line 64
    .line 65
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    sget-object v8, Lv2/l;->c:Ljava/lang/Object;

    .line 69
    .line 70
    monitor-enter v8

    .line 71
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    invoke-static {v5, v0, v9}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    check-cast v5, Lv2/s;

    .line 80
    .line 81
    invoke-static {v5, v6, v4, v7}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    .line 82
    .line 83
    .line 84
    move-result v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    monitor-exit v8

    .line 86
    invoke-static {v9, v0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 87
    .line 88
    .line 89
    if-eqz v4, :cond_0

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :catchall_0
    move-exception p0

    .line 93
    monitor-exit v8

    .line 94
    throw p0

    .line 95
    :cond_1
    :goto_0
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    sub-int/2addr v3, p1

    .line 100
    if-lez v3, :cond_2

    .line 101
    .line 102
    iget-object p1, p0, Lv2/w;->d:Lv2/o;

    .line 103
    .line 104
    invoke-static {p1}, Lv2/p;->f(Lv2/o;)I

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    iput p1, p0, Lv2/w;->f:I

    .line 109
    .line 110
    iget p1, p0, Lv2/w;->g:I

    .line 111
    .line 112
    sub-int/2addr p1, v3

    .line 113
    iput p1, p0, Lv2/w;->g:I

    .line 114
    .line 115
    :cond_2
    if-lez v3, :cond_3

    .line 116
    .line 117
    return v7

    .line 118
    :cond_3
    const/4 p0, 0x0

    .line 119
    return p0

    .line 120
    :catchall_1
    move-exception p0

    .line 121
    monitor-exit v4

    .line 122
    throw p0
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lv2/w;->g:I

    .line 2
    .line 3
    invoke-static {p1, v0}, Lv2/p;->a(II)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 7
    .line 8
    .line 9
    iget v0, p0, Lv2/w;->e:I

    .line 10
    .line 11
    add-int/2addr p1, v0

    .line 12
    iget-object v0, p0, Lv2/w;->d:Lv2/o;

    .line 13
    .line 14
    invoke-virtual {v0, p1, p2}, Lv2/o;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iput p2, p0, Lv2/w;->f:I

    .line 23
    .line 24
    return-object p1
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Lv2/w;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    if-gt p1, p2, :cond_0

    .line 4
    .line 5
    iget v0, p0, Lv2/w;->g:I

    .line 6
    .line 7
    if-gt p2, v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    :goto_0
    if-nez v0, :cond_1

    .line 13
    .line 14
    const-string v0, "fromIndex or toIndex are out of bounds"

    .line 15
    .line 16
    invoke-static {v0}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    invoke-virtual {p0}, Lv2/w;->c()V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lv2/w;

    .line 23
    .line 24
    iget v1, p0, Lv2/w;->e:I

    .line 25
    .line 26
    add-int/2addr p1, v1

    .line 27
    add-int/2addr p2, v1

    .line 28
    iget-object p0, p0, Lv2/w;->d:Lv2/o;

    .line 29
    .line 30
    invoke-direct {v0, p0, p1, p2}, Lv2/w;-><init>(Lv2/o;II)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/l;->a(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 0

    .line 2
    invoke-static {p0, p1}, Lkotlin/jvm/internal/l;->b(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method
