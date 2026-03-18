.class public final Lh8/l0;
.super Lh8/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final s:Lt7/x;


# instance fields
.field public final k:[Lh8/a;

.field public final l:Ljava/util/ArrayList;

.field public final m:[Lt7/p0;

.field public final n:Ljava/util/ArrayList;

.field public final o:Lst/b;

.field public p:I

.field public q:[[J

.field public r:Lio/ktor/utils/io/k0;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lo8/s;

    .line 2
    .line 3
    invoke-direct {v0}, Lo8/s;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lhr/h0;->e:Lhr/f0;

    .line 7
    .line 8
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 9
    .line 10
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 11
    .line 12
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 13
    .line 14
    new-instance v1, Lt7/s;

    .line 15
    .line 16
    invoke-direct {v1}, Lt7/s;-><init>()V

    .line 17
    .line 18
    .line 19
    sget-object v8, Lt7/v;->a:Lt7/v;

    .line 20
    .line 21
    new-instance v2, Lt7/x;

    .line 22
    .line 23
    new-instance v4, Lt7/r;

    .line 24
    .line 25
    invoke-direct {v4, v0}, Lt7/q;-><init>(Lo8/s;)V

    .line 26
    .line 27
    .line 28
    new-instance v6, Lt7/t;

    .line 29
    .line 30
    invoke-direct {v6, v1}, Lt7/t;-><init>(Lt7/s;)V

    .line 31
    .line 32
    .line 33
    sget-object v7, Lt7/a0;->B:Lt7/a0;

    .line 34
    .line 35
    const-string v3, "MergingMediaSource"

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    invoke-direct/range {v2 .. v8}, Lt7/x;-><init>(Ljava/lang/String;Lt7/r;Lt7/u;Lt7/t;Lt7/a0;Lt7/v;)V

    .line 39
    .line 40
    .line 41
    sput-object v2, Lh8/l0;->s:Lt7/x;

    .line 42
    .line 43
    return-void
.end method

.method public varargs constructor <init>([Lh8/a;)V
    .locals 4

    .line 1
    new-instance v0, Lst/b;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lst/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Lh8/k;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lh8/l0;->k:[Lh8/a;

    .line 11
    .line 12
    iput-object v0, p0, Lh8/l0;->o:Lst/b;

    .line 13
    .line 14
    new-instance v0, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lh8/l0;->n:Ljava/util/ArrayList;

    .line 24
    .line 25
    const/4 v0, -0x1

    .line 26
    iput v0, p0, Lh8/l0;->p:I

    .line 27
    .line 28
    new-instance v0, Ljava/util/ArrayList;

    .line 29
    .line 30
    array-length v1, p1

    .line 31
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 32
    .line 33
    .line 34
    iput-object v0, p0, Lh8/l0;->l:Ljava/util/ArrayList;

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    move v1, v0

    .line 38
    :goto_0
    array-length v2, p1

    .line 39
    if-ge v1, v2, :cond_0

    .line 40
    .line 41
    iget-object v2, p0, Lh8/l0;->l:Ljava/util/ArrayList;

    .line 42
    .line 43
    new-instance v3, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    array-length p1, p1

    .line 55
    new-array p1, p1, [Lt7/p0;

    .line 56
    .line 57
    iput-object p1, p0, Lh8/l0;->m:[Lt7/p0;

    .line 58
    .line 59
    new-array p1, v0, [[J

    .line 60
    .line 61
    iput-object p1, p0, Lh8/l0;->q:[[J

    .line 62
    .line 63
    new-instance p0, Ljava/util/HashMap;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 66
    .line 67
    .line 68
    const/16 p0, 0x8

    .line 69
    .line 70
    const-string p1, "expectedKeys"

    .line 71
    .line 72
    invoke-static {p0, p1}, Lhr/q;->c(ILjava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const/4 p0, 0x2

    .line 76
    const-string p1, "expectedValuesPerKey"

    .line 77
    .line 78
    invoke-static {p0, p1}, Lhr/q;->c(ILjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-static {}, Lhr/v;->a()Lhr/v;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    new-instance p1, Lhr/s0;

    .line 86
    .line 87
    invoke-direct {p1}, Lhr/s0;-><init>()V

    .line 88
    .line 89
    .line 90
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_1

    .line 95
    .line 96
    return-void

    .line 97
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 98
    .line 99
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 100
    .line 101
    .line 102
    throw p0
.end method


# virtual methods
.method public final a(Lh8/b0;Lk8/e;J)Lh8/z;
    .locals 10

    .line 1
    iget-object v0, p0, Lh8/l0;->k:[Lh8/a;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    new-array v2, v1, [Lh8/z;

    .line 5
    .line 6
    iget-object v3, p0, Lh8/l0;->m:[Lt7/p0;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    aget-object v5, v3, v4

    .line 10
    .line 11
    iget-object v6, p1, Lh8/b0;->a:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-virtual {v5, v6}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    :goto_0
    if-ge v4, v1, :cond_0

    .line 18
    .line 19
    aget-object v6, v3, v4

    .line 20
    .line 21
    invoke-virtual {v6, v5}, Lt7/p0;->l(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    invoke-virtual {p1, v6}, Lh8/b0;->a(Ljava/lang/Object;)Lh8/b0;

    .line 26
    .line 27
    .line 28
    move-result-object v6

    .line 29
    aget-object v7, v0, v4

    .line 30
    .line 31
    iget-object v8, p0, Lh8/l0;->q:[[J

    .line 32
    .line 33
    aget-object v8, v8, v5

    .line 34
    .line 35
    aget-wide v8, v8, v4

    .line 36
    .line 37
    sub-long v8, p3, v8

    .line 38
    .line 39
    invoke-virtual {v7, v6, p2, v8, v9}, Lh8/a;->a(Lh8/b0;Lk8/e;J)Lh8/z;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    aput-object v7, v2, v4

    .line 44
    .line 45
    iget-object v7, p0, Lh8/l0;->l:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    check-cast v7, Ljava/util/List;

    .line 52
    .line 53
    new-instance v8, Lh8/k0;

    .line 54
    .line 55
    aget-object v9, v2, v4

    .line 56
    .line 57
    invoke-direct {v8, v6, v9}, Lh8/k0;-><init>(Lh8/b0;Lh8/z;)V

    .line 58
    .line 59
    .line 60
    invoke-interface {v7, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    add-int/lit8 v4, v4, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    new-instance p1, Lh8/j0;

    .line 67
    .line 68
    iget-object p2, p0, Lh8/l0;->q:[[J

    .line 69
    .line 70
    aget-object p2, p2, v5

    .line 71
    .line 72
    iget-object p0, p0, Lh8/l0;->o:Lst/b;

    .line 73
    .line 74
    invoke-direct {p1, p0, p2, v2}, Lh8/j0;-><init>(Lst/b;[J[Lh8/z;)V

    .line 75
    .line 76
    .line 77
    return-object p1
.end method

.method public final g()Lt7/x;
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/l0;->k:[Lh8/a;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-lez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    aget-object p0, p0, v0

    .line 8
    .line 9
    invoke-virtual {p0}, Lh8/a;->g()Lt7/x;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    sget-object p0, Lh8/l0;->s:Lt7/x;

    .line 15
    .line 16
    return-object p0
.end method

.method public final i()V
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/l0;->r:Lio/ktor/utils/io/k0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0}, Lh8/k;->i()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    throw v0
.end method

.method public final k(Ly7/z;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lh8/k;->j:Ly7/z;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-static {p1}, Lw7/w;->k(Lm8/k;)Landroid/os/Handler;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lh8/k;->i:Landroid/os/Handler;

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    :goto_0
    iget-object v0, p0, Lh8/l0;->k:[Lh8/a;

    .line 12
    .line 13
    array-length v1, v0

    .line 14
    if-ge p1, v1, :cond_0

    .line 15
    .line 16
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    aget-object v0, v0, p1

    .line 21
    .line 22
    invoke-virtual {p0, v1, v0}, Lh8/k;->w(Ljava/lang/Object;Lh8/a;)V

    .line 23
    .line 24
    .line 25
    add-int/lit8 p1, p1, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-void
.end method

.method public final m(Lh8/z;)V
    .locals 8

    .line 1
    check-cast p1, Lh8/j0;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    move v1, v0

    .line 5
    :goto_0
    iget-object v2, p0, Lh8/l0;->k:[Lh8/a;

    .line 6
    .line 7
    array-length v3, v2

    .line 8
    if-ge v1, v3, :cond_4

    .line 9
    .line 10
    iget-object v3, p0, Lh8/l0;->l:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    check-cast v3, Ljava/util/List;

    .line 17
    .line 18
    iget-object v4, p1, Lh8/j0;->d:[Lh8/z;

    .line 19
    .line 20
    iget-object v5, p1, Lh8/j0;->e:[Z

    .line 21
    .line 22
    aget-boolean v6, v5, v1

    .line 23
    .line 24
    if-eqz v6, :cond_0

    .line 25
    .line 26
    aget-object v4, v4, v1

    .line 27
    .line 28
    check-cast v4, Lh8/d1;

    .line 29
    .line 30
    iget-object v4, v4, Lh8/d1;->d:Lh8/z;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    aget-object v4, v4, v1

    .line 34
    .line 35
    :goto_1
    move v6, v0

    .line 36
    :goto_2
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    if-ge v6, v7, :cond_2

    .line 41
    .line 42
    invoke-interface {v3, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v7

    .line 46
    check-cast v7, Lh8/k0;

    .line 47
    .line 48
    iget-object v7, v7, Lh8/k0;->b:Lh8/z;

    .line 49
    .line 50
    invoke-virtual {v7, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    if-eqz v7, :cond_1

    .line 55
    .line 56
    invoke-interface {v3, v6}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_1
    add-int/lit8 v6, v6, 0x1

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    :goto_3
    aget-object v2, v2, v1

    .line 64
    .line 65
    iget-object v3, p1, Lh8/j0;->d:[Lh8/z;

    .line 66
    .line 67
    aget-boolean v4, v5, v1

    .line 68
    .line 69
    if-eqz v4, :cond_3

    .line 70
    .line 71
    aget-object v3, v3, v1

    .line 72
    .line 73
    check-cast v3, Lh8/d1;

    .line 74
    .line 75
    iget-object v3, v3, Lh8/d1;->d:Lh8/z;

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_3
    aget-object v3, v3, v1

    .line 79
    .line 80
    :goto_4
    invoke-virtual {v2, v3}, Lh8/a;->m(Lh8/z;)V

    .line 81
    .line 82
    .line 83
    add-int/lit8 v1, v1, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_4
    return-void
.end method

.method public final o()V
    .locals 2

    .line 1
    invoke-super {p0}, Lh8/k;->o()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh8/l0;->m:[Lt7/p0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, -0x1

    .line 11
    iput v0, p0, Lh8/l0;->p:I

    .line 12
    .line 13
    iput-object v1, p0, Lh8/l0;->r:Lio/ktor/utils/io/k0;

    .line 14
    .line 15
    iget-object v0, p0, Lh8/l0;->n:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lh8/l0;->k:[Lh8/a;

    .line 21
    .line 22
    invoke-static {v0, p0}, Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final r(Lt7/x;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh8/l0;->k:[Lh8/a;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aget-object p0, p0, v0

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lh8/a;->r(Lt7/x;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final s(Ljava/lang/Object;Lh8/b0;)Lh8/b0;
    .locals 3

    .line 1
    check-cast p1, Ljava/lang/Integer;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iget-object p0, p0, Lh8/l0;->l:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljava/util/List;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    move v1, v0

    .line 17
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-ge v1, v2, :cond_1

    .line 22
    .line 23
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lh8/k0;

    .line 28
    .line 29
    iget-object v2, v2, Lh8/k0;->a:Lh8/b0;

    .line 30
    .line 31
    invoke-virtual {v2, p2}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    check-cast p0, Lh8/k0;

    .line 48
    .line 49
    iget-object p0, p0, Lh8/k0;->a:Lh8/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    const/4 p0, 0x0

    .line 56
    return-object p0
.end method

.method public final v(Ljava/lang/Object;Lh8/a;Lt7/p0;)V
    .locals 6

    .line 1
    check-cast p1, Ljava/lang/Integer;

    .line 2
    .line 3
    iget-object v0, p0, Lh8/l0;->r:Lio/ktor/utils/io/k0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    iget v0, p0, Lh8/l0;->p:I

    .line 9
    .line 10
    const/4 v1, -0x1

    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3}, Lt7/p0;->h()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iput v0, p0, Lh8/l0;->p:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    invoke-virtual {p3}, Lt7/p0;->h()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget v1, p0, Lh8/l0;->p:I

    .line 25
    .line 26
    if-eq v0, v1, :cond_2

    .line 27
    .line 28
    new-instance p1, Lio/ktor/utils/io/k0;

    .line 29
    .line 30
    invoke-direct {p1}, Ljava/io/IOException;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lh8/l0;->r:Lio/ktor/utils/io/k0;

    .line 34
    .line 35
    return-void

    .line 36
    :cond_2
    :goto_0
    iget-object v0, p0, Lh8/l0;->q:[[J

    .line 37
    .line 38
    array-length v0, v0

    .line 39
    const/4 v1, 0x0

    .line 40
    iget-object v2, p0, Lh8/l0;->m:[Lt7/p0;

    .line 41
    .line 42
    if-nez v0, :cond_3

    .line 43
    .line 44
    iget v0, p0, Lh8/l0;->p:I

    .line 45
    .line 46
    array-length v3, v2

    .line 47
    const/4 v4, 0x2

    .line 48
    new-array v4, v4, [I

    .line 49
    .line 50
    const/4 v5, 0x1

    .line 51
    aput v3, v4, v5

    .line 52
    .line 53
    aput v0, v4, v1

    .line 54
    .line 55
    sget-object v0, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 56
    .line 57
    invoke-static {v0, v4}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, [[J

    .line 62
    .line 63
    iput-object v0, p0, Lh8/l0;->q:[[J

    .line 64
    .line 65
    :cond_3
    iget-object v0, p0, Lh8/l0;->n:Ljava/util/ArrayList;

    .line 66
    .line 67
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    aput-object p3, v2, p1

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    if-eqz p1, :cond_4

    .line 81
    .line 82
    aget-object p1, v2, v1

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Lh8/a;->l(Lt7/p0;)V

    .line 85
    .line 86
    .line 87
    :cond_4
    :goto_1
    return-void
.end method
