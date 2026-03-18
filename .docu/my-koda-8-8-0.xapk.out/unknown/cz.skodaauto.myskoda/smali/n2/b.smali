.class public final Ln2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/RandomAccess;


# instance fields
.field public d:[Ljava/lang/Object;

.field public e:Landroidx/collection/j0;

.field public f:I


# direct methods
.method public constructor <init>([Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Ln2/b;->f:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final b(ILjava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Ln2/b;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length v1, v1

    .line 8
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ln2/b;->o(I)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget v1, p0, Ln2/b;->f:I

    .line 16
    .line 17
    if-eq p1, v1, :cond_1

    .line 18
    .line 19
    add-int/lit8 v2, p1, 0x1

    .line 20
    .line 21
    sub-int/2addr v1, p1

    .line 22
    invoke-static {v0, p1, v0, v2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    :cond_1
    aput-object p2, v0, p1

    .line 26
    .line 27
    iget p1, p0, Ln2/b;->f:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, 0x1

    .line 30
    .line 31
    iput p1, p0, Ln2/b;->f:I

    .line 32
    .line 33
    return-void
.end method

.method public final c(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Ln2/b;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length v1, v1

    .line 8
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ln2/b;->o(I)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    iget v1, p0, Ln2/b;->f:I

    .line 16
    .line 17
    aput-object p1, v0, v1

    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    iput v1, p0, Ln2/b;->f:I

    .line 22
    .line 23
    return-void
.end method

.method public final e(ILjava/util/List;)V
    .locals 6

    .line 1
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget v1, p0, Ln2/b;->f:I

    .line 13
    .line 14
    add-int/2addr v1, v0

    .line 15
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 16
    .line 17
    array-length v2, v2

    .line 18
    if-ge v2, v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v1}, Ln2/b;->o(I)V

    .line 21
    .line 22
    .line 23
    :cond_1
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 24
    .line 25
    iget v2, p0, Ln2/b;->f:I

    .line 26
    .line 27
    if-eq p1, v2, :cond_2

    .line 28
    .line 29
    add-int v3, p1, v0

    .line 30
    .line 31
    sub-int/2addr v2, p1

    .line 32
    invoke-static {v1, p1, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 33
    .line 34
    .line 35
    :cond_2
    move-object v2, p2

    .line 36
    check-cast v2, Ljava/util/Collection;

    .line 37
    .line 38
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    const/4 v3, 0x0

    .line 43
    :goto_0
    if-ge v3, v2, :cond_3

    .line 44
    .line 45
    add-int v4, p1, v3

    .line 46
    .line 47
    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    aput-object v5, v1, v4

    .line 52
    .line 53
    add-int/lit8 v3, v3, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_3
    iget p1, p0, Ln2/b;->f:I

    .line 57
    .line 58
    add-int/2addr p1, v0

    .line 59
    iput p1, p0, Ln2/b;->f:I

    .line 60
    .line 61
    return-void
.end method

.method public final f(ILn2/b;)V
    .locals 4

    .line 1
    iget v0, p2, Ln2/b;->f:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget v1, p0, Ln2/b;->f:I

    .line 7
    .line 8
    add-int/2addr v1, v0

    .line 9
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 10
    .line 11
    array-length v2, v2

    .line 12
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Ln2/b;->o(I)V

    .line 15
    .line 16
    .line 17
    :cond_1
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    iget v2, p0, Ln2/b;->f:I

    .line 20
    .line 21
    if-eq p1, v2, :cond_2

    .line 22
    .line 23
    add-int v3, p1, v0

    .line 24
    .line 25
    sub-int/2addr v2, p1

    .line 26
    invoke-static {v1, p1, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 27
    .line 28
    .line 29
    :cond_2
    iget-object p2, p2, Ln2/b;->d:[Ljava/lang/Object;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-static {p2, v2, v1, p1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 33
    .line 34
    .line 35
    iget p1, p0, Ln2/b;->f:I

    .line 36
    .line 37
    add-int/2addr p1, v0

    .line 38
    iput p1, p0, Ln2/b;->f:I

    .line 39
    .line 40
    return-void
.end method

.method public final g(ILjava/util/Collection;)Z
    .locals 5

    .line 1
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget v2, p0, Ln2/b;->f:I

    .line 14
    .line 15
    add-int/2addr v2, v0

    .line 16
    iget-object v3, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 17
    .line 18
    array-length v3, v3

    .line 19
    if-ge v3, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Ln2/b;->o(I)V

    .line 22
    .line 23
    .line 24
    :cond_1
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 25
    .line 26
    iget v3, p0, Ln2/b;->f:I

    .line 27
    .line 28
    if-eq p1, v3, :cond_2

    .line 29
    .line 30
    add-int v4, p1, v0

    .line 31
    .line 32
    sub-int/2addr v3, p1

    .line 33
    invoke-static {v2, p1, v2, v4, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 34
    .line 35
    .line 36
    :cond_2
    check-cast p2, Ljava/lang/Iterable;

    .line 37
    .line 38
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_4

    .line 47
    .line 48
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    add-int/lit8 v4, v1, 0x1

    .line 53
    .line 54
    if-ltz v1, :cond_3

    .line 55
    .line 56
    add-int/2addr v1, p1

    .line 57
    aput-object v3, v2, v1

    .line 58
    .line 59
    move v1, v4

    .line 60
    goto :goto_0

    .line 61
    :cond_3
    invoke-static {}, Ljp/k1;->r()V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    throw p0

    .line 66
    :cond_4
    iget p1, p0, Ln2/b;->f:I

    .line 67
    .line 68
    add-int/2addr p1, v0

    .line 69
    iput p1, p0, Ln2/b;->f:I

    .line 70
    .line 71
    const/4 p0, 0x1

    .line 72
    return p0
.end method

.method public final h()Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p0, Ln2/b;->e:Landroidx/collection/j0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/collection/j0;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Landroidx/collection/j0;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ln2/b;->e:Landroidx/collection/j0;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final i()V
    .locals 5

    .line 1
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p0, Ln2/b;->f:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move v3, v2

    .line 7
    :goto_0
    if-ge v3, v1, :cond_0

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    aput-object v4, v0, v3

    .line 11
    .line 12
    add-int/lit8 v3, v3, 0x1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iput v2, p0, Ln2/b;->f:I

    .line 16
    .line 17
    return-void
.end method

.method public final j(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    iget v0, p0, Ln2/b;->f:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    sub-int/2addr v0, v1

    .line 5
    const/4 v2, 0x0

    .line 6
    if-ltz v0, :cond_1

    .line 7
    .line 8
    move v3, v2

    .line 9
    :goto_0
    iget-object v4, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 10
    .line 11
    aget-object v4, v4, v3

    .line 12
    .line 13
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    return v1

    .line 20
    :cond_0
    if-eq v3, v0, :cond_1

    .line 21
    .line 22
    add-int/lit8 v3, v3, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    return v2
.end method

.method public final k(Ljava/lang/Object;)I
    .locals 3

    .line 1
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    iget p0, p0, Ln2/b;->f:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, p0, :cond_1

    .line 7
    .line 8
    aget-object v2, v0, v1

    .line 9
    .line 10
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    return v1

    .line 17
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    const/4 p0, -0x1

    .line 21
    return p0
.end method

.method public final l(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public final m(I)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    aget-object v1, v0, p1

    .line 4
    .line 5
    iget v2, p0, Ln2/b;->f:I

    .line 6
    .line 7
    add-int/lit8 v3, v2, -0x1

    .line 8
    .line 9
    if-eq p1, v3, :cond_0

    .line 10
    .line 11
    add-int/lit8 v3, p1, 0x1

    .line 12
    .line 13
    sub-int/2addr v2, v3

    .line 14
    invoke-static {v0, v3, v0, p1, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget p1, p0, Ln2/b;->f:I

    .line 18
    .line 19
    add-int/lit8 p1, p1, -0x1

    .line 20
    .line 21
    iput p1, p0, Ln2/b;->f:I

    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    aput-object p0, v0, p1

    .line 25
    .line 26
    return-object v1
.end method

.method public final n(II)V
    .locals 3

    .line 1
    if-le p2, p1, :cond_2

    .line 2
    .line 3
    iget v0, p0, Ln2/b;->f:I

    .line 4
    .line 5
    if-ge p2, v0, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 8
    .line 9
    sub-int/2addr v0, p2

    .line 10
    invoke-static {v1, p2, v1, p1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget v0, p0, Ln2/b;->f:I

    .line 14
    .line 15
    sub-int/2addr p2, p1

    .line 16
    sub-int p1, v0, p2

    .line 17
    .line 18
    add-int/lit8 v0, v0, -0x1

    .line 19
    .line 20
    if-gt p1, v0, :cond_1

    .line 21
    .line 22
    move p2, p1

    .line 23
    :goto_0
    iget-object v1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    aput-object v2, v1, p2

    .line 27
    .line 28
    if-eq p2, v0, :cond_1

    .line 29
    .line 30
    add-int/lit8 p2, p2, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iput p1, p0, Ln2/b;->f:I

    .line 34
    .line 35
    :cond_2
    return-void
.end method

.method public final o(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    mul-int/lit8 v2, v1, 0x2

    .line 5
    .line 6
    invoke-static {p1, v2}, Ljava/lang/Math;->max(II)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    new-array p1, p1, [Ljava/lang/Object;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-static {v0, v2, p1, v2, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method
