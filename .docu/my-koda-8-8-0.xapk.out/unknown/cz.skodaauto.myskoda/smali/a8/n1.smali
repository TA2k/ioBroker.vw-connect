.class public final La8/n1;
.super Lt7/p0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic k:I


# instance fields
.field public final b:I

.field public final c:Lh8/a1;

.field public final d:I

.field public final e:I

.field public final f:[I

.field public final g:[I

.field public final h:[Lt7/p0;

.field public final i:[Ljava/lang/Object;

.field public final j:Ljava/util/HashMap;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Lh8/a1;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    new-array v0, v0, [Lt7/p0;

    .line 2
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, La8/a1;

    add-int/lit8 v5, v3, 0x1

    .line 3
    invoke-interface {v4}, La8/a1;->b()Lt7/p0;

    move-result-object v4

    aput-object v4, v0, v3

    move v3, v5

    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, La8/a1;

    add-int/lit8 v4, v2, 0x1

    .line 6
    invoke-interface {v3}, La8/a1;->a()Ljava/lang/Object;

    move-result-object v3

    aput-object v3, v1, v2

    move v2, v4

    goto :goto_1

    .line 7
    :cond_1
    invoke-direct {p0, v0, v1, p2}, La8/n1;-><init>([Lt7/p0;[Ljava/lang/Object;Lh8/a1;)V

    return-void
.end method

.method public constructor <init>([Lt7/p0;[Ljava/lang/Object;Lh8/a1;)V
    .locals 7

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p3, p0, La8/n1;->c:Lh8/a1;

    .line 10
    iget-object p3, p3, Lh8/a1;->b:[I

    array-length p3, p3

    .line 11
    iput p3, p0, La8/n1;->b:I

    .line 12
    array-length p3, p1

    .line 13
    iput-object p1, p0, La8/n1;->h:[Lt7/p0;

    .line 14
    new-array v0, p3, [I

    iput-object v0, p0, La8/n1;->f:[I

    .line 15
    new-array p3, p3, [I

    iput-object p3, p0, La8/n1;->g:[I

    .line 16
    iput-object p2, p0, La8/n1;->i:[Ljava/lang/Object;

    .line 17
    new-instance p3, Ljava/util/HashMap;

    invoke-direct {p3}, Ljava/util/HashMap;-><init>()V

    iput-object p3, p0, La8/n1;->j:Ljava/util/HashMap;

    .line 18
    array-length p3, p1

    const/4 v0, 0x0

    move v1, v0

    move v2, v1

    move v3, v2

    :goto_0
    if-ge v0, p3, :cond_0

    aget-object v4, p1, v0

    .line 19
    iget-object v5, p0, La8/n1;->h:[Lt7/p0;

    aput-object v4, v5, v3

    .line 20
    iget-object v5, p0, La8/n1;->g:[I

    aput v1, v5, v3

    .line 21
    iget-object v5, p0, La8/n1;->f:[I

    aput v2, v5, v3

    .line 22
    invoke-virtual {v4}, Lt7/p0;->o()I

    move-result v4

    add-int/2addr v1, v4

    .line 23
    iget-object v4, p0, La8/n1;->h:[Lt7/p0;

    aget-object v4, v4, v3

    invoke-virtual {v4}, Lt7/p0;->h()I

    move-result v4

    add-int/2addr v2, v4

    .line 24
    iget-object v4, p0, La8/n1;->j:Ljava/util/HashMap;

    aget-object v5, p2, v3

    add-int/lit8 v6, v3, 0x1

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v4, v5, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v0, v0, 0x1

    move v3, v6

    goto :goto_0

    .line 25
    :cond_0
    iput v1, p0, La8/n1;->d:I

    .line 26
    iput v2, p0, La8/n1;->e:I

    return-void
.end method


# virtual methods
.method public final a(Z)I
    .locals 4

    .line 1
    iget v0, p0, La8/n1;->b:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    if-eqz p1, :cond_2

    .line 9
    .line 10
    iget-object v2, p0, La8/n1;->c:Lh8/a1;

    .line 11
    .line 12
    iget-object v2, v2, Lh8/a1;->b:[I

    .line 13
    .line 14
    array-length v3, v2

    .line 15
    if-lez v3, :cond_1

    .line 16
    .line 17
    aget v0, v2, v0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    move v0, v1

    .line 21
    :cond_2
    :goto_0
    iget-object v2, p0, La8/n1;->h:[Lt7/p0;

    .line 22
    .line 23
    aget-object v3, v2, v0

    .line 24
    .line 25
    invoke-virtual {v3}, Lt7/p0;->p()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_3

    .line 30
    .line 31
    invoke-virtual {p0, v0, p1}, La8/n1;->q(IZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-ne v0, v1, :cond_2

    .line 36
    .line 37
    :goto_1
    return v1

    .line 38
    :cond_3
    iget-object p0, p0, La8/n1;->g:[I

    .line 39
    .line 40
    aget p0, p0, v0

    .line 41
    .line 42
    aget-object v0, v2, v0

    .line 43
    .line 44
    invoke-virtual {v0, p1}, Lt7/p0;->a(Z)I

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    add-int/2addr p1, p0

    .line 49
    return p1
.end method

.method public final b(Ljava/lang/Object;)I
    .locals 3

    .line 1
    instance-of v0, p1, Landroid/util/Pair;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    check-cast p1, Landroid/util/Pair;

    .line 8
    .line 9
    iget-object v0, p1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object p1, p1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v2, p0, La8/n1;->j:Ljava/util/HashMap;

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Ljava/lang/Integer;

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    move v0, v1

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    :goto_0
    if-ne v0, v1, :cond_2

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_2
    iget-object v2, p0, La8/n1;->h:[Lt7/p0;

    .line 33
    .line 34
    aget-object v2, v2, v0

    .line 35
    .line 36
    invoke-virtual {v2, p1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    if-ne p1, v1, :cond_3

    .line 41
    .line 42
    :goto_1
    return v1

    .line 43
    :cond_3
    iget-object p0, p0, La8/n1;->f:[I

    .line 44
    .line 45
    aget p0, p0, v0

    .line 46
    .line 47
    add-int/2addr p0, p1

    .line 48
    return p0
.end method

.method public final c(Z)I
    .locals 4

    .line 1
    const/4 v0, -0x1

    .line 2
    iget v1, p0, La8/n1;->b:I

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    if-eqz p1, :cond_2

    .line 8
    .line 9
    iget-object v1, p0, La8/n1;->c:Lh8/a1;

    .line 10
    .line 11
    iget-object v1, v1, Lh8/a1;->b:[I

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    if-lez v2, :cond_1

    .line 15
    .line 16
    array-length v2, v1

    .line 17
    add-int/lit8 v2, v2, -0x1

    .line 18
    .line 19
    aget v1, v1, v2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move v1, v0

    .line 23
    goto :goto_0

    .line 24
    :cond_2
    add-int/lit8 v1, v1, -0x1

    .line 25
    .line 26
    :cond_3
    :goto_0
    iget-object v2, p0, La8/n1;->h:[Lt7/p0;

    .line 27
    .line 28
    aget-object v3, v2, v1

    .line 29
    .line 30
    invoke-virtual {v3}, Lt7/p0;->p()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_4

    .line 35
    .line 36
    invoke-virtual {p0, v1, p1}, La8/n1;->r(IZ)I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-ne v1, v0, :cond_3

    .line 41
    .line 42
    :goto_1
    return v0

    .line 43
    :cond_4
    iget-object p0, p0, La8/n1;->g:[I

    .line 44
    .line 45
    aget p0, p0, v1

    .line 46
    .line 47
    aget-object v0, v2, v1

    .line 48
    .line 49
    invoke-virtual {v0, p1}, Lt7/p0;->c(Z)I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    add-int/2addr p1, p0

    .line 54
    return p1
.end method

.method public final e(IIZ)I
    .locals 7

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    iget-object v1, p0, La8/n1;->g:[I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v1, v0, v2, v2}, Lw7/w;->c([IIZZ)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    aget v3, v1, v0

    .line 11
    .line 12
    iget-object v4, p0, La8/n1;->h:[Lt7/p0;

    .line 13
    .line 14
    aget-object v5, v4, v0

    .line 15
    .line 16
    sub-int/2addr p1, v3

    .line 17
    const/4 v6, 0x2

    .line 18
    if-ne p2, v6, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v2, p2

    .line 22
    :goto_0
    invoke-virtual {v5, p1, v2, p3}, Lt7/p0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    const/4 v2, -0x1

    .line 27
    if-eq p1, v2, :cond_1

    .line 28
    .line 29
    add-int/2addr v3, p1

    .line 30
    return v3

    .line 31
    :cond_1
    invoke-virtual {p0, v0, p3}, La8/n1;->q(IZ)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    :goto_1
    if-eq p1, v2, :cond_2

    .line 36
    .line 37
    aget-object v0, v4, p1

    .line 38
    .line 39
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_2

    .line 44
    .line 45
    invoke-virtual {p0, p1, p3}, La8/n1;->q(IZ)I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-eq p1, v2, :cond_3

    .line 51
    .line 52
    aget p0, v1, p1

    .line 53
    .line 54
    aget-object p1, v4, p1

    .line 55
    .line 56
    invoke-virtual {p1, p3}, Lt7/p0;->a(Z)I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    add-int/2addr p1, p0

    .line 61
    return p1

    .line 62
    :cond_3
    if-ne p2, v6, :cond_4

    .line 63
    .line 64
    invoke-virtual {p0, p3}, La8/n1;->a(Z)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    return p0

    .line 69
    :cond_4
    return v2
.end method

.method public final f(ILt7/n0;Z)Lt7/n0;
    .locals 4

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, La8/n1;->f:[I

    .line 5
    .line 6
    invoke-static {v2, v0, v1, v1}, Lw7/w;->c([IIZZ)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iget-object v1, p0, La8/n1;->g:[I

    .line 11
    .line 12
    aget v1, v1, v0

    .line 13
    .line 14
    aget v2, v2, v0

    .line 15
    .line 16
    iget-object v3, p0, La8/n1;->h:[Lt7/p0;

    .line 17
    .line 18
    aget-object v3, v3, v0

    .line 19
    .line 20
    sub-int/2addr p1, v2

    .line 21
    invoke-virtual {v3, p1, p2, p3}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 22
    .line 23
    .line 24
    iget p1, p2, Lt7/n0;->c:I

    .line 25
    .line 26
    add-int/2addr p1, v1

    .line 27
    iput p1, p2, Lt7/n0;->c:I

    .line 28
    .line 29
    if-eqz p3, :cond_0

    .line 30
    .line 31
    iget-object p0, p0, La8/n1;->i:[Ljava/lang/Object;

    .line 32
    .line 33
    aget-object p0, p0, v0

    .line 34
    .line 35
    iget-object p1, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    invoke-static {p0, p1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    iput-object p0, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 45
    .line 46
    :cond_0
    return-object p2
.end method

.method public final g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;
    .locals 3

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Landroid/util/Pair;

    .line 3
    .line 4
    iget-object v1, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 5
    .line 6
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object v2, p0, La8/n1;->j:Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    const/4 v1, -0x1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    :goto_0
    iget-object v2, p0, La8/n1;->g:[I

    .line 25
    .line 26
    aget v2, v2, v1

    .line 27
    .line 28
    iget-object p0, p0, La8/n1;->h:[Lt7/p0;

    .line 29
    .line 30
    aget-object p0, p0, v1

    .line 31
    .line 32
    invoke-virtual {p0, v0, p2}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 33
    .line 34
    .line 35
    iget p0, p2, Lt7/n0;->c:I

    .line 36
    .line 37
    add-int/2addr p0, v2

    .line 38
    iput p0, p2, Lt7/n0;->c:I

    .line 39
    .line 40
    iput-object p1, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 41
    .line 42
    return-object p2
.end method

.method public final h()I
    .locals 0

    .line 1
    iget p0, p0, La8/n1;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public final k(IIZ)I
    .locals 7

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    iget-object v1, p0, La8/n1;->g:[I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v1, v0, v2, v2}, Lw7/w;->c([IIZZ)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    aget v3, v1, v0

    .line 11
    .line 12
    iget-object v4, p0, La8/n1;->h:[Lt7/p0;

    .line 13
    .line 14
    aget-object v5, v4, v0

    .line 15
    .line 16
    sub-int/2addr p1, v3

    .line 17
    const/4 v6, 0x2

    .line 18
    if-ne p2, v6, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v2, p2

    .line 22
    :goto_0
    invoke-virtual {v5, p1, v2, p3}, Lt7/p0;->k(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    const/4 v2, -0x1

    .line 27
    if-eq p1, v2, :cond_1

    .line 28
    .line 29
    add-int/2addr v3, p1

    .line 30
    return v3

    .line 31
    :cond_1
    invoke-virtual {p0, v0, p3}, La8/n1;->r(IZ)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    :goto_1
    if-eq p1, v2, :cond_2

    .line 36
    .line 37
    aget-object v0, v4, p1

    .line 38
    .line 39
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_2

    .line 44
    .line 45
    invoke-virtual {p0, p1, p3}, La8/n1;->r(IZ)I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    if-eq p1, v2, :cond_3

    .line 51
    .line 52
    aget p0, v1, p1

    .line 53
    .line 54
    aget-object p1, v4, p1

    .line 55
    .line 56
    invoke-virtual {p1, p3}, Lt7/p0;->c(Z)I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    add-int/2addr p1, p0

    .line 61
    return p1

    .line 62
    :cond_3
    if-ne p2, v6, :cond_4

    .line 63
    .line 64
    invoke-virtual {p0, p3}, La8/n1;->c(Z)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    return p0

    .line 69
    :cond_4
    return v2
.end method

.method public final l(I)Ljava/lang/Object;
    .locals 3

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, La8/n1;->f:[I

    .line 5
    .line 6
    invoke-static {v2, v0, v1, v1}, Lw7/w;->c([IIZZ)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    aget v1, v2, v0

    .line 11
    .line 12
    iget-object v2, p0, La8/n1;->h:[Lt7/p0;

    .line 13
    .line 14
    aget-object v2, v2, v0

    .line 15
    .line 16
    sub-int/2addr p1, v1

    .line 17
    invoke-virtual {v2, p1}, Lt7/p0;->l(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iget-object p0, p0, La8/n1;->i:[Ljava/lang/Object;

    .line 22
    .line 23
    aget-object p0, p0, v0

    .line 24
    .line 25
    invoke-static {p0, p1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public final m(ILt7/o0;J)Lt7/o0;
    .locals 4

    .line 1
    add-int/lit8 v0, p1, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, La8/n1;->g:[I

    .line 5
    .line 6
    invoke-static {v2, v0, v1, v1}, Lw7/w;->c([IIZZ)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    aget v1, v2, v0

    .line 11
    .line 12
    iget-object v2, p0, La8/n1;->f:[I

    .line 13
    .line 14
    aget v2, v2, v0

    .line 15
    .line 16
    iget-object v3, p0, La8/n1;->h:[Lt7/p0;

    .line 17
    .line 18
    aget-object v3, v3, v0

    .line 19
    .line 20
    sub-int/2addr p1, v1

    .line 21
    invoke-virtual {v3, p1, p2, p3, p4}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, La8/n1;->i:[Ljava/lang/Object;

    .line 25
    .line 26
    aget-object p0, p0, v0

    .line 27
    .line 28
    sget-object p1, Lt7/o0;->p:Ljava/lang/Object;

    .line 29
    .line 30
    iget-object p3, p2, Lt7/o0;->a:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-virtual {p1, p3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-eqz p1, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    iget-object p1, p2, Lt7/o0;->a:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {p0, p1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    :goto_0
    iput-object p0, p2, Lt7/o0;->a:Ljava/lang/Object;

    .line 46
    .line 47
    iget p0, p2, Lt7/o0;->m:I

    .line 48
    .line 49
    add-int/2addr p0, v2

    .line 50
    iput p0, p2, Lt7/o0;->m:I

    .line 51
    .line 52
    iget p0, p2, Lt7/o0;->n:I

    .line 53
    .line 54
    add-int/2addr p0, v2

    .line 55
    iput p0, p2, Lt7/o0;->n:I

    .line 56
    .line 57
    return-object p2
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, La8/n1;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final q(IZ)I
    .locals 1

    .line 1
    const/4 v0, -0x1

    .line 2
    if-eqz p2, :cond_1

    .line 3
    .line 4
    iget-object p0, p0, La8/n1;->c:Lh8/a1;

    .line 5
    .line 6
    iget-object p2, p0, Lh8/a1;->c:[I

    .line 7
    .line 8
    aget p1, p2, p1

    .line 9
    .line 10
    add-int/lit8 p1, p1, 0x1

    .line 11
    .line 12
    iget-object p0, p0, Lh8/a1;->b:[I

    .line 13
    .line 14
    array-length p2, p0

    .line 15
    if-ge p1, p2, :cond_0

    .line 16
    .line 17
    aget p0, p0, p1

    .line 18
    .line 19
    return p0

    .line 20
    :cond_0
    return v0

    .line 21
    :cond_1
    iget p0, p0, La8/n1;->b:I

    .line 22
    .line 23
    add-int/lit8 p0, p0, -0x1

    .line 24
    .line 25
    if-ge p1, p0, :cond_2

    .line 26
    .line 27
    add-int/lit8 p1, p1, 0x1

    .line 28
    .line 29
    return p1

    .line 30
    :cond_2
    return v0
.end method

.method public final r(IZ)I
    .locals 1

    .line 1
    const/4 v0, -0x1

    .line 2
    if-eqz p2, :cond_1

    .line 3
    .line 4
    iget-object p0, p0, La8/n1;->c:Lh8/a1;

    .line 5
    .line 6
    iget-object p2, p0, Lh8/a1;->c:[I

    .line 7
    .line 8
    aget p1, p2, p1

    .line 9
    .line 10
    add-int/2addr p1, v0

    .line 11
    if-ltz p1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lh8/a1;->b:[I

    .line 14
    .line 15
    aget p0, p0, p1

    .line 16
    .line 17
    return p0

    .line 18
    :cond_0
    return v0

    .line 19
    :cond_1
    if-lez p1, :cond_2

    .line 20
    .line 21
    add-int/lit8 p1, p1, -0x1

    .line 22
    .line 23
    return p1

    .line 24
    :cond_2
    return v0
.end method
