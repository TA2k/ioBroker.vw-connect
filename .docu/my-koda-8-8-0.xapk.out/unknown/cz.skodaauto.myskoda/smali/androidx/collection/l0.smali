.class public final Landroidx/collection/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[Ljava/lang/Object;

.field public b:I

.field public c:Landroidx/collection/j0;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/16 v0, 0x10

    .line 5
    invoke-direct {p0, v0}, Landroidx/collection/l0;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-nez p1, :cond_0

    .line 2
    sget-object p1, Landroidx/collection/w0;->a:[Ljava/lang/Object;

    goto :goto_0

    .line 3
    :cond_0
    new-array p1, p1, [Ljava/lang/Object;

    .line 4
    :goto_0
    iput-object p1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length v2, v1

    .line 8
    if-ge v2, v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v0, v1}, Landroidx/collection/l0;->l(I[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 14
    .line 15
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 16
    .line 17
    aput-object p1, v0, v1

    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    iput v1, p0, Landroidx/collection/l0;->b:I

    .line 22
    .line 23
    return-void
.end method

.method public final b(Ljava/util/List;)V
    .locals 6

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    add-int/2addr v1, v0

    .line 15
    iget-object v2, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 16
    .line 17
    array-length v3, v2

    .line 18
    if-ge v3, v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v1, v2}, Landroidx/collection/l0;->l(I[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 24
    .line 25
    move-object v2, p1

    .line 26
    check-cast v2, Ljava/util/Collection;

    .line 27
    .line 28
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    const/4 v3, 0x0

    .line 33
    :goto_0
    if-ge v3, v2, :cond_2

    .line 34
    .line 35
    add-int v4, v3, v0

    .line 36
    .line 37
    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    aput-object v5, v1, v4

    .line 42
    .line 43
    add-int/lit8 v3, v3, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 47
    .line 48
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    add-int/2addr p1, v0

    .line 53
    iput p1, p0, Landroidx/collection/l0;->b:I

    .line 54
    .line 55
    :goto_1
    return-void
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 2
    .line 3
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-static {v2, v1, v3, v0}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput v2, p0, Landroidx/collection/l0;->b:I

    .line 11
    .line 12
    return-void
.end method

.method public final d()Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroidx/collection/l0;->g()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    aget-object p0, p0, v0

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    const-string p0, "ObjectList is empty."

    .line 14
    .line 15
    invoke-static {p0}, La1/a;->e(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    throw p0
.end method

.method public final e(I)Ljava/lang/Object;
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 8
    .line 9
    aget-object p0, p0, p1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->m(I)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    instance-of v0, p1, Landroidx/collection/l0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_3

    .line 5
    .line 6
    check-cast p1, Landroidx/collection/l0;

    .line 7
    .line 8
    iget v0, p1, Landroidx/collection/l0;->b:I

    .line 9
    .line 10
    iget v2, p0, Landroidx/collection/l0;->b:I

    .line 11
    .line 12
    if-eq v0, v2, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-object p0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 16
    .line 17
    iget-object p1, p1, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkp/r9;->m(II)Lgy0/j;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget v2, v0, Lgy0/h;->d:I

    .line 24
    .line 25
    iget v0, v0, Lgy0/h;->e:I

    .line 26
    .line 27
    if-gt v2, v0, :cond_2

    .line 28
    .line 29
    :goto_0
    aget-object v3, p0, v2

    .line 30
    .line 31
    aget-object v4, p1, v2

    .line 32
    .line 33
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-nez v3, :cond_1

    .line 38
    .line 39
    return v1

    .line 40
    :cond_1
    if-eq v2, v0, :cond_2

    .line 41
    .line 42
    add-int/lit8 v2, v2, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const/4 p0, 0x1

    .line 46
    return p0

    .line 47
    :cond_3
    :goto_1
    return v1
.end method

.method public final f(Ljava/lang/Object;)I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_1

    .line 3
    .line 4
    iget-object p1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 5
    .line 6
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 7
    .line 8
    :goto_0
    if-ge v0, p0, :cond_3

    .line 9
    .line 10
    aget-object v1, p1, v0

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    iget-object v1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 19
    .line 20
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 21
    .line 22
    :goto_1
    if-ge v0, p0, :cond_3

    .line 23
    .line 24
    aget-object v2, v1, v0

    .line 25
    .line 26
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_2

    .line 31
    .line 32
    return v0

    .line 33
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_3
    const/4 p0, -0x1

    .line 37
    return p0
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/l0;->b:I

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

.method public final h()Z
    .locals 0

    .line 1
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

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

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 2
    .line 3
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    move v3, v2

    .line 8
    :goto_0
    if-ge v2, p0, :cond_1

    .line 9
    .line 10
    aget-object v4, v0, v2

    .line 11
    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    move v4, v1

    .line 20
    :goto_1
    mul-int/lit8 v4, v4, 0x1f

    .line 21
    .line 22
    add-int/2addr v3, v4

    .line 23
    add-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    return v3
.end method

.method public final i(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->f(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

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

.method public final j(I)Ljava/lang/Object;
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    if-ltz p1, :cond_1

    .line 3
    .line 4
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 5
    .line 6
    if-ge p1, v1, :cond_1

    .line 7
    .line 8
    iget-object v2, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object v3, v2, p1

    .line 11
    .line 12
    add-int/lit8 v4, v1, -0x1

    .line 13
    .line 14
    if-eq p1, v4, :cond_0

    .line 15
    .line 16
    add-int/lit8 v4, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1, v4, v1, v2, v2}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    iget p1, p0, Landroidx/collection/l0;->b:I

    .line 22
    .line 23
    add-int/lit8 p1, p1, -0x1

    .line 24
    .line 25
    iput p1, p0, Landroidx/collection/l0;->b:I

    .line 26
    .line 27
    aput-object v0, v2, p1

    .line 28
    .line 29
    return-object v3

    .line 30
    :cond_1
    invoke-virtual {p0, p1}, Landroidx/collection/l0;->m(I)V

    .line 31
    .line 32
    .line 33
    throw v0
.end method

.method public final k(II)V
    .locals 4

    .line 1
    const-string v0, "Start ("

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-ltz p1, :cond_3

    .line 5
    .line 6
    iget v2, p0, Landroidx/collection/l0;->b:I

    .line 7
    .line 8
    if-gt p1, v2, :cond_3

    .line 9
    .line 10
    if-ltz p2, :cond_3

    .line 11
    .line 12
    if-gt p2, v2, :cond_3

    .line 13
    .line 14
    if-lt p2, p1, :cond_2

    .line 15
    .line 16
    if-eq p2, p1, :cond_1

    .line 17
    .line 18
    if-ge p2, v2, :cond_0

    .line 19
    .line 20
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 21
    .line 22
    invoke-static {p1, p2, v2, v0, v0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iget v0, p0, Landroidx/collection/l0;->b:I

    .line 26
    .line 27
    sub-int/2addr p2, p1

    .line 28
    sub-int p1, v0, p2

    .line 29
    .line 30
    iget-object p2, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 31
    .line 32
    invoke-static {p1, v0, v1, p2}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iput p1, p0, Landroidx/collection/l0;->b:I

    .line 36
    .line 37
    :cond_1
    return-void

    .line 38
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p1, ") is more than end ("

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const/16 p1, 0x29

    .line 55
    .line 56
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v1

    .line 67
    :cond_3
    const-string v2, ") and end ("

    .line 68
    .line 69
    const-string v3, ") must be in 0.."

    .line 70
    .line 71
    invoke-static {p1, p2, v0, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 76
    .line 77
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw v1
.end method

.method public final l(I[Ljava/lang/Object;)V
    .locals 2

    .line 1
    const-string v0, "oldContent"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p2

    .line 7
    mul-int/lit8 v1, v0, 0x3

    .line 8
    .line 9
    div-int/lit8 v1, v1, 0x2

    .line 10
    .line 11
    invoke-static {p1, v1}, Ljava/lang/Math;->max(II)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    new-array p1, p1, [Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-static {v1, v1, v0, p2, p1}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 22
    .line 23
    return-void
.end method

.method public final m(I)V
    .locals 2

    .line 1
    const-string v0, "Index "

    .line 2
    .line 3
    const-string v1, " must be in 0.."

    .line 4
    .line 5
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 10
    .line 11
    add-int/lit8 p0, p0, -0x1

    .line 12
    .line 13
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, La3/f;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, v1}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "["

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v2, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 15
    .line 16
    iget p0, p0, Landroidx/collection/l0;->b:I

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    :goto_0
    if-ge v3, p0, :cond_2

    .line 20
    .line 21
    aget-object v4, v2, v3

    .line 22
    .line 23
    const/4 v5, -0x1

    .line 24
    if-ne v3, v5, :cond_0

    .line 25
    .line 26
    const-string p0, "..."

    .line 27
    .line 28
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    if-eqz v3, :cond_1

    .line 33
    .line 34
    const-string v5, ", "

    .line 35
    .line 36
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    :cond_1
    invoke-virtual {v0, v4}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Ljava/lang/CharSequence;

    .line 44
    .line 45
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    add-int/lit8 v3, v3, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    const-string p0, "]"

    .line 52
    .line 53
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    :goto_1
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    const-string v0, "toString(...)"

    .line 61
    .line 62
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method
