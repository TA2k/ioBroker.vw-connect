.class public final Lg1/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:[F

.field public final c:I


# direct methods
.method public constructor <init>(Ljava/util/List;[F)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/z;->a:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Lg1/z;->b:[F

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    array-length v1, p2

    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v1, "DraggableAnchors were constructed with inconsistent key-value sizes. Keys: "

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string p1, " | Anchors: "

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-static {p2}, Lmx0/n;->Y([F)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-static {p1}, Lj1/b;->a(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    :goto_0
    array-length p1, p2

    .line 46
    iput p1, p0, Lg1/z;->c:I

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final a(F)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lg1/z;->b:[F

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, -0x1

    .line 5
    const/high16 v3, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    move v5, v4

    .line 9
    :goto_0
    if-ge v4, v1, :cond_1

    .line 10
    .line 11
    aget v6, v0, v4

    .line 12
    .line 13
    add-int/lit8 v7, v5, 0x1

    .line 14
    .line 15
    sub-float v6, p1, v6

    .line 16
    .line 17
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    cmpg-float v8, v6, v3

    .line 22
    .line 23
    if-gtz v8, :cond_0

    .line 24
    .line 25
    move v2, v5

    .line 26
    move v3, v6

    .line 27
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 28
    .line 29
    move v5, v7

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    iget-object p0, p0, Lg1/z;->a:Ljava/util/List;

    .line 32
    .line 33
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public final b(FZ)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lg1/z;->b:[F

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, -0x1

    .line 5
    const/high16 v3, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    move v6, v3

    .line 9
    move v5, v4

    .line 10
    :goto_0
    if-ge v4, v1, :cond_3

    .line 11
    .line 12
    aget v7, v0, v4

    .line 13
    .line 14
    add-int/lit8 v8, v5, 0x1

    .line 15
    .line 16
    if-eqz p2, :cond_0

    .line 17
    .line 18
    sub-float/2addr v7, p1

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    sub-float v7, p1, v7

    .line 21
    .line 22
    :goto_1
    const/4 v9, 0x0

    .line 23
    cmpg-float v9, v7, v9

    .line 24
    .line 25
    if-gez v9, :cond_1

    .line 26
    .line 27
    move v7, v3

    .line 28
    :cond_1
    cmpg-float v9, v7, v6

    .line 29
    .line 30
    if-gtz v9, :cond_2

    .line 31
    .line 32
    move v2, v5

    .line 33
    move v6, v7

    .line 34
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 35
    .line 36
    move v5, v8

    .line 37
    goto :goto_0

    .line 38
    :cond_3
    iget-object p0, p0, Lg1/z;->a:Ljava/util/List;

    .line 39
    .line 40
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method public final c(Ljava/lang/Object;)F
    .locals 1

    .line 1
    iget-object v0, p0, Lg1/z;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-ltz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lg1/z;->b:[F

    .line 10
    .line 11
    array-length v0, p0

    .line 12
    if-ge p1, v0, :cond_0

    .line 13
    .line 14
    aget p0, p0, p1

    .line 15
    .line 16
    return p0

    .line 17
    :cond_0
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 18
    .line 19
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lg1/z;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lg1/z;

    .line 12
    .line 13
    iget-object v1, p1, Lg1/z;->a:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p0, Lg1/z;->a:Ljava/util/List;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lg1/z;->b:[F

    .line 25
    .line 26
    iget-object v3, p1, Lg1/z;->b:[F

    .line 27
    .line 28
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([F[F)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget p0, p0, Lg1/z;->c:I

    .line 36
    .line 37
    iget p1, p1, Lg1/z;->c:I

    .line 38
    .line 39
    if-eq p0, p1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lg1/z;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lg1/z;->b:[F

    .line 10
    .line 11
    invoke-static {v1}, Ljava/util/Arrays;->hashCode([F)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget p0, p0, Lg1/z;->c:I

    .line 19
    .line 20
    add-int/2addr v1, p0

    .line 21
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DraggableAnchors(anchors={"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    iget v2, p0, Lg1/z;->c:I

    .line 10
    .line 11
    if-ge v1, v2, :cond_2

    .line 12
    .line 13
    new-instance v3, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 16
    .line 17
    .line 18
    iget-object v4, p0, Lg1/z;->a:Ljava/util/List;

    .line 19
    .line 20
    invoke-static {v1, v4}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const/16 v4, 0x3d

    .line 28
    .line 29
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    if-ltz v1, :cond_0

    .line 33
    .line 34
    iget-object v4, p0, Lg1/z;->b:[F

    .line 35
    .line 36
    array-length v5, v4

    .line 37
    if-ge v1, v5, :cond_0

    .line 38
    .line 39
    aget v4, v4, v1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_0
    const/high16 v4, 0x7fc00000    # Float.NaN

    .line 43
    .line 44
    :goto_1
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    add-int/lit8 v2, v2, -0x1

    .line 55
    .line 56
    if-ge v1, v2, :cond_1

    .line 57
    .line 58
    const-string v2, ", "

    .line 59
    .line 60
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    const-string p0, "})"

    .line 67
    .line 68
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    const-string v0, "toString(...)"

    .line 76
    .line 77
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-object p0
.end method
