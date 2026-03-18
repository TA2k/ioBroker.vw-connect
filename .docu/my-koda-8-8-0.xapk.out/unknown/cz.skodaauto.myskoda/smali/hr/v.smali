.class public final Lhr/v;
.super Ljava/util/AbstractMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final m:Ljava/lang/Object;


# instance fields
.field public transient d:Ljava/lang/Object;

.field public transient e:[I

.field public transient f:[Ljava/lang/Object;

.field public transient g:[Ljava/lang/Object;

.field public transient h:I

.field public transient i:I

.field public transient j:Lhr/s;

.field public transient k:Lhr/s;

.field public transient l:Lhr/n;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhr/v;->m:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public static a()Lhr/v;
    .locals 4

    .line 1
    new-instance v0, Lhr/v;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/AbstractMap;-><init>()V

    .line 4
    .line 5
    .line 6
    const v1, 0x3fffffff    # 1.9999999f

    .line 7
    .line 8
    .line 9
    const/16 v2, 0x8

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-static {v2, v1}, Ljava/lang/Math;->min(II)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    iput v1, v0, Lhr/v;->h:I

    .line 21
    .line 22
    return-object v0
.end method


# virtual methods
.method public final b()Ljava/util/Map;
    .locals 1

    .line 1
    iget-object p0, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v0, p0, Ljava/util/Map;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Ljava/util/Map;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public final c()I
    .locals 1

    .line 1
    iget p0, p0, Lhr/v;->h:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x1f

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    shl-int p0, v0, p0

    .line 7
    .line 8
    sub-int/2addr p0, v0

    .line 9
    return p0
.end method

.method public final clear()V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lhr/v;->f()Z

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
    iget v0, p0, Lhr/v;->h:I

    .line 9
    .line 10
    add-int/lit8 v0, v0, 0x20

    .line 11
    .line 12
    iput v0, p0, Lhr/v;->h:I

    .line 13
    .line 14
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v1, 0x0

    .line 19
    const/4 v2, 0x0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0}, Lhr/v;->size()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const v4, 0x3fffffff    # 1.9999999f

    .line 27
    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    iput v3, p0, Lhr/v;->h:I

    .line 39
    .line 40
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 44
    .line 45
    iput v2, p0, Lhr/v;->i:I

    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    invoke-virtual {p0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iget v3, p0, Lhr/v;->i:I

    .line 53
    .line 54
    invoke-static {v0, v2, v3, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget v3, p0, Lhr/v;->i:I

    .line 62
    .line 63
    invoke-static {v0, v2, v3, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 67
    .line 68
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    instance-of v1, v0, [B

    .line 72
    .line 73
    if-eqz v1, :cond_2

    .line 74
    .line 75
    check-cast v0, [B

    .line 76
    .line 77
    invoke-static {v0, v2}, Ljava/util/Arrays;->fill([BB)V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_2
    instance-of v1, v0, [S

    .line 82
    .line 83
    if-eqz v1, :cond_3

    .line 84
    .line 85
    check-cast v0, [S

    .line 86
    .line 87
    invoke-static {v0, v2}, Ljava/util/Arrays;->fill([SS)V

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    check-cast v0, [I

    .line 92
    .line 93
    invoke-static {v0, v2}, Ljava/util/Arrays;->fill([II)V

    .line 94
    .line 95
    .line 96
    :goto_0
    invoke-virtual {p0}, Lhr/v;->h()[I

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iget v1, p0, Lhr/v;->i:I

    .line 101
    .line 102
    invoke-static {v0, v2, v1, v2}, Ljava/util/Arrays;->fill([IIII)V

    .line 103
    .line 104
    .line 105
    iput v2, p0, Lhr/v;->i:I

    .line 106
    .line 107
    return-void
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lhr/v;->d(Ljava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const/4 p1, -0x1

    .line 17
    if-eq p0, p1, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_1
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final containsValue(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, Ljava/util/Map;->containsValue(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    move v1, v0

    .line 14
    :goto_0
    iget v2, p0, Lhr/v;->i:I

    .line 15
    .line 16
    if-ge v1, v2, :cond_2

    .line 17
    .line 18
    invoke-virtual {p0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    aget-object v2, v2, v1

    .line 23
    .line 24
    invoke-static {p1, v2}, Lkp/h9;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    return v0
.end method

.method public final d(Ljava/lang/Object;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Lhr/v;->f()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, -0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-static {p1}, Lhr/q;->p(Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0}, Lhr/v;->c()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    iget-object v3, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 18
    .line 19
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    and-int v4, v0, v2

    .line 23
    .line 24
    invoke-static {v4, v3}, Lhr/q;->q(ILjava/lang/Object;)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-nez v3, :cond_1

    .line 29
    .line 30
    return v1

    .line 31
    :cond_1
    not-int v4, v2

    .line 32
    and-int/2addr v0, v4

    .line 33
    :cond_2
    add-int/lit8 v3, v3, -0x1

    .line 34
    .line 35
    invoke-virtual {p0}, Lhr/v;->h()[I

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    aget v5, v5, v3

    .line 40
    .line 41
    and-int v6, v5, v4

    .line 42
    .line 43
    if-ne v6, v0, :cond_3

    .line 44
    .line 45
    invoke-virtual {p0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    aget-object v6, v6, v3

    .line 50
    .line 51
    invoke-static {p1, v6}, Lkp/h9;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    if-eqz v6, :cond_3

    .line 56
    .line 57
    return v3

    .line 58
    :cond_3
    and-int v3, v5, v2

    .line 59
    .line 60
    if-nez v3, :cond_2

    .line 61
    .line 62
    return v1
.end method

.method public final e(II)V
    .locals 9

    .line 1
    iget-object v0, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lhr/v;->h()[I

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {p0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {p0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {p0}, Lhr/v;->size()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/lit8 v4, p0, -0x1

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    if-ge p1, v4, :cond_2

    .line 27
    .line 28
    aget-object v7, v2, v4

    .line 29
    .line 30
    aput-object v7, v2, p1

    .line 31
    .line 32
    aget-object v8, v3, v4

    .line 33
    .line 34
    aput-object v8, v3, p1

    .line 35
    .line 36
    aput-object v6, v2, v4

    .line 37
    .line 38
    aput-object v6, v3, v4

    .line 39
    .line 40
    aget v2, v1, v4

    .line 41
    .line 42
    aput v2, v1, p1

    .line 43
    .line 44
    aput v5, v1, v4

    .line 45
    .line 46
    invoke-static {v7}, Lhr/q;->p(Ljava/lang/Object;)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    and-int/2addr v2, p2

    .line 51
    invoke-static {v2, v0}, Lhr/q;->q(ILjava/lang/Object;)I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    if-ne v3, p0, :cond_0

    .line 56
    .line 57
    add-int/lit8 p1, p1, 0x1

    .line 58
    .line 59
    invoke-static {v2, v0, p1}, Lhr/q;->r(ILjava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_0
    :goto_0
    add-int/lit8 v3, v3, -0x1

    .line 64
    .line 65
    aget v0, v1, v3

    .line 66
    .line 67
    and-int v2, v0, p2

    .line 68
    .line 69
    if-ne v2, p0, :cond_1

    .line 70
    .line 71
    add-int/lit8 p1, p1, 0x1

    .line 72
    .line 73
    invoke-static {v0, p1, p2}, Lhr/q;->k(III)I

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    aput p0, v1, v3

    .line 78
    .line 79
    return-void

    .line 80
    :cond_1
    move v3, v2

    .line 81
    goto :goto_0

    .line 82
    :cond_2
    aput-object v6, v2, p1

    .line 83
    .line 84
    aput-object v6, v3, p1

    .line 85
    .line 86
    aput v5, v1, p1

    .line 87
    .line 88
    return-void
.end method

.method public final entrySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Lhr/v;->k:Lhr/s;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/s;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Lhr/s;-><init>(Lhr/v;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lhr/v;->k:Lhr/s;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final f()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/v;->d:Ljava/lang/Object;

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

.method public final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Lhr/v;->f()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {p0}, Lhr/v;->c()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    iget-object v4, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {v4}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lhr/v;->h()[I

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    invoke-virtual {p0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    const/4 v7, 0x0

    .line 26
    const/4 v2, 0x0

    .line 27
    move-object v1, p1

    .line 28
    invoke-static/range {v1 .. v7}, Lhr/q;->m(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;[I[Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    const/4 v0, -0x1

    .line 33
    if-ne p1, v0, :cond_1

    .line 34
    .line 35
    :goto_0
    sget-object p0, Lhr/v;->m:Ljava/lang/Object;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    invoke-virtual {p0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    aget-object v0, v0, p1

    .line 43
    .line 44
    invoke-virtual {p0, p1, v3}, Lhr/v;->e(II)V

    .line 45
    .line 46
    .line 47
    iget p1, p0, Lhr/v;->i:I

    .line 48
    .line 49
    add-int/lit8 p1, p1, -0x1

    .line 50
    .line 51
    iput p1, p0, Lhr/v;->i:I

    .line 52
    .line 53
    iget p1, p0, Lhr/v;->h:I

    .line 54
    .line 55
    add-int/lit8 p1, p1, 0x20

    .line 56
    .line 57
    iput p1, p0, Lhr/v;->h:I

    .line 58
    .line 59
    return-object v0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lhr/v;->d(Ljava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    const/4 v0, -0x1

    .line 17
    if-ne p1, v0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_1
    invoke-virtual {p0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    aget-object p0, p0, p1

    .line 26
    .line 27
    return-object p0
.end method

.method public final h()[I
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/v;->e:[I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p0, [I

    .line 7
    .line 8
    return-object p0
.end method

.method public final i()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/v;->f:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p0, [Ljava/lang/Object;

    .line 7
    .line 8
    return-object p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/v;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

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

.method public final j()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lhr/v;->g:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    check-cast p0, [Ljava/lang/Object;

    .line 7
    .line 8
    return-object p0
.end method

.method public final k(IIII)I
    .locals 8

    .line 1
    invoke-static {p2}, Lhr/q;->d(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    add-int/lit8 p2, p2, -0x1

    .line 6
    .line 7
    if-eqz p4, :cond_0

    .line 8
    .line 9
    and-int/2addr p3, p2

    .line 10
    add-int/lit8 p4, p4, 0x1

    .line 11
    .line 12
    invoke-static {p3, v0, p4}, Lhr/q;->r(ILjava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object p3, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {p3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lhr/v;->h()[I

    .line 21
    .line 22
    .line 23
    move-result-object p4

    .line 24
    const/4 v1, 0x0

    .line 25
    :goto_0
    if-gt v1, p1, :cond_2

    .line 26
    .line 27
    invoke-static {v1, p3}, Lhr/q;->q(ILjava/lang/Object;)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    :goto_1
    if-eqz v2, :cond_1

    .line 32
    .line 33
    add-int/lit8 v3, v2, -0x1

    .line 34
    .line 35
    aget v4, p4, v3

    .line 36
    .line 37
    not-int v5, p1

    .line 38
    and-int/2addr v5, v4

    .line 39
    or-int/2addr v5, v1

    .line 40
    and-int v6, v5, p2

    .line 41
    .line 42
    invoke-static {v6, v0}, Lhr/q;->q(ILjava/lang/Object;)I

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    invoke-static {v6, v0, v2}, Lhr/q;->r(ILjava/lang/Object;I)V

    .line 47
    .line 48
    .line 49
    invoke-static {v5, v7, p2}, Lhr/q;->k(III)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    aput v2, p4, v3

    .line 54
    .line 55
    and-int v2, v4, p1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iput-object v0, p0, Lhr/v;->d:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-static {p2}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    rsub-int/lit8 p1, p1, 0x20

    .line 68
    .line 69
    iget p3, p0, Lhr/v;->h:I

    .line 70
    .line 71
    const/16 p4, 0x1f

    .line 72
    .line 73
    invoke-static {p3, p1, p4}, Lhr/q;->k(III)I

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    iput p1, p0, Lhr/v;->h:I

    .line 78
    .line 79
    return p2
.end method

.method public final keySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Lhr/v;->j:Lhr/s;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/s;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Lhr/s;-><init>(Lhr/v;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lhr/v;->j:Lhr/s;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-virtual {v0}, Lhr/v;->f()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/4 v4, 0x2

    .line 12
    const/4 v5, 0x4

    .line 13
    const/16 v6, 0x20

    .line 14
    .line 15
    const/4 v7, 0x1

    .line 16
    if-eqz v3, :cond_2

    .line 17
    .line 18
    invoke-virtual {v0}, Lhr/v;->f()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const-string v8, "Arrays already allocated"

    .line 23
    .line 24
    invoke-static {v8, v3}, Lkp/i9;->h(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    iget v3, v0, Lhr/v;->h:I

    .line 28
    .line 29
    add-int/lit8 v8, v3, 0x1

    .line 30
    .line 31
    invoke-static {v8, v4}, Ljava/lang/Math;->max(II)I

    .line 32
    .line 33
    .line 34
    move-result v8

    .line 35
    invoke-static {v8}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 36
    .line 37
    .line 38
    move-result v9

    .line 39
    int-to-double v10, v9

    .line 40
    const-wide/high16 v12, 0x3ff0000000000000L    # 1.0

    .line 41
    .line 42
    mul-double/2addr v12, v10

    .line 43
    double-to-int v10, v12

    .line 44
    if-le v8, v10, :cond_1

    .line 45
    .line 46
    shl-int/lit8 v9, v9, 0x1

    .line 47
    .line 48
    if-lez v9, :cond_0

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/high16 v9, 0x40000000    # 2.0f

    .line 52
    .line 53
    :cond_1
    :goto_0
    invoke-static {v5, v9}, Ljava/lang/Math;->max(II)I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    invoke-static {v8}, Lhr/q;->d(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v9

    .line 61
    iput-object v9, v0, Lhr/v;->d:Ljava/lang/Object;

    .line 62
    .line 63
    sub-int/2addr v8, v7

    .line 64
    invoke-static {v8}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 65
    .line 66
    .line 67
    move-result v8

    .line 68
    rsub-int/lit8 v8, v8, 0x20

    .line 69
    .line 70
    iget v9, v0, Lhr/v;->h:I

    .line 71
    .line 72
    const/16 v10, 0x1f

    .line 73
    .line 74
    invoke-static {v9, v8, v10}, Lhr/q;->k(III)I

    .line 75
    .line 76
    .line 77
    move-result v8

    .line 78
    iput v8, v0, Lhr/v;->h:I

    .line 79
    .line 80
    new-array v8, v3, [I

    .line 81
    .line 82
    iput-object v8, v0, Lhr/v;->e:[I

    .line 83
    .line 84
    new-array v8, v3, [Ljava/lang/Object;

    .line 85
    .line 86
    iput-object v8, v0, Lhr/v;->f:[Ljava/lang/Object;

    .line 87
    .line 88
    new-array v3, v3, [Ljava/lang/Object;

    .line 89
    .line 90
    iput-object v3, v0, Lhr/v;->g:[Ljava/lang/Object;

    .line 91
    .line 92
    :cond_2
    invoke-virtual {v0}, Lhr/v;->b()Ljava/util/Map;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    if-eqz v3, :cond_3

    .line 97
    .line 98
    invoke-interface {v3, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    return-object v0

    .line 103
    :cond_3
    invoke-virtual {v0}, Lhr/v;->h()[I

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    invoke-virtual {v0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    invoke-virtual {v0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v9

    .line 115
    iget v10, v0, Lhr/v;->i:I

    .line 116
    .line 117
    add-int/lit8 v11, v10, 0x1

    .line 118
    .line 119
    invoke-static {v1}, Lhr/q;->p(Ljava/lang/Object;)I

    .line 120
    .line 121
    .line 122
    move-result v12

    .line 123
    invoke-virtual {v0}, Lhr/v;->c()I

    .line 124
    .line 125
    .line 126
    move-result v13

    .line 127
    and-int v14, v12, v13

    .line 128
    .line 129
    iget-object v15, v0, Lhr/v;->d:Ljava/lang/Object;

    .line 130
    .line 131
    invoke-static {v15}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    invoke-static {v14, v15}, Lhr/q;->q(ILjava/lang/Object;)I

    .line 135
    .line 136
    .line 137
    move-result v15

    .line 138
    if-nez v15, :cond_6

    .line 139
    .line 140
    if-le v11, v13, :cond_5

    .line 141
    .line 142
    if-ge v13, v6, :cond_4

    .line 143
    .line 144
    const/16 v16, 0x4

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_4
    const/16 v16, 0x2

    .line 148
    .line 149
    :goto_1
    add-int/lit8 v3, v13, 0x1

    .line 150
    .line 151
    mul-int v3, v3, v16

    .line 152
    .line 153
    invoke-virtual {v0, v13, v3, v12, v10}, Lhr/v;->k(IIII)I

    .line 154
    .line 155
    .line 156
    move-result v13

    .line 157
    :goto_2
    move/from16 v19, v7

    .line 158
    .line 159
    goto/16 :goto_6

    .line 160
    .line 161
    :cond_5
    iget-object v3, v0, Lhr/v;->d:Ljava/lang/Object;

    .line 162
    .line 163
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    invoke-static {v14, v3, v11}, Lhr/q;->r(ILjava/lang/Object;I)V

    .line 167
    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_6
    not-int v14, v13

    .line 171
    and-int v5, v12, v14

    .line 172
    .line 173
    const/16 v18, 0x0

    .line 174
    .line 175
    :goto_3
    sub-int/2addr v15, v7

    .line 176
    move/from16 v19, v7

    .line 177
    .line 178
    aget v7, v3, v15

    .line 179
    .line 180
    move/from16 v20, v6

    .line 181
    .line 182
    and-int v6, v7, v14

    .line 183
    .line 184
    if-ne v6, v5, :cond_7

    .line 185
    .line 186
    aget-object v6, v8, v15

    .line 187
    .line 188
    invoke-static {v1, v6}, Lkp/h9;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v6

    .line 192
    if-eqz v6, :cond_7

    .line 193
    .line 194
    aget-object v0, v9, v15

    .line 195
    .line 196
    aput-object v2, v9, v15

    .line 197
    .line 198
    return-object v0

    .line 199
    :cond_7
    and-int v6, v7, v13

    .line 200
    .line 201
    add-int/lit8 v4, v18, 0x1

    .line 202
    .line 203
    if-nez v6, :cond_f

    .line 204
    .line 205
    const/16 v5, 0x9

    .line 206
    .line 207
    if-lt v4, v5, :cond_b

    .line 208
    .line 209
    invoke-virtual {v0}, Lhr/v;->c()I

    .line 210
    .line 211
    .line 212
    move-result v3

    .line 213
    add-int/lit8 v3, v3, 0x1

    .line 214
    .line 215
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 216
    .line 217
    const/high16 v5, 0x3f800000    # 1.0f

    .line 218
    .line 219
    invoke-direct {v4, v3, v5}, Ljava/util/LinkedHashMap;-><init>(IF)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v0}, Lhr/v;->isEmpty()Z

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    const/4 v5, -0x1

    .line 227
    if-eqz v3, :cond_9

    .line 228
    .line 229
    :cond_8
    move/from16 v17, v5

    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_9
    const/16 v17, 0x0

    .line 233
    .line 234
    :goto_4
    if-ltz v17, :cond_a

    .line 235
    .line 236
    invoke-virtual {v0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    aget-object v3, v3, v17

    .line 241
    .line 242
    invoke-virtual {v0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    aget-object v6, v6, v17

    .line 247
    .line 248
    invoke-interface {v4, v3, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    add-int/lit8 v3, v17, 0x1

    .line 252
    .line 253
    iget v6, v0, Lhr/v;->i:I

    .line 254
    .line 255
    if-ge v3, v6, :cond_8

    .line 256
    .line 257
    move/from16 v17, v3

    .line 258
    .line 259
    goto :goto_4

    .line 260
    :cond_a
    iput-object v4, v0, Lhr/v;->d:Ljava/lang/Object;

    .line 261
    .line 262
    const/4 v3, 0x0

    .line 263
    iput-object v3, v0, Lhr/v;->e:[I

    .line 264
    .line 265
    iput-object v3, v0, Lhr/v;->f:[Ljava/lang/Object;

    .line 266
    .line 267
    iput-object v3, v0, Lhr/v;->g:[Ljava/lang/Object;

    .line 268
    .line 269
    iget v3, v0, Lhr/v;->h:I

    .line 270
    .line 271
    add-int/lit8 v3, v3, 0x20

    .line 272
    .line 273
    iput v3, v0, Lhr/v;->h:I

    .line 274
    .line 275
    invoke-interface {v4, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    return-object v0

    .line 280
    :cond_b
    if-le v11, v13, :cond_d

    .line 281
    .line 282
    move/from16 v4, v20

    .line 283
    .line 284
    if-ge v13, v4, :cond_c

    .line 285
    .line 286
    const/4 v4, 0x4

    .line 287
    goto :goto_5

    .line 288
    :cond_c
    const/4 v4, 0x2

    .line 289
    :goto_5
    add-int/lit8 v3, v13, 0x1

    .line 290
    .line 291
    mul-int/2addr v3, v4

    .line 292
    invoke-virtual {v0, v13, v3, v12, v10}, Lhr/v;->k(IIII)I

    .line 293
    .line 294
    .line 295
    move-result v13

    .line 296
    goto :goto_6

    .line 297
    :cond_d
    invoke-static {v7, v11, v13}, Lhr/q;->k(III)I

    .line 298
    .line 299
    .line 300
    move-result v4

    .line 301
    aput v4, v3, v15

    .line 302
    .line 303
    :goto_6
    invoke-virtual {v0}, Lhr/v;->h()[I

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    array-length v3, v3

    .line 308
    if-le v11, v3, :cond_e

    .line 309
    .line 310
    ushr-int/lit8 v4, v3, 0x1

    .line 311
    .line 312
    move/from16 v7, v19

    .line 313
    .line 314
    invoke-static {v7, v4}, Ljava/lang/Math;->max(II)I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    add-int/2addr v4, v3

    .line 319
    or-int/2addr v4, v7

    .line 320
    const v5, 0x3fffffff    # 1.9999999f

    .line 321
    .line 322
    .line 323
    invoke-static {v5, v4}, Ljava/lang/Math;->min(II)I

    .line 324
    .line 325
    .line 326
    move-result v4

    .line 327
    if-eq v4, v3, :cond_e

    .line 328
    .line 329
    invoke-virtual {v0}, Lhr/v;->h()[I

    .line 330
    .line 331
    .line 332
    move-result-object v3

    .line 333
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([II)[I

    .line 334
    .line 335
    .line 336
    move-result-object v3

    .line 337
    iput-object v3, v0, Lhr/v;->e:[I

    .line 338
    .line 339
    invoke-virtual {v0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v3

    .line 343
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v3

    .line 347
    iput-object v3, v0, Lhr/v;->f:[Ljava/lang/Object;

    .line 348
    .line 349
    invoke-virtual {v0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v3

    .line 353
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v3

    .line 357
    iput-object v3, v0, Lhr/v;->g:[Ljava/lang/Object;

    .line 358
    .line 359
    :cond_e
    const/4 v15, 0x0

    .line 360
    invoke-static {v12, v15, v13}, Lhr/q;->k(III)I

    .line 361
    .line 362
    .line 363
    move-result v3

    .line 364
    invoke-virtual {v0}, Lhr/v;->h()[I

    .line 365
    .line 366
    .line 367
    move-result-object v4

    .line 368
    aput v3, v4, v10

    .line 369
    .line 370
    invoke-virtual {v0}, Lhr/v;->i()[Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v3

    .line 374
    aput-object v1, v3, v10

    .line 375
    .line 376
    invoke-virtual {v0}, Lhr/v;->j()[Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v1

    .line 380
    aput-object v2, v1, v10

    .line 381
    .line 382
    iput v11, v0, Lhr/v;->i:I

    .line 383
    .line 384
    iget v1, v0, Lhr/v;->h:I

    .line 385
    .line 386
    const/16 v20, 0x20

    .line 387
    .line 388
    add-int/lit8 v1, v1, 0x20

    .line 389
    .line 390
    iput v1, v0, Lhr/v;->h:I

    .line 391
    .line 392
    const/16 v21, 0x0

    .line 393
    .line 394
    return-object v21

    .line 395
    :cond_f
    const/16 v21, 0x0

    .line 396
    .line 397
    move/from16 v18, v4

    .line 398
    .line 399
    move v15, v6

    .line 400
    move/from16 v7, v19

    .line 401
    .line 402
    move/from16 v6, v20

    .line 403
    .line 404
    goto/16 :goto_3
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lhr/v;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Lhr/v;->m:Ljava/lang/Object;

    .line 17
    .line 18
    if-ne p0, p1, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    :cond_1
    return-object p0
.end method

.method public final size()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhr/v;->b()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    iget p0, p0, Lhr/v;->i:I

    .line 13
    .line 14
    return p0
.end method

.method public final values()Ljava/util/Collection;
    .locals 2

    .line 1
    iget-object v0, p0, Lhr/v;->l:Lhr/n;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/n;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1, p0}, Lhr/n;-><init>(ILjava/io/Serializable;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lhr/v;->l:Lhr/n;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method
