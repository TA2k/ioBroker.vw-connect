.class public final Ljp/t;
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

.field public transient j:Ljp/r;

.field public transient k:Ljp/r;

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
    sput-object v0, Ljp/t;->m:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractMap;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0xc

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const v1, 0x3fffffff    # 1.9999999f

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iput v0, p0, Ljp/t;->h:I

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()[I
    .locals 0

    .line 1
    iget-object p0, p0, Ljp/t;->e:[I

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

.method public final b()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ljp/t;->f:[Ljava/lang/Object;

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

.method public final c()[Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ljp/t;->g:[Ljava/lang/Object;

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

.method public final clear()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljp/t;->f()Z

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
    iget v0, p0, Ljp/t;->h:I

    .line 9
    .line 10
    add-int/lit8 v0, v0, 0x20

    .line 11
    .line 12
    iput v0, p0, Ljp/t;->h:I

    .line 13
    .line 14
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

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
    invoke-virtual {p0}, Ljp/t;->size()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x3

    .line 27
    invoke-static {v3, v4}, Ljava/lang/Math;->max(II)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const v4, 0x3fffffff    # 1.9999999f

    .line 32
    .line 33
    .line 34
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    iput v3, p0, Ljp/t;->h:I

    .line 39
    .line 40
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 44
    .line 45
    iput v2, p0, Ljp/t;->i:I

    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    invoke-virtual {p0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iget v3, p0, Ljp/t;->i:I

    .line 53
    .line 54
    invoke-static {v0, v2, v3, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iget v3, p0, Ljp/t;->i:I

    .line 62
    .line 63
    invoke-static {v0, v2, v3, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Ljp/t;->d:Ljava/lang/Object;

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
    invoke-virtual {p0}, Ljp/t;->a()[I

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iget v1, p0, Ljp/t;->i:I

    .line 101
    .line 102
    invoke-static {v0, v2, v1, v2}, Ljava/util/Arrays;->fill([IIII)V

    .line 103
    .line 104
    .line 105
    iput v2, p0, Ljp/t;->i:I

    .line 106
    .line 107
    return-void
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

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
    invoke-virtual {p0, p1}, Ljp/t;->h(Ljava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const/4 p1, -0x1

    .line 17
    if-ne p0, p1, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return p0

    .line 21
    :cond_1
    const/4 p0, 0x1

    .line 22
    return p0
.end method

.method public final containsValue(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    move v1, v0

    .line 9
    :goto_0
    iget v2, p0, Ljp/t;->i:I

    .line 10
    .line 11
    if-ge v1, v2, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    aget-object v2, v2, v1

    .line 18
    .line 19
    invoke-static {p1, v2}, Llp/hc;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    return v0

    .line 31
    :cond_2
    invoke-interface {v0, p1}, Ljava/util/Map;->containsValue(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public final d()Ljava/util/Map;
    .locals 1

    .line 1
    iget-object p0, p0, Ljp/t;->d:Ljava/lang/Object;

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

.method public final e(II)V
    .locals 10

    .line 1
    iget-object v0, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljp/t;->a()[I

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {p0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {p0}, Ljp/t;->size()I

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
    add-int/lit8 v7, p1, 0x1

    .line 29
    .line 30
    aget-object v8, v2, v4

    .line 31
    .line 32
    aput-object v8, v2, p1

    .line 33
    .line 34
    aget-object v9, v3, v4

    .line 35
    .line 36
    aput-object v9, v3, p1

    .line 37
    .line 38
    aput-object v6, v2, v4

    .line 39
    .line 40
    aput-object v6, v3, v4

    .line 41
    .line 42
    aget v2, v1, v4

    .line 43
    .line 44
    aput v2, v1, p1

    .line 45
    .line 46
    aput v5, v1, v4

    .line 47
    .line 48
    invoke-static {v8}, Llp/lc;->a(Ljava/lang/Object;)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    and-int/2addr p1, p2

    .line 53
    invoke-static {p1, v0}, Llp/kc;->c(ILjava/lang/Object;)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eq v2, p0, :cond_1

    .line 58
    .line 59
    :goto_0
    add-int/lit8 v2, v2, -0x1

    .line 60
    .line 61
    aget p1, v1, v2

    .line 62
    .line 63
    and-int v0, p1, p2

    .line 64
    .line 65
    if-eq v0, p0, :cond_0

    .line 66
    .line 67
    move v2, v0

    .line 68
    goto :goto_0

    .line 69
    :cond_0
    not-int p0, p2

    .line 70
    and-int/2addr p0, p1

    .line 71
    and-int p1, v7, p2

    .line 72
    .line 73
    or-int/2addr p0, p1

    .line 74
    aput p0, v1, v2

    .line 75
    .line 76
    return-void

    .line 77
    :cond_1
    invoke-static {p1, v0, v7}, Llp/kc;->e(ILjava/lang/Object;I)V

    .line 78
    .line 79
    .line 80
    return-void

    .line 81
    :cond_2
    aput-object v6, v2, p1

    .line 82
    .line 83
    aput-object v6, v3, p1

    .line 84
    .line 85
    aput v5, v1, p1

    .line 86
    .line 87
    return-void
.end method

.method public final entrySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Ljp/t;->k:Ljp/r;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljp/r;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Ljp/r;-><init>(Ljp/t;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ljp/t;->k:Ljp/r;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final f()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ljp/t;->d:Ljava/lang/Object;

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

.method public final g()I
    .locals 1

    .line 1
    iget p0, p0, Ljp/t;->h:I

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
    add-int/lit8 p0, p0, -0x1

    .line 9
    .line 10
    return p0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

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
    invoke-virtual {p0, p1}, Ljp/t;->h(Ljava/lang/Object;)I

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
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

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

.method public final h(Ljava/lang/Object;)I
    .locals 7

    .line 1
    invoke-virtual {p0}, Ljp/t;->f()Z

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
    invoke-static {p1}, Llp/lc;->a(Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0}, Ljp/t;->g()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    iget-object v3, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 18
    .line 19
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    and-int v4, v0, v2

    .line 23
    .line 24
    invoke-static {v4, v3}, Llp/kc;->c(ILjava/lang/Object;)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_4

    .line 29
    .line 30
    not-int v4, v2

    .line 31
    and-int/2addr v0, v4

    .line 32
    :cond_1
    add-int/2addr v3, v1

    .line 33
    invoke-virtual {p0}, Ljp/t;->a()[I

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    aget v5, v5, v3

    .line 38
    .line 39
    and-int v6, v5, v4

    .line 40
    .line 41
    if-ne v6, v0, :cond_3

    .line 42
    .line 43
    invoke-virtual {p0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    aget-object v6, v6, v3

    .line 48
    .line 49
    invoke-static {p1, v6}, Llp/hc;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-nez v6, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    return v3

    .line 57
    :cond_3
    :goto_0
    and-int v3, v5, v2

    .line 58
    .line 59
    if-nez v3, :cond_1

    .line 60
    .line 61
    :cond_4
    return v1
.end method

.method public final i(IIII)I
    .locals 8

    .line 1
    add-int/lit8 v0, p2, -0x1

    .line 2
    .line 3
    invoke-static {p2}, Llp/kc;->d(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    if-eqz p4, :cond_0

    .line 8
    .line 9
    and-int/2addr p3, v0

    .line 10
    add-int/lit8 p4, p4, 0x1

    .line 11
    .line 12
    invoke-static {p3, p2, p4}, Llp/kc;->e(ILjava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object p3, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {p3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Ljp/t;->a()[I

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
    invoke-static {v1, p3}, Llp/kc;->c(ILjava/lang/Object;)I

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
    and-int v6, v5, v0

    .line 41
    .line 42
    invoke-static {v6, p2}, Llp/kc;->c(ILjava/lang/Object;)I

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    invoke-static {v6, p2, v2}, Llp/kc;->e(ILjava/lang/Object;I)V

    .line 47
    .line 48
    .line 49
    not-int v2, v0

    .line 50
    and-int v6, v7, v0

    .line 51
    .line 52
    and-int/2addr v2, v5

    .line 53
    or-int/2addr v2, v6

    .line 54
    aput v2, p4, v3

    .line 55
    .line 56
    and-int v2, v4, p1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    iput-object p2, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 63
    .line 64
    invoke-static {v0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    rsub-int/lit8 p1, p1, 0x20

    .line 69
    .line 70
    iget p2, p0, Ljp/t;->h:I

    .line 71
    .line 72
    and-int/lit8 p2, p2, -0x20

    .line 73
    .line 74
    and-int/lit8 p1, p1, 0x1f

    .line 75
    .line 76
    or-int/2addr p1, p2

    .line 77
    iput p1, p0, Ljp/t;->h:I

    .line 78
    .line 79
    return v0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljp/t;->size()I

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

.method public final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljp/t;->f()Z

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
    invoke-virtual {p0}, Ljp/t;->g()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    iget-object v4, p0, Ljp/t;->d:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-static {v4}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ljp/t;->a()[I

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    invoke-virtual {p0}, Ljp/t;->b()[Ljava/lang/Object;

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
    invoke-static/range {v1 .. v7}, Llp/kc;->b(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;[I[Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    const/4 v0, -0x1

    .line 33
    if-eq p1, v0, :cond_1

    .line 34
    .line 35
    invoke-virtual {p0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    aget-object v1, v1, p1

    .line 40
    .line 41
    invoke-virtual {p0, p1, v3}, Ljp/t;->e(II)V

    .line 42
    .line 43
    .line 44
    iget p1, p0, Ljp/t;->i:I

    .line 45
    .line 46
    add-int/2addr p1, v0

    .line 47
    iput p1, p0, Ljp/t;->i:I

    .line 48
    .line 49
    iget p1, p0, Ljp/t;->h:I

    .line 50
    .line 51
    add-int/lit8 p1, p1, 0x20

    .line 52
    .line 53
    iput p1, p0, Ljp/t;->h:I

    .line 54
    .line 55
    return-object v1

    .line 56
    :cond_1
    :goto_0
    sget-object p0, Ljp/t;->m:Ljava/lang/Object;

    .line 57
    .line 58
    return-object p0
.end method

.method public final keySet()Ljava/util/Set;
    .locals 2

    .line 1
    iget-object v0, p0, Ljp/t;->j:Ljp/r;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljp/r;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Ljp/r;-><init>(Ljp/t;I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ljp/t;->j:Ljp/r;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

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
    invoke-virtual {v0}, Ljp/t;->f()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/4 v4, 0x4

    .line 12
    const/4 v5, 0x2

    .line 13
    const/16 v6, 0x20

    .line 14
    .line 15
    const/4 v7, -0x1

    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0}, Ljp/t;->f()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const-string v8, "Arrays already allocated"

    .line 23
    .line 24
    invoke-static {v8, v3}, Llp/ic;->d(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    iget v3, v0, Ljp/t;->h:I

    .line 28
    .line 29
    add-int/lit8 v8, v3, 0x1

    .line 30
    .line 31
    invoke-static {v8, v5}, Ljava/lang/Math;->max(II)I

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
    double-to-int v10, v10

    .line 41
    if-le v8, v10, :cond_0

    .line 42
    .line 43
    add-int/2addr v9, v9

    .line 44
    if-gtz v9, :cond_0

    .line 45
    .line 46
    const/high16 v9, 0x40000000    # 2.0f

    .line 47
    .line 48
    :cond_0
    invoke-static {v4, v9}, Ljava/lang/Math;->max(II)I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    invoke-static {v8}, Llp/kc;->d(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    iput-object v9, v0, Ljp/t;->d:Ljava/lang/Object;

    .line 57
    .line 58
    add-int/2addr v8, v7

    .line 59
    invoke-static {v8}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    rsub-int/lit8 v8, v8, 0x20

    .line 64
    .line 65
    iget v9, v0, Ljp/t;->h:I

    .line 66
    .line 67
    and-int/lit8 v9, v9, -0x20

    .line 68
    .line 69
    and-int/lit8 v8, v8, 0x1f

    .line 70
    .line 71
    or-int/2addr v8, v9

    .line 72
    iput v8, v0, Ljp/t;->h:I

    .line 73
    .line 74
    new-array v8, v3, [I

    .line 75
    .line 76
    iput-object v8, v0, Ljp/t;->e:[I

    .line 77
    .line 78
    new-array v8, v3, [Ljava/lang/Object;

    .line 79
    .line 80
    iput-object v8, v0, Ljp/t;->f:[Ljava/lang/Object;

    .line 81
    .line 82
    new-array v3, v3, [Ljava/lang/Object;

    .line 83
    .line 84
    iput-object v3, v0, Ljp/t;->g:[Ljava/lang/Object;

    .line 85
    .line 86
    :cond_1
    invoke-virtual {v0}, Ljp/t;->d()Ljava/util/Map;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    if-eqz v3, :cond_2

    .line 91
    .line 92
    invoke-interface {v3, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    return-object v0

    .line 97
    :cond_2
    invoke-virtual {v0}, Ljp/t;->a()[I

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    invoke-virtual {v0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    invoke-virtual {v0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v9

    .line 109
    iget v10, v0, Ljp/t;->i:I

    .line 110
    .line 111
    add-int/lit8 v11, v10, 0x1

    .line 112
    .line 113
    invoke-static {v1}, Llp/lc;->a(Ljava/lang/Object;)I

    .line 114
    .line 115
    .line 116
    move-result v12

    .line 117
    invoke-virtual {v0}, Ljp/t;->g()I

    .line 118
    .line 119
    .line 120
    move-result v13

    .line 121
    and-int v14, v12, v13

    .line 122
    .line 123
    iget-object v15, v0, Ljp/t;->d:Ljava/lang/Object;

    .line 124
    .line 125
    invoke-static {v15}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    invoke-static {v14, v15}, Llp/kc;->c(ILjava/lang/Object;)I

    .line 129
    .line 130
    .line 131
    move-result v15

    .line 132
    if-nez v15, :cond_5

    .line 133
    .line 134
    if-le v11, v13, :cond_4

    .line 135
    .line 136
    if-ge v13, v6, :cond_3

    .line 137
    .line 138
    const/16 v16, 0x4

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_3
    const/16 v16, 0x2

    .line 142
    .line 143
    :goto_0
    add-int/lit8 v3, v13, 0x1

    .line 144
    .line 145
    mul-int v3, v3, v16

    .line 146
    .line 147
    invoke-virtual {v0, v13, v3, v12, v10}, Ljp/t;->i(IIII)I

    .line 148
    .line 149
    .line 150
    move-result v13

    .line 151
    :goto_1
    const/16 v21, 0x1

    .line 152
    .line 153
    goto/16 :goto_6

    .line 154
    .line 155
    :cond_4
    iget-object v3, v0, Ljp/t;->d:Ljava/lang/Object;

    .line 156
    .line 157
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    invoke-static {v14, v3, v11}, Llp/kc;->e(ILjava/lang/Object;I)V

    .line 161
    .line 162
    .line 163
    goto :goto_1

    .line 164
    :cond_5
    not-int v14, v13

    .line 165
    move/from16 v17, v7

    .line 166
    .line 167
    and-int v7, v12, v14

    .line 168
    .line 169
    const/16 v18, 0x0

    .line 170
    .line 171
    move/from16 v19, v18

    .line 172
    .line 173
    :goto_2
    add-int/lit8 v15, v15, -0x1

    .line 174
    .line 175
    aget v20, v3, v15

    .line 176
    .line 177
    const/16 v21, 0x1

    .line 178
    .line 179
    and-int v5, v20, v14

    .line 180
    .line 181
    move/from16 v22, v6

    .line 182
    .line 183
    if-ne v5, v7, :cond_7

    .line 184
    .line 185
    aget-object v6, v8, v15

    .line 186
    .line 187
    invoke-static {v1, v6}, Llp/hc;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v6

    .line 191
    if-nez v6, :cond_6

    .line 192
    .line 193
    goto :goto_3

    .line 194
    :cond_6
    aget-object v0, v9, v15

    .line 195
    .line 196
    aput-object v2, v9, v15

    .line 197
    .line 198
    return-object v0

    .line 199
    :cond_7
    :goto_3
    and-int v6, v20, v13

    .line 200
    .line 201
    add-int/lit8 v4, v19, 0x1

    .line 202
    .line 203
    if-nez v6, :cond_f

    .line 204
    .line 205
    const/16 v6, 0x9

    .line 206
    .line 207
    if-lt v4, v6, :cond_b

    .line 208
    .line 209
    invoke-virtual {v0}, Ljp/t;->g()I

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
    invoke-virtual {v0}, Ljp/t;->isEmpty()Z

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    if-eqz v3, :cond_9

    .line 227
    .line 228
    :cond_8
    move/from16 v18, v17

    .line 229
    .line 230
    :cond_9
    :goto_4
    if-ltz v18, :cond_a

    .line 231
    .line 232
    invoke-virtual {v0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    aget-object v3, v3, v18

    .line 237
    .line 238
    invoke-virtual {v0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v5

    .line 242
    aget-object v5, v5, v18

    .line 243
    .line 244
    invoke-interface {v4, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    add-int/lit8 v3, v18, 0x1

    .line 248
    .line 249
    iget v5, v0, Ljp/t;->i:I

    .line 250
    .line 251
    if-ge v3, v5, :cond_8

    .line 252
    .line 253
    move/from16 v18, v3

    .line 254
    .line 255
    goto :goto_4

    .line 256
    :cond_a
    iput-object v4, v0, Ljp/t;->d:Ljava/lang/Object;

    .line 257
    .line 258
    const/4 v3, 0x0

    .line 259
    iput-object v3, v0, Ljp/t;->e:[I

    .line 260
    .line 261
    iput-object v3, v0, Ljp/t;->f:[Ljava/lang/Object;

    .line 262
    .line 263
    iput-object v3, v0, Ljp/t;->g:[Ljava/lang/Object;

    .line 264
    .line 265
    iget v3, v0, Ljp/t;->h:I

    .line 266
    .line 267
    add-int/lit8 v3, v3, 0x20

    .line 268
    .line 269
    iput v3, v0, Ljp/t;->h:I

    .line 270
    .line 271
    invoke-interface {v4, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    return-object v0

    .line 276
    :cond_b
    if-le v11, v13, :cond_d

    .line 277
    .line 278
    move/from16 v4, v22

    .line 279
    .line 280
    if-ge v13, v4, :cond_c

    .line 281
    .line 282
    const/4 v4, 0x4

    .line 283
    goto :goto_5

    .line 284
    :cond_c
    const/4 v4, 0x2

    .line 285
    :goto_5
    add-int/lit8 v3, v13, 0x1

    .line 286
    .line 287
    mul-int/2addr v3, v4

    .line 288
    invoke-virtual {v0, v13, v3, v12, v10}, Ljp/t;->i(IIII)I

    .line 289
    .line 290
    .line 291
    move-result v13

    .line 292
    goto :goto_6

    .line 293
    :cond_d
    and-int v4, v11, v13

    .line 294
    .line 295
    or-int/2addr v4, v5

    .line 296
    aput v4, v3, v15

    .line 297
    .line 298
    :goto_6
    invoke-virtual {v0}, Ljp/t;->a()[I

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    array-length v3, v3

    .line 303
    if-le v11, v3, :cond_e

    .line 304
    .line 305
    ushr-int/lit8 v4, v3, 0x1

    .line 306
    .line 307
    move/from16 v5, v21

    .line 308
    .line 309
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 310
    .line 311
    .line 312
    move-result v4

    .line 313
    add-int/2addr v4, v3

    .line 314
    or-int/2addr v4, v5

    .line 315
    const v5, 0x3fffffff    # 1.9999999f

    .line 316
    .line 317
    .line 318
    invoke-static {v5, v4}, Ljava/lang/Math;->min(II)I

    .line 319
    .line 320
    .line 321
    move-result v4

    .line 322
    if-eq v4, v3, :cond_e

    .line 323
    .line 324
    invoke-virtual {v0}, Ljp/t;->a()[I

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([II)[I

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    iput-object v3, v0, Ljp/t;->e:[I

    .line 333
    .line 334
    invoke-virtual {v0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v3

    .line 338
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v3

    .line 342
    iput-object v3, v0, Ljp/t;->f:[Ljava/lang/Object;

    .line 343
    .line 344
    invoke-virtual {v0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v3

    .line 348
    invoke-static {v3, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v3

    .line 352
    iput-object v3, v0, Ljp/t;->g:[Ljava/lang/Object;

    .line 353
    .line 354
    :cond_e
    not-int v3, v13

    .line 355
    and-int/2addr v3, v12

    .line 356
    invoke-virtual {v0}, Ljp/t;->a()[I

    .line 357
    .line 358
    .line 359
    move-result-object v4

    .line 360
    aput v3, v4, v10

    .line 361
    .line 362
    invoke-virtual {v0}, Ljp/t;->b()[Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v3

    .line 366
    aput-object v1, v3, v10

    .line 367
    .line 368
    invoke-virtual {v0}, Ljp/t;->c()[Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    aput-object v2, v1, v10

    .line 373
    .line 374
    iput v11, v0, Ljp/t;->i:I

    .line 375
    .line 376
    iget v1, v0, Ljp/t;->h:I

    .line 377
    .line 378
    const/16 v22, 0x20

    .line 379
    .line 380
    add-int/lit8 v1, v1, 0x20

    .line 381
    .line 382
    iput v1, v0, Ljp/t;->h:I

    .line 383
    .line 384
    const/16 v20, 0x0

    .line 385
    .line 386
    return-object v20

    .line 387
    :cond_f
    const/16 v20, 0x0

    .line 388
    .line 389
    move/from16 v19, v4

    .line 390
    .line 391
    move v15, v6

    .line 392
    move/from16 v6, v22

    .line 393
    .line 394
    goto/16 :goto_2
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

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
    invoke-virtual {p0, p1}, Ljp/t;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Ljp/t;->m:Ljava/lang/Object;

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
    invoke-virtual {p0}, Ljp/t;->d()Ljava/util/Map;

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
    iget p0, p0, Ljp/t;->i:I

    .line 13
    .line 14
    return p0
.end method

.method public final values()Ljava/util/Collection;
    .locals 2

    .line 1
    iget-object v0, p0, Ljp/t;->l:Lhr/n;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/n;

    .line 6
    .line 7
    const/4 v1, 0x3

    .line 8
    invoke-direct {v0, v1, p0}, Lhr/n;-><init>(ILjava/io/Serializable;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ljp/t;->l:Lhr/n;

    .line 12
    .line 13
    :cond_0
    return-object v0
.end method
