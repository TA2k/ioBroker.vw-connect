.class public final Lj8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lj8/q;


# instance fields
.field public final a:Lt7/q0;

.field public final b:I

.field public final c:[I

.field public final d:[Lt7/o;

.field public e:I

.field public final synthetic f:I


# direct methods
.method public constructor <init>(ILt7/q0;[I)V
    .locals 4

    .line 1
    iput p1, p0, Lj8/b;->f:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    array-length p1, p3

    .line 7
    const/4 v0, 0x0

    .line 8
    if-lez p1, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move p1, v0

    .line 13
    :goto_0
    invoke-static {p1}, Lw7/a;->j(Z)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget-object p1, p2, Lt7/q0;->d:[Lt7/o;

    .line 20
    .line 21
    iput-object p2, p0, Lj8/b;->a:Lt7/q0;

    .line 22
    .line 23
    array-length p2, p3

    .line 24
    iput p2, p0, Lj8/b;->b:I

    .line 25
    .line 26
    new-array p2, p2, [Lt7/o;

    .line 27
    .line 28
    iput-object p2, p0, Lj8/b;->d:[Lt7/o;

    .line 29
    .line 30
    move p2, v0

    .line 31
    :goto_1
    array-length v1, p3

    .line 32
    if-ge p2, v1, :cond_1

    .line 33
    .line 34
    iget-object v1, p0, Lj8/b;->d:[Lt7/o;

    .line 35
    .line 36
    aget v2, p3, p2

    .line 37
    .line 38
    aget-object v2, p1, v2

    .line 39
    .line 40
    aput-object v2, v1, p2

    .line 41
    .line 42
    add-int/lit8 p2, p2, 0x1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    iget-object p2, p0, Lj8/b;->d:[Lt7/o;

    .line 46
    .line 47
    new-instance p3, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 48
    .line 49
    const/4 v1, 0x4

    .line 50
    invoke-direct {p3, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 51
    .line 52
    .line 53
    invoke-static {p2, p3}, Ljava/util/Arrays;->sort([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 54
    .line 55
    .line 56
    iget p2, p0, Lj8/b;->b:I

    .line 57
    .line 58
    new-array p2, p2, [I

    .line 59
    .line 60
    iput-object p2, p0, Lj8/b;->c:[I

    .line 61
    .line 62
    move p2, v0

    .line 63
    :goto_2
    iget p3, p0, Lj8/b;->b:I

    .line 64
    .line 65
    if-ge p2, p3, :cond_4

    .line 66
    .line 67
    iget-object p3, p0, Lj8/b;->c:[I

    .line 68
    .line 69
    iget-object v1, p0, Lj8/b;->d:[Lt7/o;

    .line 70
    .line 71
    aget-object v1, v1, p2

    .line 72
    .line 73
    move v2, v0

    .line 74
    :goto_3
    array-length v3, p1

    .line 75
    if-ge v2, v3, :cond_3

    .line 76
    .line 77
    aget-object v3, p1, v2

    .line 78
    .line 79
    if-ne v1, v3, :cond_2

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_3
    const/4 v2, -0x1

    .line 86
    :goto_4
    aput v2, p3, p2

    .line 87
    .line 88
    add-int/lit8 p2, p2, 0x1

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_4
    new-array p0, p3, [J

    .line 92
    .line 93
    return-void
.end method

.method public static m(Ljava/util/ArrayList;[J)V
    .locals 7

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    move v3, v2

    .line 5
    :goto_0
    array-length v4, p1

    .line 6
    if-ge v3, v4, :cond_0

    .line 7
    .line 8
    aget-wide v4, p1, v3

    .line 9
    .line 10
    add-long/2addr v0, v4

    .line 11
    add-int/lit8 v3, v3, 0x1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    :goto_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-ge v2, v3, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    check-cast v3, Lhr/e0;

    .line 25
    .line 26
    if-nez v3, :cond_1

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_1
    new-instance v4, Lj8/a;

    .line 30
    .line 31
    aget-wide v5, p1, v2

    .line 32
    .line 33
    invoke-direct {v4, v0, v1, v5, v6}, Lj8/a;-><init>(JJ)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3, v4}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    return-void
.end method

.method private final n()V
    .locals 0

    .line 1
    return-void
.end method

.method private final p()V
    .locals 0

    .line 1
    return-void
.end method

.method private final r(F)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(I)Lt7/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lj8/b;->d:[Lt7/o;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    return-object p0
.end method

.method public final b(I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lj8/b;->c:[I

    .line 2
    .line 3
    aget p0, p0, p1

    .line 4
    .line 5
    return p0
.end method

.method public c()V
    .locals 0

    .line 1
    iget p0, p0, Lj8/b;->f:I

    .line 2
    .line 3
    return-void
.end method

.method public d(F)V
    .locals 0

    .line 1
    iget p0, p0, Lj8/b;->f:I

    .line 2
    .line 3
    return-void
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
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    if-eq v2, v3, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    check-cast p1, Lj8/b;

    .line 20
    .line 21
    iget-object v2, p0, Lj8/b;->a:Lt7/q0;

    .line 22
    .line 23
    iget-object v3, p1, Lj8/b;->a:Lt7/q0;

    .line 24
    .line 25
    invoke-virtual {v2, v3}, Lt7/q0;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_2

    .line 30
    .line 31
    iget-object p0, p0, Lj8/b;->c:[I

    .line 32
    .line 33
    iget-object p1, p1, Lj8/b;->c:[I

    .line 34
    .line 35
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([I[I)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    return v0

    .line 42
    :cond_2
    :goto_0
    return v1
.end method

.method public final f(I)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget v1, p0, Lj8/b;->b:I

    .line 3
    .line 4
    if-ge v0, v1, :cond_1

    .line 5
    .line 6
    iget-object v1, p0, Lj8/b;->c:[I

    .line 7
    .line 8
    aget v1, v1, v0

    .line 9
    .line 10
    if-ne v1, p1, :cond_0

    .line 11
    .line 12
    return v0

    .line 13
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    const/4 p0, -0x1

    .line 17
    return p0
.end method

.method public final g()Lt7/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lj8/b;->a:Lt7/q0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lj8/b;->e:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lj8/b;->a:Lt7/q0;

    .line 6
    .line 7
    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    mul-int/lit8 v0, v0, 0x1f

    .line 12
    .line 13
    iget-object v1, p0, Lj8/b;->c:[I

    .line 14
    .line 15
    invoke-static {v1}, Ljava/util/Arrays;->hashCode([I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    add-int/2addr v1, v0

    .line 20
    iput v1, p0, Lj8/b;->e:I

    .line 21
    .line 22
    :cond_0
    iget p0, p0, Lj8/b;->e:I

    .line 23
    .line 24
    return p0
.end method

.method public i()V
    .locals 0

    .line 1
    iget p0, p0, Lj8/b;->f:I

    .line 2
    .line 3
    return-void
.end method

.method public final j()I
    .locals 1

    .line 1
    iget-object p0, p0, Lj8/b;->c:[I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aget p0, p0, v0

    .line 5
    .line 6
    return p0
.end method

.method public final k()Lt7/o;
    .locals 1

    .line 1
    iget-object p0, p0, Lj8/b;->d:[Lt7/o;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aget-object p0, p0, v0

    .line 5
    .line 6
    return-object p0
.end method

.method public final length()I
    .locals 0

    .line 1
    iget-object p0, p0, Lj8/b;->c:[I

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public final o()V
    .locals 0

    .line 1
    return-void
.end method

.method public final q()V
    .locals 0

    .line 1
    return-void
.end method

.method public final s(F)V
    .locals 0

    .line 1
    return-void
.end method
