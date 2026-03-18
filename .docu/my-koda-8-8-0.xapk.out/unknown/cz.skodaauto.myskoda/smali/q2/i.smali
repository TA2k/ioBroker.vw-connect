.class public final Lq2/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lq2/i;


# instance fields
.field public a:I

.field public b:I

.field public final c:Ls2/b;

.field public d:[Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lq2/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v2, v3}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lq2/i;->e:Lq2/i;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(II[Ljava/lang/Object;Ls2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lq2/i;->a:I

    .line 5
    .line 6
    iput p2, p0, Lq2/i;->b:I

    .line 7
    .line 8
    iput-object p4, p0, Lq2/i;->c:Ls2/b;

    .line 9
    .line 10
    iput-object p3, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method

.method public static j(ILjava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;ILs2/b;)Lq2/i;
    .locals 11

    .line 1
    move-object/from16 v5, p5

    .line 2
    .line 3
    move/from16 v0, p6

    .line 4
    .line 5
    move-object/from16 v7, p7

    .line 6
    .line 7
    const/16 v1, 0x1e

    .line 8
    .line 9
    const/4 v8, 0x0

    .line 10
    if-le v0, v1, :cond_0

    .line 11
    .line 12
    new-instance p0, Lq2/i;

    .line 13
    .line 14
    filled-new-array {p1, p2, p4, v5}, [Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {p0, v8, v8, p1, v7}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    invoke-static {p0, v0}, Ljp/ke;->d(II)I

    .line 23
    .line 24
    .line 25
    move-result v9

    .line 26
    invoke-static {p3, v0}, Ljp/ke;->d(II)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const/4 v10, 0x1

    .line 31
    if-eq v9, v1, :cond_2

    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    const/4 p3, 0x2

    .line 35
    const/4 v0, 0x4

    .line 36
    if-ge v9, v1, :cond_1

    .line 37
    .line 38
    new-array v0, v0, [Ljava/lang/Object;

    .line 39
    .line 40
    aput-object p1, v0, v8

    .line 41
    .line 42
    aput-object p2, v0, v10

    .line 43
    .line 44
    aput-object p4, v0, p3

    .line 45
    .line 46
    aput-object v5, v0, p0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    new-array v0, v0, [Ljava/lang/Object;

    .line 50
    .line 51
    aput-object p4, v0, v8

    .line 52
    .line 53
    aput-object v5, v0, v10

    .line 54
    .line 55
    aput-object p1, v0, p3

    .line 56
    .line 57
    aput-object p2, v0, p0

    .line 58
    .line 59
    :goto_0
    new-instance p0, Lq2/i;

    .line 60
    .line 61
    shl-int p1, v10, v9

    .line 62
    .line 63
    shl-int p2, v10, v1

    .line 64
    .line 65
    or-int/2addr p1, p2

    .line 66
    invoke-direct {p0, p1, v8, v0, v7}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 67
    .line 68
    .line 69
    return-object p0

    .line 70
    :cond_2
    add-int/lit8 v6, v0, 0x5

    .line 71
    .line 72
    move v0, p0

    .line 73
    move-object v1, p1

    .line 74
    move-object v2, p2

    .line 75
    move v3, p3

    .line 76
    move-object v4, p4

    .line 77
    invoke-static/range {v0 .. v7}, Lq2/i;->j(ILjava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;ILs2/b;)Lq2/i;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    new-instance p1, Lq2/i;

    .line 82
    .line 83
    shl-int p2, v10, v9

    .line 84
    .line 85
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-direct {p1, v8, p2, p0, v7}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 90
    .line 91
    .line 92
    return-object p1
.end method


# virtual methods
.method public final a(IIILjava/lang/Object;Ljava/lang/Object;ILs2/b;)[Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    aget-object v2, v0, p1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz v2, :cond_0

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v1, v0

    .line 14
    :goto_0
    invoke-virtual/range {p0 .. p1}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    add-int/lit8 v7, p6, 0x5

    .line 19
    .line 20
    move v4, p3

    .line 21
    move-object v5, p4

    .line 22
    move-object v6, p5

    .line 23
    move-object/from16 v8, p7

    .line 24
    .line 25
    invoke-static/range {v1 .. v8}, Lq2/i;->j(ILjava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;ILs2/b;)Lq2/i;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    invoke-virtual {p0, p2}, Lq2/i;->t(I)I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    add-int/lit8 p4, p2, 0x1

    .line 34
    .line 35
    iget-object p0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 36
    .line 37
    add-int/lit8 v1, p2, -0x1

    .line 38
    .line 39
    array-length v2, p0

    .line 40
    add-int/lit8 v2, v2, -0x1

    .line 41
    .line 42
    new-array v2, v2, [Ljava/lang/Object;

    .line 43
    .line 44
    const/4 v3, 0x6

    .line 45
    invoke-static {v0, p1, v3, p0, v2}, Lmx0/n;->m(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    add-int/lit8 v0, p1, 0x2

    .line 49
    .line 50
    invoke-static {p1, v0, p4, p0, v2}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    aput-object p3, v2, v1

    .line 54
    .line 55
    array-length p1, p0

    .line 56
    invoke-static {p2, p4, p1, p0, v2}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-object v2
.end method

.method public final b()I
    .locals 4

    .line 1
    iget v0, p0, Lq2/i;->b:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length p0, p0

    .line 8
    div-int/lit8 p0, p0, 0x2

    .line 9
    .line 10
    return p0

    .line 11
    :cond_0
    iget v0, p0, Lq2/i;->a:I

    .line 12
    .line 13
    invoke-static {v0}, Ljava/lang/Integer;->bitCount(I)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    mul-int/lit8 v1, v0, 0x2

    .line 18
    .line 19
    iget-object v2, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    array-length v2, v2

    .line 22
    :goto_0
    if-ge v1, v2, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Lq2/i;->s(I)Lq2/i;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-virtual {v3}, Lq2/i;->b()I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    add-int/2addr v0, v3

    .line 33
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return v0
.end method

.method public final c(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-static {v1, v0}, Lkp/r9;->m(II)Lgy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-static {v2, v0}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget v2, v0, Lgy0/h;->d:I

    .line 15
    .line 16
    iget v3, v0, Lgy0/h;->e:I

    .line 17
    .line 18
    iget v0, v0, Lgy0/h;->f:I

    .line 19
    .line 20
    if-lez v0, :cond_0

    .line 21
    .line 22
    if-le v2, v3, :cond_1

    .line 23
    .line 24
    :cond_0
    if-gez v0, :cond_3

    .line 25
    .line 26
    if-gt v3, v2, :cond_3

    .line 27
    .line 28
    :cond_1
    :goto_0
    iget-object v4, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 29
    .line 30
    aget-object v4, v4, v2

    .line 31
    .line 32
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0

    .line 40
    :cond_2
    if-eq v2, v3, :cond_3

    .line 41
    .line 42
    add-int/2addr v2, v0

    .line 43
    goto :goto_0

    .line 44
    :cond_3
    return v1
.end method

.method public final d(ILjava/lang/Object;I)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, p3}, Ljp/ke;->d(II)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    shl-int/2addr v0, v1

    .line 7
    invoke-virtual {p0, v0}, Lq2/i;->h(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lq2/i;->f(I)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object p0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    aget-object p0, p0, p1

    .line 20
    .line 21
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    invoke-virtual {p0, v0}, Lq2/i;->i(I)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_2

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lq2/i;->t(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-virtual {p0, v0}, Lq2/i;->s(I)Lq2/i;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const/16 v0, 0x1e

    .line 41
    .line 42
    if-ne p3, v0, :cond_1

    .line 43
    .line 44
    invoke-virtual {p0, p2}, Lq2/i;->c(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    return p0

    .line 49
    :cond_1
    add-int/lit8 p3, p3, 0x5

    .line 50
    .line 51
    invoke-virtual {p0, p1, p2, p3}, Lq2/i;->d(ILjava/lang/Object;I)Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    return p0

    .line 56
    :cond_2
    const/4 p0, 0x0

    .line 57
    return p0
.end method

.method public final e(Lq2/i;)Z
    .locals 5

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_2

    .line 4
    :cond_0
    iget v0, p0, Lq2/i;->b:I

    .line 5
    .line 6
    iget v1, p1, Lq2/i;->b:I

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_1
    iget v0, p0, Lq2/i;->a:I

    .line 13
    .line 14
    iget v1, p1, Lq2/i;->a:I

    .line 15
    .line 16
    if-eq v0, v1, :cond_2

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_2
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    array-length v0, v0

    .line 22
    move v1, v2

    .line 23
    :goto_0
    if-ge v1, v0, :cond_4

    .line 24
    .line 25
    iget-object v3, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 26
    .line 27
    aget-object v3, v3, v1

    .line 28
    .line 29
    iget-object v4, p1, Lq2/i;->d:[Ljava/lang/Object;

    .line 30
    .line 31
    aget-object v4, v4, v1

    .line 32
    .line 33
    if-eq v3, v4, :cond_3

    .line 34
    .line 35
    :goto_1
    return v2

    .line 36
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_4
    :goto_2
    const/4 p0, 0x1

    .line 40
    return p0
.end method

.method public final f(I)I
    .locals 0

    .line 1
    iget p0, p0, Lq2/i;->a:I

    .line 2
    .line 3
    add-int/lit8 p1, p1, -0x1

    .line 4
    .line 5
    and-int/2addr p0, p1

    .line 6
    invoke-static {p0}, Ljava/lang/Integer;->bitCount(I)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    mul-int/lit8 p0, p0, 0x2

    .line 11
    .line 12
    return p0
.end method

.method public final g(ILjava/lang/Object;I)Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, p3}, Ljp/ke;->d(II)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    shl-int/2addr v0, v1

    .line 7
    invoke-virtual {p0, v0}, Lq2/i;->h(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lq2/i;->f(I)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object p3, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    aget-object p3, p3, p1

    .line 20
    .line 21
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_5

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_0
    invoke-virtual {p0, v0}, Lq2/i;->i(I)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_5

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Lq2/i;->t(I)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    invoke-virtual {p0, v0}, Lq2/i;->s(I)Lq2/i;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const/16 v0, 0x1e

    .line 47
    .line 48
    if-ne p3, v0, :cond_4

    .line 49
    .line 50
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 51
    .line 52
    array-length p1, p1

    .line 53
    const/4 p3, 0x0

    .line 54
    invoke-static {p3, p1}, Lkp/r9;->m(II)Lgy0/j;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    const/4 p3, 0x2

    .line 59
    invoke-static {p3, p1}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iget p3, p1, Lgy0/h;->d:I

    .line 64
    .line 65
    iget v0, p1, Lgy0/h;->e:I

    .line 66
    .line 67
    iget p1, p1, Lgy0/h;->f:I

    .line 68
    .line 69
    if-lez p1, :cond_1

    .line 70
    .line 71
    if-le p3, v0, :cond_2

    .line 72
    .line 73
    :cond_1
    if-gez p1, :cond_5

    .line 74
    .line 75
    if-gt v0, p3, :cond_5

    .line 76
    .line 77
    :cond_2
    :goto_0
    iget-object v1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 78
    .line 79
    aget-object v1, v1, p3

    .line 80
    .line 81
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-eqz v1, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0, p3}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :cond_3
    if-eq p3, v0, :cond_5

    .line 93
    .line 94
    add-int/2addr p3, p1

    .line 95
    goto :goto_0

    .line 96
    :cond_4
    add-int/lit8 p3, p3, 0x5

    .line 97
    .line 98
    invoke-virtual {p0, p1, p2, p3}, Lq2/i;->g(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
    :cond_5
    const/4 p0, 0x0

    .line 104
    return-object p0
.end method

.method public final h(I)Z
    .locals 0

    .line 1
    iget p0, p0, Lq2/i;->a:I

    .line 2
    .line 3
    and-int/2addr p0, p1

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final i(I)Z
    .locals 0

    .line 1
    iget p0, p0, Lq2/i;->b:I

    .line 2
    .line 3
    and-int/2addr p0, p1

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final k(ILt2/f;)Lq2/i;
    .locals 3

    .line 1
    iget v0, p2, Lt2/f;->h:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    invoke-virtual {p2, v0}, Lt2/f;->i(I)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p2, Lt2/f;->f:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 15
    .line 16
    array-length v1, v0

    .line 17
    const/4 v2, 0x2

    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_0
    iget-object v1, p0, Lq2/i;->c:Ls2/b;

    .line 23
    .line 24
    iget-object v2, p2, Lt2/f;->d:Ls2/b;

    .line 25
    .line 26
    if-ne v1, v2, :cond_1

    .line 27
    .line 28
    invoke-static {p1, v0}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    invoke-static {p1, v0}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    new-instance p1, Lq2/i;

    .line 40
    .line 41
    iget-object p2, p2, Lt2/f;->d:Ls2/b;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    invoke-direct {p1, v0, v0, p0, p2}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 45
    .line 46
    .line 47
    return-object p1
.end method

.method public final l(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;
    .locals 10

    .line 1
    invoke-static {p1, p4}, Ljp/ke;->d(II)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    shl-int v4, v1, v0

    .line 7
    .line 8
    invoke-virtual {p0, v4}, Lq2/i;->h(I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const-string v2, "copyOf(...)"

    .line 13
    .line 14
    iget-object v3, p0, Lq2/i;->c:Ls2/b;

    .line 15
    .line 16
    if-eqz v0, :cond_4

    .line 17
    .line 18
    move-object v0, v3

    .line 19
    invoke-virtual {p0, v4}, Lq2/i;->f(I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    iget-object v5, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 24
    .line 25
    aget-object v5, v5, v3

    .line 26
    .line 27
    invoke-static {p2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0, v3}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p5, Lt2/f;->f:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-virtual {p0, v3}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    if-ne p1, p3, :cond_0

    .line 44
    .line 45
    move-object p1, p0

    .line 46
    goto/16 :goto_3

    .line 47
    .line 48
    :cond_0
    iget-object p1, p5, Lt2/f;->d:Ls2/b;

    .line 49
    .line 50
    if-ne v0, p1, :cond_1

    .line 51
    .line 52
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 53
    .line 54
    add-int/2addr v3, v1

    .line 55
    aput-object p3, p1, v3

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_1
    iget p1, p5, Lt2/f;->g:I

    .line 59
    .line 60
    add-int/2addr p1, v1

    .line 61
    iput p1, p5, Lt2/f;->g:I

    .line 62
    .line 63
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 64
    .line 65
    array-length p2, p1

    .line 66
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    add-int/2addr v3, v1

    .line 74
    aput-object p3, p1, v3

    .line 75
    .line 76
    new-instance p2, Lq2/i;

    .line 77
    .line 78
    iget p3, p0, Lq2/i;->a:I

    .line 79
    .line 80
    iget p0, p0, Lq2/i;->b:I

    .line 81
    .line 82
    iget-object p4, p5, Lt2/f;->d:Ls2/b;

    .line 83
    .line 84
    invoke-direct {p2, p3, p0, p1, p4}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 85
    .line 86
    .line 87
    return-object p2

    .line 88
    :cond_2
    iget v2, p5, Lt2/f;->h:I

    .line 89
    .line 90
    add-int/2addr v2, v1

    .line 91
    invoke-virtual {p5, v2}, Lt2/f;->i(I)V

    .line 92
    .line 93
    .line 94
    iget-object v9, p5, Lt2/f;->d:Ls2/b;

    .line 95
    .line 96
    if-ne v0, v9, :cond_3

    .line 97
    .line 98
    move-object v2, p0

    .line 99
    move v5, p1

    .line 100
    move-object v6, p2

    .line 101
    move-object v7, p3

    .line 102
    move v8, p4

    .line 103
    invoke-virtual/range {v2 .. v9}, Lq2/i;->a(IIILjava/lang/Object;Ljava/lang/Object;ILs2/b;)[Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    iput-object p0, v2, Lq2/i;->d:[Ljava/lang/Object;

    .line 108
    .line 109
    iget p0, v2, Lq2/i;->a:I

    .line 110
    .line 111
    xor-int/2addr p0, v4

    .line 112
    iput p0, v2, Lq2/i;->a:I

    .line 113
    .line 114
    iget p0, v2, Lq2/i;->b:I

    .line 115
    .line 116
    or-int/2addr p0, v4

    .line 117
    iput p0, v2, Lq2/i;->b:I

    .line 118
    .line 119
    return-object v2

    .line 120
    :cond_3
    move-object v2, p0

    .line 121
    move v5, p1

    .line 122
    move-object v6, p2

    .line 123
    move-object v7, p3

    .line 124
    move v8, p4

    .line 125
    invoke-virtual/range {v2 .. v9}, Lq2/i;->a(IIILjava/lang/Object;Ljava/lang/Object;ILs2/b;)[Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    move-object p1, v2

    .line 130
    new-instance p2, Lq2/i;

    .line 131
    .line 132
    iget p3, p1, Lq2/i;->a:I

    .line 133
    .line 134
    xor-int/2addr p3, v4

    .line 135
    iget p1, p1, Lq2/i;->b:I

    .line 136
    .line 137
    or-int/2addr p1, v4

    .line 138
    invoke-direct {p2, p3, p1, p0, v9}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 139
    .line 140
    .line 141
    return-object p2

    .line 142
    :cond_4
    move v5, p1

    .line 143
    move-object v6, p2

    .line 144
    move-object v7, p3

    .line 145
    move v8, p4

    .line 146
    move-object v0, v3

    .line 147
    move-object p1, p0

    .line 148
    invoke-virtual {p1, v4}, Lq2/i;->i(I)Z

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    if-eqz p0, :cond_c

    .line 153
    .line 154
    invoke-virtual {p1, v4}, Lq2/i;->t(I)I

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    invoke-virtual {p1, p0}, Lq2/i;->s(I)Lq2/i;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    const/16 p2, 0x1e

    .line 163
    .line 164
    if-ne v8, p2, :cond_a

    .line 165
    .line 166
    iget-object p2, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 167
    .line 168
    array-length p2, p2

    .line 169
    const/4 p3, 0x0

    .line 170
    invoke-static {p3, p2}, Lkp/r9;->m(II)Lgy0/j;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    const/4 p4, 0x2

    .line 175
    invoke-static {p4, p2}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 176
    .line 177
    .line 178
    move-result-object p2

    .line 179
    iget p4, p2, Lgy0/h;->d:I

    .line 180
    .line 181
    iget v3, p2, Lgy0/h;->e:I

    .line 182
    .line 183
    iget p2, p2, Lgy0/h;->f:I

    .line 184
    .line 185
    if-lez p2, :cond_5

    .line 186
    .line 187
    if-le p4, v3, :cond_6

    .line 188
    .line 189
    :cond_5
    if-gez p2, :cond_9

    .line 190
    .line 191
    if-gt v3, p4, :cond_9

    .line 192
    .line 193
    :cond_6
    :goto_0
    iget-object v4, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 194
    .line 195
    aget-object v4, v4, p4

    .line 196
    .line 197
    invoke-static {v6, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    if-eqz v4, :cond_8

    .line 202
    .line 203
    invoke-virtual {v0, p4}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    iput-object p2, p5, Lt2/f;->f:Ljava/lang/Object;

    .line 208
    .line 209
    iget-object p2, v0, Lq2/i;->c:Ls2/b;

    .line 210
    .line 211
    iget-object v3, p5, Lt2/f;->d:Ls2/b;

    .line 212
    .line 213
    if-ne p2, v3, :cond_7

    .line 214
    .line 215
    iget-object p2, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 216
    .line 217
    add-int/2addr p4, v1

    .line 218
    aput-object v7, p2, p4

    .line 219
    .line 220
    move-object p4, v0

    .line 221
    goto :goto_1

    .line 222
    :cond_7
    iget p2, p5, Lt2/f;->g:I

    .line 223
    .line 224
    add-int/2addr p2, v1

    .line 225
    iput p2, p5, Lt2/f;->g:I

    .line 226
    .line 227
    iget-object p2, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 228
    .line 229
    array-length v3, p2

    .line 230
    invoke-static {p2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p2

    .line 234
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    add-int/2addr p4, v1

    .line 238
    aput-object v7, p2, p4

    .line 239
    .line 240
    new-instance p4, Lq2/i;

    .line 241
    .line 242
    iget-object v1, p5, Lt2/f;->d:Ls2/b;

    .line 243
    .line 244
    invoke-direct {p4, p3, p3, p2, v1}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 245
    .line 246
    .line 247
    goto :goto_1

    .line 248
    :cond_8
    if-eq p4, v3, :cond_9

    .line 249
    .line 250
    add-int/2addr p4, p2

    .line 251
    goto :goto_0

    .line 252
    :cond_9
    iget p2, p5, Lt2/f;->h:I

    .line 253
    .line 254
    add-int/2addr p2, v1

    .line 255
    invoke-virtual {p5, p2}, Lt2/f;->i(I)V

    .line 256
    .line 257
    .line 258
    iget-object p2, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 259
    .line 260
    invoke-static {p2, p3, v6, v7}, Ljp/ke;->a([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p2

    .line 264
    new-instance p4, Lq2/i;

    .line 265
    .line 266
    iget-object v1, p5, Lt2/f;->d:Ls2/b;

    .line 267
    .line 268
    invoke-direct {p4, p3, p3, p2, v1}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 269
    .line 270
    .line 271
    :goto_1
    move-object v5, p5

    .line 272
    goto :goto_2

    .line 273
    :cond_a
    add-int/lit8 v4, v8, 0x5

    .line 274
    .line 275
    move v1, v5

    .line 276
    move-object v2, v6

    .line 277
    move-object v3, v7

    .line 278
    move-object v5, p5

    .line 279
    invoke-virtual/range {v0 .. v5}, Lq2/i;->l(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    .line 280
    .line 281
    .line 282
    move-result-object p4

    .line 283
    :goto_2
    if-ne v0, p4, :cond_b

    .line 284
    .line 285
    :goto_3
    return-object p1

    .line 286
    :cond_b
    iget-object p2, v5, Lt2/f;->d:Ls2/b;

    .line 287
    .line 288
    invoke-virtual {p1, p0, p4, p2}, Lq2/i;->r(ILq2/i;Ls2/b;)Lq2/i;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    return-object p0

    .line 293
    :cond_c
    move-object v5, p5

    .line 294
    iget p0, v5, Lt2/f;->h:I

    .line 295
    .line 296
    add-int/2addr p0, v1

    .line 297
    invoke-virtual {v5, p0}, Lt2/f;->i(I)V

    .line 298
    .line 299
    .line 300
    iget-object p0, v5, Lt2/f;->d:Ls2/b;

    .line 301
    .line 302
    invoke-virtual {p1, v4}, Lq2/i;->f(I)I

    .line 303
    .line 304
    .line 305
    move-result p2

    .line 306
    if-ne v0, p0, :cond_d

    .line 307
    .line 308
    iget-object p0, p1, Lq2/i;->d:[Ljava/lang/Object;

    .line 309
    .line 310
    invoke-static {p0, p2, v6, v7}, Ljp/ke;->a([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    iput-object p0, p1, Lq2/i;->d:[Ljava/lang/Object;

    .line 315
    .line 316
    iget p0, p1, Lq2/i;->a:I

    .line 317
    .line 318
    or-int/2addr p0, v4

    .line 319
    iput p0, p1, Lq2/i;->a:I

    .line 320
    .line 321
    return-object p1

    .line 322
    :cond_d
    iget-object p3, p1, Lq2/i;->d:[Ljava/lang/Object;

    .line 323
    .line 324
    invoke-static {p3, p2, v6, v7}, Ljp/ke;->a([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object p2

    .line 328
    new-instance p3, Lq2/i;

    .line 329
    .line 330
    iget p4, p1, Lq2/i;->a:I

    .line 331
    .line 332
    or-int/2addr p4, v4

    .line 333
    iget p1, p1, Lq2/i;->b:I

    .line 334
    .line 335
    invoke-direct {p3, p4, p1, p2, p0}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 336
    .line 337
    .line 338
    return-object p3
.end method

.method public final m(Lq2/i;ILs2/a;Lt2/f;)Lq2/i;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v9, p4

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Lq2/i;->b()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget v2, v3, Ls2/a;->a:I

    .line 18
    .line 19
    add-int/2addr v2, v1

    .line 20
    iput v2, v3, Ls2/a;->a:I

    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    const/16 v4, 0x1e

    .line 24
    .line 25
    const/4 v5, 0x2

    .line 26
    const/4 v10, 0x0

    .line 27
    if-le v2, v4, :cond_8

    .line 28
    .line 29
    iget-object v2, v9, Lt2/f;->d:Ls2/b;

    .line 30
    .line 31
    iget v4, v1, Lq2/i;->b:I

    .line 32
    .line 33
    iget-object v4, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 34
    .line 35
    array-length v6, v4

    .line 36
    iget-object v7, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 37
    .line 38
    array-length v7, v7

    .line 39
    add-int/2addr v6, v7

    .line 40
    invoke-static {v4, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    const-string v6, "copyOf(...)"

    .line 45
    .line 46
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object v7, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 50
    .line 51
    array-length v7, v7

    .line 52
    iget-object v8, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 53
    .line 54
    array-length v8, v8

    .line 55
    invoke-static {v10, v8}, Lkp/r9;->m(II)Lgy0/j;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    invoke-static {v5, v8}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    iget v8, v5, Lgy0/h;->d:I

    .line 64
    .line 65
    iget v9, v5, Lgy0/h;->e:I

    .line 66
    .line 67
    iget v5, v5, Lgy0/h;->f:I

    .line 68
    .line 69
    if-lez v5, :cond_1

    .line 70
    .line 71
    if-le v8, v9, :cond_2

    .line 72
    .line 73
    :cond_1
    if-gez v5, :cond_4

    .line 74
    .line 75
    if-gt v9, v8, :cond_4

    .line 76
    .line 77
    :cond_2
    :goto_0
    iget-object v11, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 78
    .line 79
    aget-object v11, v11, v8

    .line 80
    .line 81
    invoke-virtual {v0, v11}, Lq2/i;->c(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    if-nez v11, :cond_3

    .line 86
    .line 87
    iget-object v11, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 88
    .line 89
    aget-object v12, v11, v8

    .line 90
    .line 91
    aput-object v12, v4, v7

    .line 92
    .line 93
    add-int/lit8 v12, v7, 0x1

    .line 94
    .line 95
    add-int/lit8 v13, v8, 0x1

    .line 96
    .line 97
    aget-object v11, v11, v13

    .line 98
    .line 99
    aput-object v11, v4, v12

    .line 100
    .line 101
    add-int/lit8 v7, v7, 0x2

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_3
    iget v11, v3, Ls2/a;->a:I

    .line 105
    .line 106
    add-int/lit8 v11, v11, 0x1

    .line 107
    .line 108
    iput v11, v3, Ls2/a;->a:I

    .line 109
    .line 110
    :goto_1
    if-eq v8, v9, :cond_4

    .line 111
    .line 112
    add-int/2addr v8, v5

    .line 113
    goto :goto_0

    .line 114
    :cond_4
    iget-object v3, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 115
    .line 116
    array-length v3, v3

    .line 117
    if-ne v7, v3, :cond_5

    .line 118
    .line 119
    goto/16 :goto_f

    .line 120
    .line 121
    :cond_5
    iget-object v0, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 122
    .line 123
    array-length v0, v0

    .line 124
    if-ne v7, v0, :cond_6

    .line 125
    .line 126
    return-object v1

    .line 127
    :cond_6
    array-length v0, v4

    .line 128
    if-ne v7, v0, :cond_7

    .line 129
    .line 130
    new-instance v0, Lq2/i;

    .line 131
    .line 132
    invoke-direct {v0, v10, v10, v4, v2}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 133
    .line 134
    .line 135
    return-object v0

    .line 136
    :cond_7
    new-instance v0, Lq2/i;

    .line 137
    .line 138
    invoke-static {v4, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-direct {v0, v10, v10, v1, v2}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 146
    .line 147
    .line 148
    return-object v0

    .line 149
    :cond_8
    iget v4, v0, Lq2/i;->b:I

    .line 150
    .line 151
    iget v6, v1, Lq2/i;->b:I

    .line 152
    .line 153
    or-int/2addr v4, v6

    .line 154
    iget v6, v0, Lq2/i;->a:I

    .line 155
    .line 156
    iget v7, v1, Lq2/i;->a:I

    .line 157
    .line 158
    xor-int v8, v6, v7

    .line 159
    .line 160
    not-int v11, v4

    .line 161
    and-int/2addr v8, v11

    .line 162
    and-int/2addr v6, v7

    .line 163
    move v11, v8

    .line 164
    :goto_2
    if-eqz v6, :cond_a

    .line 165
    .line 166
    invoke-static {v6}, Ljava/lang/Integer;->lowestOneBit(I)I

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    invoke-virtual {v0, v7}, Lq2/i;->f(I)I

    .line 171
    .line 172
    .line 173
    move-result v8

    .line 174
    iget-object v12, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 175
    .line 176
    aget-object v8, v12, v8

    .line 177
    .line 178
    invoke-virtual {v1, v7}, Lq2/i;->f(I)I

    .line 179
    .line 180
    .line 181
    move-result v12

    .line 182
    iget-object v13, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 183
    .line 184
    aget-object v12, v13, v12

    .line 185
    .line 186
    invoke-static {v8, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result v8

    .line 190
    if-eqz v8, :cond_9

    .line 191
    .line 192
    or-int v8, v11, v7

    .line 193
    .line 194
    move v11, v8

    .line 195
    goto :goto_3

    .line 196
    :cond_9
    or-int/2addr v4, v7

    .line 197
    :goto_3
    xor-int/2addr v6, v7

    .line 198
    goto :goto_2

    .line 199
    :cond_a
    and-int v6, v4, v11

    .line 200
    .line 201
    if-nez v6, :cond_b

    .line 202
    .line 203
    goto :goto_4

    .line 204
    :cond_b
    const-string v6, "Check failed."

    .line 205
    .line 206
    invoke-static {v6}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    :goto_4
    iget-object v6, v0, Lq2/i;->c:Ls2/b;

    .line 210
    .line 211
    iget-object v7, v9, Lt2/f;->d:Ls2/b;

    .line 212
    .line 213
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    if-eqz v6, :cond_c

    .line 218
    .line 219
    iget v6, v0, Lq2/i;->a:I

    .line 220
    .line 221
    if-ne v6, v11, :cond_c

    .line 222
    .line 223
    iget v6, v0, Lq2/i;->b:I

    .line 224
    .line 225
    if-ne v6, v4, :cond_c

    .line 226
    .line 227
    move-object v12, v0

    .line 228
    goto :goto_5

    .line 229
    :cond_c
    invoke-static {v11}, Ljava/lang/Integer;->bitCount(I)I

    .line 230
    .line 231
    .line 232
    move-result v6

    .line 233
    mul-int/2addr v6, v5

    .line 234
    invoke-static {v4}, Ljava/lang/Integer;->bitCount(I)I

    .line 235
    .line 236
    .line 237
    move-result v5

    .line 238
    add-int/2addr v5, v6

    .line 239
    new-array v5, v5, [Ljava/lang/Object;

    .line 240
    .line 241
    new-instance v6, Lq2/i;

    .line 242
    .line 243
    const/4 v7, 0x0

    .line 244
    invoke-direct {v6, v11, v4, v5, v7}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 245
    .line 246
    .line 247
    move-object v12, v6

    .line 248
    :goto_5
    move v13, v4

    .line 249
    move v14, v10

    .line 250
    :goto_6
    if-eqz v13, :cond_19

    .line 251
    .line 252
    invoke-static {v13}, Ljava/lang/Integer;->lowestOneBit(I)I

    .line 253
    .line 254
    .line 255
    move-result v15

    .line 256
    iget-object v4, v12, Lq2/i;->d:[Ljava/lang/Object;

    .line 257
    .line 258
    array-length v5, v4

    .line 259
    add-int/lit8 v5, v5, -0x1

    .line 260
    .line 261
    sub-int v16, v5, v14

    .line 262
    .line 263
    invoke-virtual {v0, v15}, Lq2/i;->i(I)Z

    .line 264
    .line 265
    .line 266
    move-result v5

    .line 267
    if-eqz v5, :cond_10

    .line 268
    .line 269
    invoke-virtual {v0, v15}, Lq2/i;->t(I)I

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    invoke-virtual {v0, v5}, Lq2/i;->s(I)Lq2/i;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    invoke-virtual {v1, v15}, Lq2/i;->i(I)Z

    .line 278
    .line 279
    .line 280
    move-result v6

    .line 281
    if-eqz v6, :cond_d

    .line 282
    .line 283
    invoke-virtual {v1, v15}, Lq2/i;->t(I)I

    .line 284
    .line 285
    .line 286
    move-result v6

    .line 287
    invoke-virtual {v1, v6}, Lq2/i;->s(I)Lq2/i;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    add-int/lit8 v7, v2, 0x5

    .line 292
    .line 293
    invoke-virtual {v5, v6, v7, v3, v9}, Lq2/i;->m(Lq2/i;ILs2/a;Lt2/f;)Lq2/i;

    .line 294
    .line 295
    .line 296
    move-result-object v5

    .line 297
    move-object/from16 v17, v4

    .line 298
    .line 299
    goto/16 :goto_c

    .line 300
    .line 301
    :cond_d
    invoke-virtual {v1, v15}, Lq2/i;->h(I)Z

    .line 302
    .line 303
    .line 304
    move-result v6

    .line 305
    if-eqz v6, :cond_f

    .line 306
    .line 307
    invoke-virtual {v1, v15}, Lq2/i;->f(I)I

    .line 308
    .line 309
    .line 310
    move-result v6

    .line 311
    iget-object v7, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 312
    .line 313
    aget-object v7, v7, v6

    .line 314
    .line 315
    invoke-virtual {v1, v6}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v6

    .line 319
    iget v8, v9, Lt2/f;->h:I

    .line 320
    .line 321
    if-eqz v7, :cond_e

    .line 322
    .line 323
    invoke-virtual {v7}, Ljava/lang/Object;->hashCode()I

    .line 324
    .line 325
    .line 326
    move-result v17

    .line 327
    goto :goto_7

    .line 328
    :cond_e
    move/from16 v17, v10

    .line 329
    .line 330
    :goto_7
    move/from16 v18, v8

    .line 331
    .line 332
    add-int/lit8 v8, v2, 0x5

    .line 333
    .line 334
    move/from16 v10, v17

    .line 335
    .line 336
    move-object/from16 v17, v4

    .line 337
    .line 338
    move-object v4, v5

    .line 339
    move v5, v10

    .line 340
    move-object v10, v7

    .line 341
    move-object v7, v6

    .line 342
    move-object v6, v10

    .line 343
    move/from16 v10, v18

    .line 344
    .line 345
    invoke-virtual/range {v4 .. v9}, Lq2/i;->l(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    .line 346
    .line 347
    .line 348
    move-result-object v5

    .line 349
    iget v4, v9, Lt2/f;->h:I

    .line 350
    .line 351
    if-ne v4, v10, :cond_18

    .line 352
    .line 353
    iget v4, v3, Ls2/a;->a:I

    .line 354
    .line 355
    add-int/lit8 v4, v4, 0x1

    .line 356
    .line 357
    iput v4, v3, Ls2/a;->a:I

    .line 358
    .line 359
    goto/16 :goto_c

    .line 360
    .line 361
    :cond_f
    move-object/from16 v17, v4

    .line 362
    .line 363
    move-object v4, v5

    .line 364
    goto/16 :goto_c

    .line 365
    .line 366
    :cond_10
    move-object/from16 v17, v4

    .line 367
    .line 368
    invoke-virtual {v1, v15}, Lq2/i;->i(I)Z

    .line 369
    .line 370
    .line 371
    move-result v4

    .line 372
    if-eqz v4, :cond_15

    .line 373
    .line 374
    invoke-virtual {v1, v15}, Lq2/i;->t(I)I

    .line 375
    .line 376
    .line 377
    move-result v4

    .line 378
    invoke-virtual {v1, v4}, Lq2/i;->s(I)Lq2/i;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    invoke-virtual {v0, v15}, Lq2/i;->h(I)Z

    .line 383
    .line 384
    .line 385
    move-result v5

    .line 386
    if-eqz v5, :cond_12

    .line 387
    .line 388
    invoke-virtual {v0, v15}, Lq2/i;->f(I)I

    .line 389
    .line 390
    .line 391
    move-result v5

    .line 392
    iget-object v6, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 393
    .line 394
    aget-object v6, v6, v5

    .line 395
    .line 396
    if-eqz v6, :cond_11

    .line 397
    .line 398
    invoke-virtual {v6}, Ljava/lang/Object;->hashCode()I

    .line 399
    .line 400
    .line 401
    move-result v7

    .line 402
    goto :goto_8

    .line 403
    :cond_11
    const/4 v7, 0x0

    .line 404
    :goto_8
    add-int/lit8 v8, v2, 0x5

    .line 405
    .line 406
    invoke-virtual {v4, v7, v6, v8}, Lq2/i;->d(ILjava/lang/Object;I)Z

    .line 407
    .line 408
    .line 409
    move-result v7

    .line 410
    if-eqz v7, :cond_13

    .line 411
    .line 412
    iget v5, v3, Ls2/a;->a:I

    .line 413
    .line 414
    add-int/lit8 v5, v5, 0x1

    .line 415
    .line 416
    iput v5, v3, Ls2/a;->a:I

    .line 417
    .line 418
    :cond_12
    move-object v5, v4

    .line 419
    goto :goto_c

    .line 420
    :cond_13
    invoke-virtual {v0, v5}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v7

    .line 424
    if-eqz v6, :cond_14

    .line 425
    .line 426
    invoke-virtual {v6}, Ljava/lang/Object;->hashCode()I

    .line 427
    .line 428
    .line 429
    move-result v5

    .line 430
    goto :goto_9

    .line 431
    :cond_14
    const/4 v5, 0x0

    .line 432
    :goto_9
    invoke-virtual/range {v4 .. v9}, Lq2/i;->l(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    .line 433
    .line 434
    .line 435
    move-result-object v5

    .line 436
    goto :goto_c

    .line 437
    :cond_15
    invoke-virtual {v0, v15}, Lq2/i;->f(I)I

    .line 438
    .line 439
    .line 440
    move-result v4

    .line 441
    iget-object v5, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 442
    .line 443
    aget-object v20, v5, v4

    .line 444
    .line 445
    invoke-virtual {v0, v4}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object v21

    .line 449
    invoke-virtual {v1, v15}, Lq2/i;->f(I)I

    .line 450
    .line 451
    .line 452
    move-result v4

    .line 453
    iget-object v5, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 454
    .line 455
    aget-object v23, v5, v4

    .line 456
    .line 457
    invoke-virtual {v1, v4}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v24

    .line 461
    if-eqz v20, :cond_16

    .line 462
    .line 463
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Object;->hashCode()I

    .line 464
    .line 465
    .line 466
    move-result v4

    .line 467
    move/from16 v19, v4

    .line 468
    .line 469
    goto :goto_a

    .line 470
    :cond_16
    const/16 v19, 0x0

    .line 471
    .line 472
    :goto_a
    if-eqz v23, :cond_17

    .line 473
    .line 474
    invoke-virtual/range {v23 .. v23}, Ljava/lang/Object;->hashCode()I

    .line 475
    .line 476
    .line 477
    move-result v4

    .line 478
    move/from16 v22, v4

    .line 479
    .line 480
    goto :goto_b

    .line 481
    :cond_17
    const/16 v22, 0x0

    .line 482
    .line 483
    :goto_b
    add-int/lit8 v25, v2, 0x5

    .line 484
    .line 485
    iget-object v4, v9, Lt2/f;->d:Ls2/b;

    .line 486
    .line 487
    move-object/from16 v26, v4

    .line 488
    .line 489
    invoke-static/range {v19 .. v26}, Lq2/i;->j(ILjava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;ILs2/b;)Lq2/i;

    .line 490
    .line 491
    .line 492
    move-result-object v5

    .line 493
    :cond_18
    :goto_c
    aput-object v5, v17, v16

    .line 494
    .line 495
    add-int/lit8 v14, v14, 0x1

    .line 496
    .line 497
    xor-int/2addr v13, v15

    .line 498
    const/4 v10, 0x0

    .line 499
    goto/16 :goto_6

    .line 500
    .line 501
    :cond_19
    const/4 v10, 0x0

    .line 502
    :goto_d
    if-eqz v11, :cond_1c

    .line 503
    .line 504
    invoke-static {v11}, Ljava/lang/Integer;->lowestOneBit(I)I

    .line 505
    .line 506
    .line 507
    move-result v2

    .line 508
    mul-int/lit8 v4, v10, 0x2

    .line 509
    .line 510
    invoke-virtual {v1, v2}, Lq2/i;->h(I)Z

    .line 511
    .line 512
    .line 513
    move-result v5

    .line 514
    if-nez v5, :cond_1a

    .line 515
    .line 516
    invoke-virtual {v0, v2}, Lq2/i;->f(I)I

    .line 517
    .line 518
    .line 519
    move-result v5

    .line 520
    iget-object v6, v12, Lq2/i;->d:[Ljava/lang/Object;

    .line 521
    .line 522
    iget-object v7, v0, Lq2/i;->d:[Ljava/lang/Object;

    .line 523
    .line 524
    aget-object v7, v7, v5

    .line 525
    .line 526
    aput-object v7, v6, v4

    .line 527
    .line 528
    add-int/lit8 v4, v4, 0x1

    .line 529
    .line 530
    invoke-virtual {v0, v5}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v5

    .line 534
    aput-object v5, v6, v4

    .line 535
    .line 536
    goto :goto_e

    .line 537
    :cond_1a
    invoke-virtual {v1, v2}, Lq2/i;->f(I)I

    .line 538
    .line 539
    .line 540
    move-result v5

    .line 541
    iget-object v6, v12, Lq2/i;->d:[Ljava/lang/Object;

    .line 542
    .line 543
    iget-object v7, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 544
    .line 545
    aget-object v7, v7, v5

    .line 546
    .line 547
    aput-object v7, v6, v4

    .line 548
    .line 549
    add-int/lit8 v4, v4, 0x1

    .line 550
    .line 551
    invoke-virtual {v1, v5}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    move-result-object v5

    .line 555
    aput-object v5, v6, v4

    .line 556
    .line 557
    invoke-virtual {v0, v2}, Lq2/i;->h(I)Z

    .line 558
    .line 559
    .line 560
    move-result v4

    .line 561
    if-eqz v4, :cond_1b

    .line 562
    .line 563
    iget v4, v3, Ls2/a;->a:I

    .line 564
    .line 565
    add-int/lit8 v4, v4, 0x1

    .line 566
    .line 567
    iput v4, v3, Ls2/a;->a:I

    .line 568
    .line 569
    :cond_1b
    :goto_e
    add-int/lit8 v10, v10, 0x1

    .line 570
    .line 571
    xor-int/2addr v11, v2

    .line 572
    goto :goto_d

    .line 573
    :cond_1c
    invoke-virtual {v0, v12}, Lq2/i;->e(Lq2/i;)Z

    .line 574
    .line 575
    .line 576
    move-result v2

    .line 577
    if-eqz v2, :cond_1d

    .line 578
    .line 579
    :goto_f
    return-object v0

    .line 580
    :cond_1d
    invoke-virtual {v1, v12}, Lq2/i;->e(Lq2/i;)Z

    .line 581
    .line 582
    .line 583
    move-result v0

    .line 584
    if-eqz v0, :cond_1e

    .line 585
    .line 586
    return-object v1

    .line 587
    :cond_1e
    return-object v12
.end method

.method public final n(ILjava/lang/Object;ILt2/f;)Lq2/i;
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, p3}, Ljp/ke;->d(II)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    shl-int v6, v0, v1

    .line 7
    .line 8
    invoke-virtual {p0, v6}, Lq2/i;->h(I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v6}, Lq2/i;->f(I)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    iget-object p3, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 19
    .line 20
    aget-object p3, p3, p1

    .line 21
    .line 22
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    if-eqz p2, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0, p1, v6, p4}, Lq2/i;->p(IILt2/f;)Lq2/i;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_0
    move-object v2, p0

    .line 34
    goto :goto_3

    .line 35
    :cond_1
    invoke-virtual {p0, v6}, Lq2/i;->i(I)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    invoke-virtual {p0, v6}, Lq2/i;->t(I)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    invoke-virtual {p0, v5}, Lq2/i;->s(I)Lq2/i;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    const/16 v0, 0x1e

    .line 50
    .line 51
    if-ne p3, v0, :cond_6

    .line 52
    .line 53
    iget-object p1, v3, Lq2/i;->d:[Ljava/lang/Object;

    .line 54
    .line 55
    array-length p1, p1

    .line 56
    const/4 p3, 0x0

    .line 57
    invoke-static {p3, p1}, Lkp/r9;->m(II)Lgy0/j;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    const/4 p3, 0x2

    .line 62
    invoke-static {p3, p1}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iget p3, p1, Lgy0/h;->d:I

    .line 67
    .line 68
    iget v0, p1, Lgy0/h;->e:I

    .line 69
    .line 70
    iget p1, p1, Lgy0/h;->f:I

    .line 71
    .line 72
    if-lez p1, :cond_2

    .line 73
    .line 74
    if-le p3, v0, :cond_3

    .line 75
    .line 76
    :cond_2
    if-gez p1, :cond_5

    .line 77
    .line 78
    if-gt v0, p3, :cond_5

    .line 79
    .line 80
    :cond_3
    :goto_0
    iget-object v1, v3, Lq2/i;->d:[Ljava/lang/Object;

    .line 81
    .line 82
    aget-object v1, v1, p3

    .line 83
    .line 84
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_4

    .line 89
    .line 90
    invoke-virtual {v3, p3, p4}, Lq2/i;->k(ILt2/f;)Lq2/i;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    goto :goto_1

    .line 95
    :cond_4
    if-eq p3, v0, :cond_5

    .line 96
    .line 97
    add-int/2addr p3, p1

    .line 98
    goto :goto_0

    .line 99
    :cond_5
    move-object p1, v3

    .line 100
    :goto_1
    move-object v4, p1

    .line 101
    goto :goto_2

    .line 102
    :cond_6
    add-int/lit8 p3, p3, 0x5

    .line 103
    .line 104
    invoke-virtual {v3, p1, p2, p3, p4}, Lq2/i;->n(ILjava/lang/Object;ILt2/f;)Lq2/i;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    goto :goto_1

    .line 109
    :goto_2
    iget-object v7, p4, Lt2/f;->d:Ls2/b;

    .line 110
    .line 111
    move-object v2, p0

    .line 112
    invoke-virtual/range {v2 .. v7}, Lq2/i;->q(Lq2/i;Lq2/i;IILs2/b;)Lq2/i;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0

    .line 117
    :goto_3
    return-object v2
.end method

.method public final o(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p1, p4}, Ljp/ke;->d(II)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    shl-int/2addr v0, v1

    .line 7
    invoke-virtual {p0, v0}, Lq2/i;->h(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lq2/i;->f(I)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    iget-object p4, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    aget-object p4, p4, p1

    .line 20
    .line 21
    invoke-static {p2, p4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_6

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    if-eqz p2, :cond_6

    .line 36
    .line 37
    invoke-virtual {p0, p1, v0, p5}, Lq2/i;->p(IILt2/f;)Lq2/i;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_0
    invoke-virtual {p0, v0}, Lq2/i;->i(I)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_6

    .line 47
    .line 48
    move-object v4, p3

    .line 49
    invoke-virtual {p0, v0}, Lq2/i;->t(I)I

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    invoke-virtual {p0, p3}, Lq2/i;->s(I)Lq2/i;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    const/16 v2, 0x1e

    .line 58
    .line 59
    if-ne p4, v2, :cond_5

    .line 60
    .line 61
    iget-object p1, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 62
    .line 63
    array-length p1, p1

    .line 64
    const/4 p4, 0x0

    .line 65
    invoke-static {p4, p1}, Lkp/r9;->m(II)Lgy0/j;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    const/4 p4, 0x2

    .line 70
    invoke-static {p4, p1}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    iget p4, p1, Lgy0/h;->d:I

    .line 75
    .line 76
    iget v2, p1, Lgy0/h;->e:I

    .line 77
    .line 78
    iget p1, p1, Lgy0/h;->f:I

    .line 79
    .line 80
    if-lez p1, :cond_1

    .line 81
    .line 82
    if-le p4, v2, :cond_2

    .line 83
    .line 84
    :cond_1
    if-gez p1, :cond_4

    .line 85
    .line 86
    if-gt v2, p4, :cond_4

    .line 87
    .line 88
    :cond_2
    :goto_0
    iget-object v3, v1, Lq2/i;->d:[Ljava/lang/Object;

    .line 89
    .line 90
    aget-object v3, v3, p4

    .line 91
    .line 92
    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    if-eqz v3, :cond_3

    .line 97
    .line 98
    invoke-virtual {v1, p4}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    if-eqz v3, :cond_3

    .line 107
    .line 108
    invoke-virtual {v1, p4, p5}, Lq2/i;->k(ILt2/f;)Lq2/i;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    goto :goto_1

    .line 113
    :cond_3
    if-eq p4, v2, :cond_4

    .line 114
    .line 115
    add-int/2addr p4, p1

    .line 116
    goto :goto_0

    .line 117
    :cond_4
    move-object p1, v1

    .line 118
    :goto_1
    move-object v6, p5

    .line 119
    :goto_2
    move-object p2, p1

    .line 120
    goto :goto_3

    .line 121
    :cond_5
    add-int/lit8 v5, p4, 0x5

    .line 122
    .line 123
    move v2, p1

    .line 124
    move-object v3, p2

    .line 125
    move-object v6, p5

    .line 126
    invoke-virtual/range {v1 .. v6}, Lq2/i;->o(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    goto :goto_2

    .line 131
    :goto_3
    iget-object p5, v6, Lt2/f;->d:Ls2/b;

    .line 132
    .line 133
    move p4, v0

    .line 134
    move-object p1, v1

    .line 135
    invoke-virtual/range {p0 .. p5}, Lq2/i;->q(Lq2/i;Lq2/i;IILs2/b;)Lq2/i;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    :cond_6
    return-object p0
.end method

.method public final p(IILt2/f;)Lq2/i;
    .locals 3

    .line 1
    iget v0, p3, Lt2/f;->h:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    invoke-virtual {p3, v0}, Lt2/f;->i(I)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p3, Lt2/f;->f:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 15
    .line 16
    array-length v1, v0

    .line 17
    const/4 v2, 0x2

    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_0
    iget-object v1, p0, Lq2/i;->c:Ls2/b;

    .line 23
    .line 24
    iget-object v2, p3, Lt2/f;->d:Ls2/b;

    .line 25
    .line 26
    if-ne v1, v2, :cond_1

    .line 27
    .line 28
    invoke-static {p1, v0}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 33
    .line 34
    iget p1, p0, Lq2/i;->a:I

    .line 35
    .line 36
    xor-int/2addr p1, p2

    .line 37
    iput p1, p0, Lq2/i;->a:I

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    invoke-static {p1, v0}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    new-instance v0, Lq2/i;

    .line 45
    .line 46
    iget v1, p0, Lq2/i;->a:I

    .line 47
    .line 48
    xor-int/2addr p2, v1

    .line 49
    iget p0, p0, Lq2/i;->b:I

    .line 50
    .line 51
    iget-object p3, p3, Lt2/f;->d:Ls2/b;

    .line 52
    .line 53
    invoke-direct {v0, p2, p0, p1, p3}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 54
    .line 55
    .line 56
    return-object v0
.end method

.method public final q(Lq2/i;Lq2/i;IILs2/b;)Lq2/i;
    .locals 2

    .line 1
    iget-object v0, p0, Lq2/i;->c:Ls2/b;

    .line 2
    .line 3
    if-nez p2, :cond_2

    .line 4
    .line 5
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 6
    .line 7
    array-length p2, p1

    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne p2, v1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return-object p0

    .line 13
    :cond_0
    if-ne v0, p5, :cond_1

    .line 14
    .line 15
    invoke-static {p3, p1}, Ljp/ke;->c(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    iget p1, p0, Lq2/i;->b:I

    .line 22
    .line 23
    xor-int/2addr p1, p4

    .line 24
    iput p1, p0, Lq2/i;->b:I

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_1
    invoke-static {p3, p1}, Ljp/ke;->c(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lq2/i;

    .line 32
    .line 33
    iget p3, p0, Lq2/i;->a:I

    .line 34
    .line 35
    iget p0, p0, Lq2/i;->b:I

    .line 36
    .line 37
    xor-int/2addr p0, p4

    .line 38
    invoke-direct {p2, p3, p0, p1, p5}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 39
    .line 40
    .line 41
    return-object p2

    .line 42
    :cond_2
    if-eq v0, p5, :cond_4

    .line 43
    .line 44
    if-eq p1, p2, :cond_3

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_3
    return-object p0

    .line 48
    :cond_4
    :goto_0
    invoke-virtual {p0, p3, p2, p5}, Lq2/i;->r(ILq2/i;Ls2/b;)Lq2/i;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public final r(ILq2/i;Ls2/b;)Lq2/i;
    .locals 3

    .line 1
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne v1, v2, :cond_0

    .line 6
    .line 7
    iget-object v1, p2, Lq2/i;->d:[Ljava/lang/Object;

    .line 8
    .line 9
    array-length v1, v1

    .line 10
    const/4 v2, 0x2

    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    iget v1, p2, Lq2/i;->b:I

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    iget p0, p0, Lq2/i;->b:I

    .line 18
    .line 19
    iput p0, p2, Lq2/i;->a:I

    .line 20
    .line 21
    return-object p2

    .line 22
    :cond_0
    iget-object v1, p0, Lq2/i;->c:Ls2/b;

    .line 23
    .line 24
    if-ne v1, p3, :cond_1

    .line 25
    .line 26
    aput-object p2, v0, p1

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_1
    array-length v1, v0

    .line 30
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const-string v1, "copyOf(...)"

    .line 35
    .line 36
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    aput-object p2, v0, p1

    .line 40
    .line 41
    new-instance p1, Lq2/i;

    .line 42
    .line 43
    iget p2, p0, Lq2/i;->a:I

    .line 44
    .line 45
    iget p0, p0, Lq2/i;->b:I

    .line 46
    .line 47
    invoke-direct {p1, p2, p0, v0, p3}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 48
    .line 49
    .line 50
    return-object p1
.end method

.method public final s(I)Lq2/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    const-string p1, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode>"

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    check-cast p0, Lq2/i;

    .line 11
    .line 12
    return-object p0
.end method

.method public final t(I)I
    .locals 1

    .line 1
    iget-object v0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    add-int/lit8 v0, v0, -0x1

    .line 5
    .line 6
    iget p0, p0, Lq2/i;->b:I

    .line 7
    .line 8
    add-int/lit8 p1, p1, -0x1

    .line 9
    .line 10
    and-int/2addr p0, p1

    .line 11
    invoke-static {p0}, Ljava/lang/Integer;->bitCount(I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    sub-int/2addr v0, p0

    .line 16
    return v0
.end method

.method public final u(IILjava/lang/Object;Ljava/lang/Object;)Lb11/a;
    .locals 11

    .line 1
    invoke-static {p1, p2}, Ljp/ke;->d(II)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    shl-int v4, v1, v0

    .line 7
    .line 8
    invoke-virtual {p0, v4}, Lq2/i;->h(I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v2, 0x0

    .line 13
    const-string v3, "copyOf(...)"

    .line 14
    .line 15
    const/4 v10, 0x0

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    move-object v0, v3

    .line 19
    invoke-virtual {p0, v4}, Lq2/i;->f(I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    iget-object v5, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 24
    .line 25
    aget-object v5, v5, v3

    .line 26
    .line 27
    invoke-static {p3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eqz v5, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0, v3}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    if-ne p1, p4, :cond_0

    .line 38
    .line 39
    goto/16 :goto_2

    .line 40
    .line 41
    :cond_0
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 42
    .line 43
    array-length p2, p1

    .line 44
    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    add-int/2addr v3, v1

    .line 52
    aput-object p4, p1, v3

    .line 53
    .line 54
    new-instance p2, Lq2/i;

    .line 55
    .line 56
    iget p3, p0, Lq2/i;->a:I

    .line 57
    .line 58
    iget p0, p0, Lq2/i;->b:I

    .line 59
    .line 60
    invoke-direct {p2, p3, p0, p1, v10}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 61
    .line 62
    .line 63
    new-instance p0, Lb11/a;

    .line 64
    .line 65
    const/16 p1, 0x8

    .line 66
    .line 67
    invoke-direct {p0, p2, v2, p1}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_1
    const/4 v9, 0x0

    .line 72
    move-object v2, p0

    .line 73
    move v5, p1

    .line 74
    move v8, p2

    .line 75
    move-object v6, p3

    .line 76
    move-object v7, p4

    .line 77
    invoke-virtual/range {v2 .. v9}, Lq2/i;->a(IIILjava/lang/Object;Ljava/lang/Object;ILs2/b;)[Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    move-object p1, v2

    .line 82
    new-instance p2, Lq2/i;

    .line 83
    .line 84
    iget p3, p1, Lq2/i;->a:I

    .line 85
    .line 86
    xor-int/2addr p3, v4

    .line 87
    iget p1, p1, Lq2/i;->b:I

    .line 88
    .line 89
    or-int/2addr p1, v4

    .line 90
    invoke-direct {p2, p3, p1, p0, v10}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 91
    .line 92
    .line 93
    new-instance p0, Lb11/a;

    .line 94
    .line 95
    const/16 p1, 0x8

    .line 96
    .line 97
    invoke-direct {p0, p2, v1, p1}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 98
    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_2
    move v5, p1

    .line 102
    move v8, p2

    .line 103
    move-object v6, p3

    .line 104
    move-object v7, p4

    .line 105
    move-object v0, v3

    .line 106
    move-object p1, p0

    .line 107
    invoke-virtual {p1, v4}, Lq2/i;->i(I)Z

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    if-eqz p0, :cond_a

    .line 112
    .line 113
    invoke-virtual {p1, v4}, Lq2/i;->t(I)I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    invoke-virtual {p1, p0}, Lq2/i;->s(I)Lq2/i;

    .line 118
    .line 119
    .line 120
    move-result-object p2

    .line 121
    const/16 p3, 0x1e

    .line 122
    .line 123
    if-ne v8, p3, :cond_8

    .line 124
    .line 125
    iget-object p3, p2, Lq2/i;->d:[Ljava/lang/Object;

    .line 126
    .line 127
    array-length p3, p3

    .line 128
    invoke-static {v2, p3}, Lkp/r9;->m(II)Lgy0/j;

    .line 129
    .line 130
    .line 131
    move-result-object p3

    .line 132
    const/4 p4, 0x2

    .line 133
    invoke-static {p4, p3}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 134
    .line 135
    .line 136
    move-result-object p3

    .line 137
    iget p4, p3, Lgy0/h;->d:I

    .line 138
    .line 139
    iget v3, p3, Lgy0/h;->e:I

    .line 140
    .line 141
    iget p3, p3, Lgy0/h;->f:I

    .line 142
    .line 143
    if-lez p3, :cond_3

    .line 144
    .line 145
    if-le p4, v3, :cond_4

    .line 146
    .line 147
    :cond_3
    if-gez p3, :cond_7

    .line 148
    .line 149
    if-gt v3, p4, :cond_7

    .line 150
    .line 151
    :cond_4
    :goto_0
    iget-object v5, p2, Lq2/i;->d:[Ljava/lang/Object;

    .line 152
    .line 153
    aget-object v5, v5, p4

    .line 154
    .line 155
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-eqz v5, :cond_6

    .line 160
    .line 161
    invoke-virtual {p2, p4}, Lq2/i;->x(I)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    if-ne v7, p3, :cond_5

    .line 166
    .line 167
    move-object p2, v10

    .line 168
    goto :goto_1

    .line 169
    :cond_5
    iget-object p2, p2, Lq2/i;->d:[Ljava/lang/Object;

    .line 170
    .line 171
    array-length p3, p2

    .line 172
    invoke-static {p2, p3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p2

    .line 176
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    add-int/2addr p4, v1

    .line 180
    aput-object v7, p2, p4

    .line 181
    .line 182
    new-instance p3, Lq2/i;

    .line 183
    .line 184
    invoke-direct {p3, v2, v2, p2, v10}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 185
    .line 186
    .line 187
    new-instance p2, Lb11/a;

    .line 188
    .line 189
    const/16 p4, 0x8

    .line 190
    .line 191
    invoke-direct {p2, p3, v2, p4}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 192
    .line 193
    .line 194
    goto :goto_1

    .line 195
    :cond_6
    if-eq p4, v3, :cond_7

    .line 196
    .line 197
    add-int/2addr p4, p3

    .line 198
    goto :goto_0

    .line 199
    :cond_7
    iget-object p2, p2, Lq2/i;->d:[Ljava/lang/Object;

    .line 200
    .line 201
    invoke-static {p2, v2, v6, v7}, Ljp/ke;->a([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p2

    .line 205
    new-instance p3, Lq2/i;

    .line 206
    .line 207
    invoke-direct {p3, v2, v2, p2, v10}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 208
    .line 209
    .line 210
    new-instance p2, Lb11/a;

    .line 211
    .line 212
    const/16 p4, 0x8

    .line 213
    .line 214
    invoke-direct {p2, p3, v1, p4}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 215
    .line 216
    .line 217
    :goto_1
    if-nez p2, :cond_9

    .line 218
    .line 219
    goto :goto_2

    .line 220
    :cond_8
    add-int/lit8 p3, v8, 0x5

    .line 221
    .line 222
    invoke-virtual {p2, v5, p3, v6, v7}, Lq2/i;->u(IILjava/lang/Object;Ljava/lang/Object;)Lb11/a;

    .line 223
    .line 224
    .line 225
    move-result-object p2

    .line 226
    if-nez p2, :cond_9

    .line 227
    .line 228
    :goto_2
    return-object v10

    .line 229
    :cond_9
    iget-object p3, p2, Lb11/a;->f:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast p3, Lq2/i;

    .line 232
    .line 233
    invoke-virtual {p1, p0, v4, p3}, Lq2/i;->w(IILq2/i;)Lq2/i;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    iput-object p0, p2, Lb11/a;->f:Ljava/lang/Object;

    .line 238
    .line 239
    return-object p2

    .line 240
    :cond_a
    invoke-virtual {p1, v4}, Lq2/i;->f(I)I

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    iget-object p2, p1, Lq2/i;->d:[Ljava/lang/Object;

    .line 245
    .line 246
    invoke-static {p2, p0, v6, v7}, Ljp/ke;->a([Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;)[Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    new-instance p2, Lq2/i;

    .line 251
    .line 252
    iget p3, p1, Lq2/i;->a:I

    .line 253
    .line 254
    or-int/2addr p3, v4

    .line 255
    iget p1, p1, Lq2/i;->b:I

    .line 256
    .line 257
    invoke-direct {p2, p3, p1, p0, v10}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 258
    .line 259
    .line 260
    new-instance p0, Lb11/a;

    .line 261
    .line 262
    const/16 p1, 0x8

    .line 263
    .line 264
    invoke-direct {p0, p2, v1, p1}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 265
    .line 266
    .line 267
    return-object p0
.end method

.method public final v(ILjava/lang/Object;I)Lq2/i;
    .locals 9

    .line 1
    invoke-static {p1, p3}, Ljp/ke;->d(II)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    shl-int v0, v1, v0

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lq2/i;->h(I)Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lq2/i;->f(I)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iget-object p3, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 21
    .line 22
    aget-object p3, p3, p1

    .line 23
    .line 24
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    if-eqz p2, :cond_a

    .line 29
    .line 30
    iget-object p2, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 31
    .line 32
    array-length p3, p2

    .line 33
    if-ne p3, v3, :cond_0

    .line 34
    .line 35
    goto/16 :goto_2

    .line 36
    .line 37
    :cond_0
    invoke-static {p1, p2}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    new-instance p2, Lq2/i;

    .line 42
    .line 43
    iget p3, p0, Lq2/i;->a:I

    .line 44
    .line 45
    xor-int/2addr p3, v0

    .line 46
    iget p0, p0, Lq2/i;->b:I

    .line 47
    .line 48
    invoke-direct {p2, p3, p0, p1, v4}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 49
    .line 50
    .line 51
    return-object p2

    .line 52
    :cond_1
    invoke-virtual {p0, v0}, Lq2/i;->i(I)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_a

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Lq2/i;->t(I)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    invoke-virtual {p0, v2}, Lq2/i;->s(I)Lq2/i;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    const/16 v6, 0x1e

    .line 67
    .line 68
    if-ne p3, v6, :cond_7

    .line 69
    .line 70
    iget-object p1, v5, Lq2/i;->d:[Ljava/lang/Object;

    .line 71
    .line 72
    array-length p1, p1

    .line 73
    const/4 p3, 0x0

    .line 74
    invoke-static {p3, p1}, Lkp/r9;->m(II)Lgy0/j;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-static {v3, p1}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    iget v6, p1, Lgy0/h;->d:I

    .line 83
    .line 84
    iget v7, p1, Lgy0/h;->e:I

    .line 85
    .line 86
    iget p1, p1, Lgy0/h;->f:I

    .line 87
    .line 88
    if-lez p1, :cond_2

    .line 89
    .line 90
    if-le v6, v7, :cond_3

    .line 91
    .line 92
    :cond_2
    if-gez p1, :cond_6

    .line 93
    .line 94
    if-gt v7, v6, :cond_6

    .line 95
    .line 96
    :cond_3
    :goto_0
    iget-object v8, v5, Lq2/i;->d:[Ljava/lang/Object;

    .line 97
    .line 98
    aget-object v8, v8, v6

    .line 99
    .line 100
    invoke-static {p2, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    if-eqz v8, :cond_5

    .line 105
    .line 106
    iget-object p1, v5, Lq2/i;->d:[Ljava/lang/Object;

    .line 107
    .line 108
    array-length p2, p1

    .line 109
    if-ne p2, v3, :cond_4

    .line 110
    .line 111
    move-object p2, v4

    .line 112
    goto :goto_1

    .line 113
    :cond_4
    invoke-static {v6, p1}, Ljp/ke;->b(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    new-instance p2, Lq2/i;

    .line 118
    .line 119
    invoke-direct {p2, p3, p3, p1, v4}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_5
    if-eq v6, v7, :cond_6

    .line 124
    .line 125
    add-int/2addr v6, p1

    .line 126
    goto :goto_0

    .line 127
    :cond_6
    move-object p2, v5

    .line 128
    goto :goto_1

    .line 129
    :cond_7
    add-int/lit8 p3, p3, 0x5

    .line 130
    .line 131
    invoke-virtual {v5, p1, p2, p3}, Lq2/i;->v(ILjava/lang/Object;I)Lq2/i;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    :goto_1
    if-nez p2, :cond_9

    .line 136
    .line 137
    iget-object p1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 138
    .line 139
    array-length p2, p1

    .line 140
    if-ne p2, v1, :cond_8

    .line 141
    .line 142
    :goto_2
    return-object v4

    .line 143
    :cond_8
    invoke-static {v2, p1}, Ljp/ke;->c(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    new-instance p2, Lq2/i;

    .line 148
    .line 149
    iget p3, p0, Lq2/i;->a:I

    .line 150
    .line 151
    iget p0, p0, Lq2/i;->b:I

    .line 152
    .line 153
    xor-int/2addr p0, v0

    .line 154
    invoke-direct {p2, p3, p0, p1, v4}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 155
    .line 156
    .line 157
    return-object p2

    .line 158
    :cond_9
    if-eq v5, p2, :cond_a

    .line 159
    .line 160
    invoke-virtual {p0, v2, v0, p2}, Lq2/i;->w(IILq2/i;)Lq2/i;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    :cond_a
    return-object p0
.end method

.method public final w(IILq2/i;)Lq2/i;
    .locals 8

    .line 1
    iget-object v0, p3, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x2

    .line 5
    const/4 v3, 0x0

    .line 6
    const-string v4, "copyOf(...)"

    .line 7
    .line 8
    if-ne v1, v2, :cond_1

    .line 9
    .line 10
    iget v1, p3, Lq2/i;->b:I

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    iget-object v1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 15
    .line 16
    array-length v1, v1

    .line 17
    const/4 v2, 0x1

    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    iget p0, p0, Lq2/i;->b:I

    .line 21
    .line 22
    iput p0, p3, Lq2/i;->a:I

    .line 23
    .line 24
    return-object p3

    .line 25
    :cond_0
    invoke-virtual {p0, p2}, Lq2/i;->f(I)I

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    iget-object v1, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    aget-object v5, v0, v5

    .line 33
    .line 34
    aget-object v0, v0, v2

    .line 35
    .line 36
    array-length v6, v1

    .line 37
    add-int/2addr v6, v2

    .line 38
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    invoke-static {v6, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    add-int/lit8 v4, p1, 0x2

    .line 46
    .line 47
    add-int/lit8 v7, p1, 0x1

    .line 48
    .line 49
    array-length v1, v1

    .line 50
    invoke-static {v4, v7, v1, v6, v6}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    add-int/lit8 v1, p3, 0x2

    .line 54
    .line 55
    invoke-static {v1, p3, p1, v6, v6}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    aput-object v5, v6, p3

    .line 59
    .line 60
    add-int/2addr p3, v2

    .line 61
    aput-object v0, v6, p3

    .line 62
    .line 63
    new-instance p1, Lq2/i;

    .line 64
    .line 65
    iget p3, p0, Lq2/i;->a:I

    .line 66
    .line 67
    xor-int/2addr p3, p2

    .line 68
    iget p0, p0, Lq2/i;->b:I

    .line 69
    .line 70
    xor-int/2addr p0, p2

    .line 71
    invoke-direct {p1, p3, p0, v6, v3}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 72
    .line 73
    .line 74
    return-object p1

    .line 75
    :cond_1
    iget-object p2, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 76
    .line 77
    array-length v0, p2

    .line 78
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    aput-object p3, p2, p1

    .line 86
    .line 87
    new-instance p1, Lq2/i;

    .line 88
    .line 89
    iget p3, p0, Lq2/i;->a:I

    .line 90
    .line 91
    iget p0, p0, Lq2/i;->b:I

    .line 92
    .line 93
    invoke-direct {p1, p3, p0, p2, v3}, Lq2/i;-><init>(II[Ljava/lang/Object;Ls2/b;)V

    .line 94
    .line 95
    .line 96
    return-object p1
.end method

.method public final x(I)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lq2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x1

    .line 4
    .line 5
    aget-object p0, p0, p1

    .line 6
    .line 7
    return-object p0
.end method
