.class public final Ll2/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll2/f2;

.field public final b:[I

.field public final c:I

.field public d:[Ljava/lang/Object;

.field public final e:I

.field public f:Z

.field public g:I

.field public h:I

.field public i:I

.field public final j:Ll2/q0;

.field public k:I

.field public l:I

.field public m:I

.field public n:Z


# direct methods
.method public constructor <init>(Ll2/f2;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/e2;->a:Ll2/f2;

    .line 5
    .line 6
    iget-object v0, p1, Ll2/f2;->d:[I

    .line 7
    .line 8
    iput-object v0, p0, Ll2/e2;->b:[I

    .line 9
    .line 10
    iget v0, p1, Ll2/f2;->e:I

    .line 11
    .line 12
    iput v0, p0, Ll2/e2;->c:I

    .line 13
    .line 14
    iget-object v1, p1, Ll2/f2;->f:[Ljava/lang/Object;

    .line 15
    .line 16
    iput-object v1, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 17
    .line 18
    iget p1, p1, Ll2/f2;->g:I

    .line 19
    .line 20
    iput p1, p0, Ll2/e2;->e:I

    .line 21
    .line 22
    iput v0, p0, Ll2/e2;->h:I

    .line 23
    .line 24
    const/4 p1, -0x1

    .line 25
    iput p1, p0, Ll2/e2;->i:I

    .line 26
    .line 27
    new-instance p1, Ll2/q0;

    .line 28
    .line 29
    invoke-direct {p1}, Ll2/q0;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Ll2/e2;->j:Ll2/q0;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a(I)Ll2/a;
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/e2;->a:Ll2/f2;

    .line 2
    .line 3
    iget-object v0, v0, Ll2/f2;->l:Ljava/util/ArrayList;

    .line 4
    .line 5
    iget p0, p0, Ll2/e2;->c:I

    .line 6
    .line 7
    invoke-static {v0, p1, p0}, Ll2/h2;->e(Ljava/util/ArrayList;II)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-gez p0, :cond_0

    .line 12
    .line 13
    new-instance v1, Ll2/a;

    .line 14
    .line 15
    invoke-direct {v1, p1}, Ll2/a;-><init>(I)V

    .line 16
    .line 17
    .line 18
    add-int/lit8 p0, p0, 0x1

    .line 19
    .line 20
    neg-int p0, p0

    .line 21
    invoke-virtual {v0, p0, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object v1

    .line 25
    :cond_0
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ll2/a;

    .line 30
    .line 31
    return-object p0
.end method

.method public final b(I[I)Ljava/lang/Object;
    .locals 2

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    add-int/lit8 v0, p1, 0x1

    .line 4
    .line 5
    aget v0, p2, v0

    .line 6
    .line 7
    const/high16 v1, 0x10000000

    .line 8
    .line 9
    and-int/2addr v1, v0

    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 13
    .line 14
    array-length v1, p2

    .line 15
    if-lt p1, v1, :cond_0

    .line 16
    .line 17
    array-length p1, p2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/lit8 p1, p1, 0x4

    .line 20
    .line 21
    aget p1, p2, p1

    .line 22
    .line 23
    shr-int/lit8 p2, v0, 0x1d

    .line 24
    .line 25
    invoke-static {p2}, Ljava/lang/Integer;->bitCount(I)I

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    add-int/2addr p1, p2

    .line 30
    :goto_0
    aget-object p0, p0, p1

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 34
    .line 35
    return-object p0
.end method

.method public final c()V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Ll2/e2;->f:Z

    .line 3
    .line 4
    iget-object v0, p0, Ll2/e2;->a:Ll2/f2;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Ll2/e2;->a:Ll2/f2;

    .line 10
    .line 11
    if-ne v1, v0, :cond_0

    .line 12
    .line 13
    iget v1, v0, Ll2/f2;->h:I

    .line 14
    .line 15
    if-lez v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v1, "Unexpected reader close()"

    .line 19
    .line 20
    invoke-static {v1}, Ll2/v;->c(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :goto_0
    iget v1, v0, Ll2/f2;->h:I

    .line 24
    .line 25
    add-int/lit8 v1, v1, -0x1

    .line 26
    .line 27
    iput v1, v0, Ll2/f2;->h:I

    .line 28
    .line 29
    const/4 v0, 0x0

    .line 30
    new-array v0, v0, [Ljava/lang/Object;

    .line 31
    .line 32
    iput-object v0, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 33
    .line 34
    return-void
.end method

.method public final d(I)Z
    .locals 1

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    add-int/2addr p1, v0

    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    const/high16 p1, 0x4000000

    .line 10
    .line 11
    and-int/2addr p0, p1

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final e()V
    .locals 6

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    if-nez v0, :cond_5

    .line 4
    .line 5
    iget v0, p0, Ll2/e2;->g:I

    .line 6
    .line 7
    iget v1, p0, Ll2/e2;->h:I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    move v0, v3

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v0, v2

    .line 16
    :goto_0
    if-nez v0, :cond_1

    .line 17
    .line 18
    const-string v0, "endGroup() not called at the end of a group"

    .line 19
    .line 20
    invoke-static {v0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    iget v0, p0, Ll2/e2;->i:I

    .line 24
    .line 25
    mul-int/lit8 v0, v0, 0x5

    .line 26
    .line 27
    add-int/lit8 v0, v0, 0x2

    .line 28
    .line 29
    iget-object v1, p0, Ll2/e2;->b:[I

    .line 30
    .line 31
    aget v0, v1, v0

    .line 32
    .line 33
    iput v0, p0, Ll2/e2;->i:I

    .line 34
    .line 35
    iget v4, p0, Ll2/e2;->c:I

    .line 36
    .line 37
    if-gez v0, :cond_2

    .line 38
    .line 39
    move v5, v4

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    invoke-static {v0, v1}, Ll2/h2;->a(I[I)I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    add-int/2addr v5, v0

    .line 46
    :goto_1
    iput v5, p0, Ll2/e2;->h:I

    .line 47
    .line 48
    iget-object v5, p0, Ll2/e2;->j:Ll2/q0;

    .line 49
    .line 50
    invoke-virtual {v5}, Ll2/q0;->b()I

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    if-gez v5, :cond_3

    .line 55
    .line 56
    iput v2, p0, Ll2/e2;->l:I

    .line 57
    .line 58
    iput v2, p0, Ll2/e2;->m:I

    .line 59
    .line 60
    return-void

    .line 61
    :cond_3
    iput v5, p0, Ll2/e2;->l:I

    .line 62
    .line 63
    sub-int/2addr v4, v3

    .line 64
    if-lt v0, v4, :cond_4

    .line 65
    .line 66
    iget v0, p0, Ll2/e2;->e:I

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    add-int/2addr v0, v3

    .line 70
    mul-int/lit8 v0, v0, 0x5

    .line 71
    .line 72
    add-int/lit8 v0, v0, 0x4

    .line 73
    .line 74
    aget v0, v1, v0

    .line 75
    .line 76
    :goto_2
    iput v0, p0, Ll2/e2;->m:I

    .line 77
    .line 78
    :cond_5
    return-void
.end method

.method public final f()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ll2/e2;->g:I

    .line 2
    .line 3
    iget v1, p0, Ll2/e2;->h:I

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Ll2/e2;->b:[I

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Ll2/e2;->b(I[I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final g()I
    .locals 2

    .line 1
    iget v0, p0, Ll2/e2;->g:I

    .line 2
    .line 3
    iget v1, p0, Ll2/e2;->h:I

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    mul-int/lit8 v0, v0, 0x5

    .line 8
    .line 9
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 10
    .line 11
    aget p0, p0, v0

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public final h(II)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/e2;->b:[I

    .line 2
    .line 3
    invoke-static {p1, v0}, Ll2/h2;->c(I[I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    add-int/lit8 p1, p1, 0x1

    .line 8
    .line 9
    iget v2, p0, Ll2/e2;->c:I

    .line 10
    .line 11
    if-ge p1, v2, :cond_0

    .line 12
    .line 13
    mul-int/lit8 p1, p1, 0x5

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x4

    .line 16
    .line 17
    aget p1, v0, p1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iget p1, p0, Ll2/e2;->e:I

    .line 21
    .line 22
    :goto_0
    add-int/2addr v1, p2

    .line 23
    if-ge v1, p1, :cond_1

    .line 24
    .line 25
    iget-object p0, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 26
    .line 27
    aget-object p0, p0, v1

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 31
    .line 32
    return-object p0
.end method

.method public final i(I)I
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    return p0
.end method

.method public final j(I)Z
    .locals 1

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    add-int/2addr p1, v0

    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    const/high16 p1, 0x8000000

    .line 10
    .line 11
    and-int/2addr p0, p1

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final k(I)Z
    .locals 1

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    add-int/2addr p1, v0

    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    const/high16 p1, 0x20000000

    .line 10
    .line 11
    and-int/2addr p0, p1

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final l(I)Z
    .locals 1

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    add-int/2addr p1, v0

    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    const/high16 p1, 0x40000000    # 2.0f

    .line 10
    .line 11
    and-int/2addr p0, p1

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final m()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    if-gtz v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Ll2/e2;->l:I

    .line 6
    .line 7
    iget v1, p0, Ll2/e2;->m:I

    .line 8
    .line 9
    if-lt v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v1, 0x1

    .line 13
    iput-boolean v1, p0, Ll2/e2;->n:Z

    .line 14
    .line 15
    iget-object v1, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 16
    .line 17
    add-int/lit8 v2, v0, 0x1

    .line 18
    .line 19
    iput v2, p0, Ll2/e2;->l:I

    .line 20
    .line 21
    aget-object p0, v1, v0

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 25
    iput-boolean v0, p0, Ll2/e2;->n:Z

    .line 26
    .line 27
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 28
    .line 29
    return-object p0
.end method

.method public final n(I)Ljava/lang/Object;
    .locals 3

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    add-int/lit8 v0, p1, 0x1

    .line 4
    .line 5
    iget-object v1, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget v0, v1, v0

    .line 8
    .line 9
    const/high16 v2, 0x40000000    # 2.0f

    .line 10
    .line 11
    and-int/2addr v0, v2

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 17
    .line 18
    add-int/lit8 p1, p1, 0x4

    .line 19
    .line 20
    aget p1, v1, p1

    .line 21
    .line 22
    aget-object p0, p0, p1

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method public final o(I)I
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x1

    .line 4
    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    const p1, 0x3ffffff

    .line 10
    .line 11
    .line 12
    and-int/2addr p0, p1

    .line 13
    return p0
.end method

.method public final p(I[I)Ljava/lang/Object;
    .locals 2

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    add-int/lit8 v0, p1, 0x1

    .line 4
    .line 5
    aget v0, p2, v0

    .line 6
    .line 7
    const/high16 v1, 0x20000000

    .line 8
    .line 9
    and-int/2addr v1, v0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Ll2/e2;->d:[Ljava/lang/Object;

    .line 13
    .line 14
    add-int/lit8 p1, p1, 0x4

    .line 15
    .line 16
    aget p1, p2, p1

    .line 17
    .line 18
    shr-int/lit8 p2, v0, 0x1e

    .line 19
    .line 20
    invoke-static {p2}, Ljava/lang/Integer;->bitCount(I)I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    add-int/2addr p2, p1

    .line 25
    aget-object p0, p0, p2

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method

.method public final q(I)I
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x5

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    iget-object p0, p0, Ll2/e2;->b:[I

    .line 6
    .line 7
    aget p0, p0, p1

    .line 8
    .line 9
    return p0
.end method

.method public final r(I)V
    .locals 4

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v0, v1

    .line 9
    :goto_0
    if-nez v0, :cond_1

    .line 10
    .line 11
    const-string v0, "Cannot reposition while in an empty region"

    .line 12
    .line 13
    invoke-static {v0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :cond_1
    iput p1, p0, Ll2/e2;->g:I

    .line 17
    .line 18
    iget-object v0, p0, Ll2/e2;->b:[I

    .line 19
    .line 20
    iget v2, p0, Ll2/e2;->c:I

    .line 21
    .line 22
    if-ge p1, v2, :cond_2

    .line 23
    .line 24
    mul-int/lit8 p1, p1, 0x5

    .line 25
    .line 26
    add-int/lit8 p1, p1, 0x2

    .line 27
    .line 28
    aget p1, v0, p1

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    const/4 p1, -0x1

    .line 32
    :goto_1
    iget v3, p0, Ll2/e2;->i:I

    .line 33
    .line 34
    if-eq p1, v3, :cond_4

    .line 35
    .line 36
    iput p1, p0, Ll2/e2;->i:I

    .line 37
    .line 38
    if-gez p1, :cond_3

    .line 39
    .line 40
    iput v2, p0, Ll2/e2;->h:I

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_3
    invoke-static {p1, v0}, Ll2/h2;->a(I[I)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    add-int/2addr v0, p1

    .line 48
    iput v0, p0, Ll2/e2;->h:I

    .line 49
    .line 50
    :goto_2
    iput v1, p0, Ll2/e2;->l:I

    .line 51
    .line 52
    iput v1, p0, Ll2/e2;->m:I

    .line 53
    .line 54
    :cond_4
    return-void
.end method

.method public final s()I
    .locals 5

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    if-nez v0, :cond_1

    .line 10
    .line 11
    const-string v0, "Cannot skip while in an empty region"

    .line 12
    .line 13
    invoke-static {v0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :cond_1
    iget v0, p0, Ll2/e2;->g:I

    .line 17
    .line 18
    mul-int/lit8 v2, v0, 0x5

    .line 19
    .line 20
    add-int/2addr v2, v1

    .line 21
    iget-object v3, p0, Ll2/e2;->b:[I

    .line 22
    .line 23
    aget v2, v3, v2

    .line 24
    .line 25
    const/high16 v4, 0x40000000    # 2.0f

    .line 26
    .line 27
    and-int/2addr v2, v4

    .line 28
    if-eqz v2, :cond_2

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    mul-int/lit8 v2, v0, 0x5

    .line 32
    .line 33
    add-int/2addr v2, v1

    .line 34
    aget v1, v3, v2

    .line 35
    .line 36
    const v2, 0x3ffffff

    .line 37
    .line 38
    .line 39
    and-int/2addr v1, v2

    .line 40
    :goto_1
    invoke-static {v0, v3}, Ll2/h2;->a(I[I)I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    add-int/2addr v2, v0

    .line 45
    iput v2, p0, Ll2/e2;->g:I

    .line 46
    .line 47
    return v1
.end method

.method public final t()V
    .locals 2

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v0, v1

    .line 9
    :goto_0
    if-nez v0, :cond_1

    .line 10
    .line 11
    const-string v0, "Cannot skip the enclosing group while in an empty region"

    .line 12
    .line 13
    invoke-static {v0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :cond_1
    iget v0, p0, Ll2/e2;->h:I

    .line 17
    .line 18
    iput v0, p0, Ll2/e2;->g:I

    .line 19
    .line 20
    iput v1, p0, Ll2/e2;->l:I

    .line 21
    .line 22
    iput v1, p0, Ll2/e2;->m:I

    .line 23
    .line 24
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SlotReader(current="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Ll2/e2;->g:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", key="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Ll2/e2;->g()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ", parent="

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget v1, p0, Ll2/e2;->i:I

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", end="

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget p0, p0, Ll2/e2;->h:I

    .line 41
    .line 42
    const/16 v1, 0x29

    .line 43
    .line 44
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public final u()V
    .locals 6

    .line 1
    iget v0, p0, Ll2/e2;->k:I

    .line 2
    .line 3
    if-gtz v0, :cond_4

    .line 4
    .line 5
    iget v0, p0, Ll2/e2;->i:I

    .line 6
    .line 7
    iget v1, p0, Ll2/e2;->g:I

    .line 8
    .line 9
    mul-int/lit8 v2, v1, 0x5

    .line 10
    .line 11
    add-int/lit8 v2, v2, 0x2

    .line 12
    .line 13
    iget-object v3, p0, Ll2/e2;->b:[I

    .line 14
    .line 15
    aget v2, v3, v2

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    if-ne v2, v0, :cond_0

    .line 19
    .line 20
    move v0, v4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "Invalid slot table detected"

    .line 26
    .line 27
    invoke-static {v0}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    iget v0, p0, Ll2/e2;->l:I

    .line 31
    .line 32
    iget v2, p0, Ll2/e2;->m:I

    .line 33
    .line 34
    iget-object v5, p0, Ll2/e2;->j:Ll2/q0;

    .line 35
    .line 36
    if-nez v0, :cond_2

    .line 37
    .line 38
    if-nez v2, :cond_2

    .line 39
    .line 40
    const/4 v0, -0x1

    .line 41
    invoke-virtual {v5, v0}, Ll2/q0;->c(I)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    invoke-virtual {v5, v0}, Ll2/q0;->c(I)V

    .line 46
    .line 47
    .line 48
    :goto_1
    iput v1, p0, Ll2/e2;->i:I

    .line 49
    .line 50
    invoke-static {v1, v3}, Ll2/h2;->a(I[I)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    add-int/2addr v0, v1

    .line 55
    iput v0, p0, Ll2/e2;->h:I

    .line 56
    .line 57
    add-int/lit8 v0, v1, 0x1

    .line 58
    .line 59
    iput v0, p0, Ll2/e2;->g:I

    .line 60
    .line 61
    invoke-static {v1, v3}, Ll2/h2;->c(I[I)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    iput v2, p0, Ll2/e2;->l:I

    .line 66
    .line 67
    iget v2, p0, Ll2/e2;->c:I

    .line 68
    .line 69
    sub-int/2addr v2, v4

    .line 70
    if-lt v1, v2, :cond_3

    .line 71
    .line 72
    iget v0, p0, Ll2/e2;->e:I

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    mul-int/lit8 v0, v0, 0x5

    .line 76
    .line 77
    add-int/lit8 v0, v0, 0x4

    .line 78
    .line 79
    aget v0, v3, v0

    .line 80
    .line 81
    :goto_2
    iput v0, p0, Ll2/e2;->m:I

    .line 82
    .line 83
    :cond_4
    return-void
.end method
