.class public final Lry0/i;
.super Lp2/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:I

.field public h:[Ljava/lang/Object;

.field public i:Z


# direct methods
.method public constructor <init>([Ljava/lang/Object;III)V
    .locals 2

    .line 1
    const-string v0, "root"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    invoke-direct {p0, p2, p3, v0}, Lp2/a;-><init>(III)V

    .line 8
    .line 9
    .line 10
    iput p4, p0, Lry0/i;->g:I

    .line 11
    .line 12
    new-array p4, p4, [Ljava/lang/Object;

    .line 13
    .line 14
    iput-object p4, p0, Lry0/i;->h:[Ljava/lang/Object;

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    const/4 v1, 0x1

    .line 18
    if-ne p2, p3, :cond_0

    .line 19
    .line 20
    move p3, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move p3, v0

    .line 23
    :goto_0
    iput-boolean p3, p0, Lry0/i;->i:Z

    .line 24
    .line 25
    aput-object p1, p4, v0

    .line 26
    .line 27
    sub-int/2addr p2, p3

    .line 28
    invoke-virtual {p0, p2, v1}, Lry0/i;->b(II)V

    .line 29
    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lp2/a;->e:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x1f

    .line 4
    .line 5
    iget-object v1, p0, Lry0/i;->h:[Ljava/lang/Object;

    .line 6
    .line 7
    iget p0, p0, Lry0/i;->g:I

    .line 8
    .line 9
    add-int/lit8 p0, p0, -0x1

    .line 10
    .line 11
    aget-object p0, v1, p0

    .line 12
    .line 13
    const-string v1, "null cannot be cast to non-null type kotlin.Array<E of kotlinx.collections.immutable.implementations.immutableList.TrieIterator>"

    .line 14
    .line 15
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    check-cast p0, [Ljava/lang/Object;

    .line 19
    .line 20
    aget-object p0, p0, v0

    .line 21
    .line 22
    return-object p0
.end method

.method public final b(II)V
    .locals 4

    .line 1
    iget v0, p0, Lry0/i;->g:I

    .line 2
    .line 3
    sub-int/2addr v0, p2

    .line 4
    mul-int/lit8 v0, v0, 0x5

    .line 5
    .line 6
    :goto_0
    iget v1, p0, Lry0/i;->g:I

    .line 7
    .line 8
    if-ge p2, v1, :cond_0

    .line 9
    .line 10
    iget-object v1, p0, Lry0/i;->h:[Ljava/lang/Object;

    .line 11
    .line 12
    add-int/lit8 v2, p2, -0x1

    .line 13
    .line 14
    aget-object v2, v1, v2

    .line 15
    .line 16
    const-string v3, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>"

    .line 17
    .line 18
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    check-cast v2, [Ljava/lang/Object;

    .line 22
    .line 23
    invoke-static {p1, v0}, Lkp/t6;->c(II)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    aget-object v2, v2, v3

    .line 28
    .line 29
    aput-object v2, v1, p2

    .line 30
    .line 31
    add-int/lit8 v0, v0, -0x5

    .line 32
    .line 33
    add-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    return-void
.end method

.method public final c(I)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget v1, p0, Lp2/a;->e:I

    .line 3
    .line 4
    invoke-static {v1, v0}, Lkp/t6;->c(II)I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-ne v1, p1, :cond_0

    .line 9
    .line 10
    add-int/lit8 v0, v0, 0x5

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    if-lez v0, :cond_1

    .line 14
    .line 15
    iget p1, p0, Lry0/i;->g:I

    .line 16
    .line 17
    add-int/lit8 p1, p1, -0x1

    .line 18
    .line 19
    div-int/lit8 v0, v0, 0x5

    .line 20
    .line 21
    sub-int/2addr p1, v0

    .line 22
    iget v0, p0, Lp2/a;->e:I

    .line 23
    .line 24
    add-int/lit8 p1, p1, 0x1

    .line 25
    .line 26
    invoke-virtual {p0, v0, p1}, Lry0/i;->b(II)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lp2/a;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lry0/i;->a()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget v1, p0, Lp2/a;->e:I

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    add-int/2addr v1, v2

    .line 15
    iput v1, p0, Lp2/a;->e:I

    .line 16
    .line 17
    iget v3, p0, Lp2/a;->f:I

    .line 18
    .line 19
    if-ne v1, v3, :cond_0

    .line 20
    .line 21
    iput-boolean v2, p0, Lry0/i;->i:Z

    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_0
    const/4 v1, 0x0

    .line 25
    invoke-virtual {p0, v1}, Lry0/i;->c(I)V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public final previous()Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lp2/a;->hasPrevious()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget v0, p0, Lp2/a;->e:I

    .line 8
    .line 9
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    iput v0, p0, Lp2/a;->e:I

    .line 12
    .line 13
    iget-boolean v0, p0, Lry0/i;->i:Z

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lry0/i;->i:Z

    .line 19
    .line 20
    invoke-virtual {p0}, Lry0/i;->a()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    const/16 v0, 0x1f

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lry0/i;->c(I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lry0/i;->a()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0
.end method
