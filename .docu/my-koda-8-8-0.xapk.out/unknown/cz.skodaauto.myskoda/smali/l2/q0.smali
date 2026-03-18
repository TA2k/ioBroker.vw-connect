.class public final Ll2/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[I

.field public b:I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0xa

    .line 2
    new-array v0, v0, [I

    iput-object v0, p0, Ll2/q0;->a:[I

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-array p1, p1, [I

    iput-object p1, p0, Ll2/q0;->a:[I

    return-void
.end method


# virtual methods
.method public a(I)I
    .locals 1

    .line 1
    iget v0, p0, Ll2/q0;->b:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    if-ltz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ll2/q0;->a:[I

    .line 8
    .line 9
    aget p0, p0, v0

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    return p1
.end method

.method public b()I
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/q0;->a:[I

    .line 2
    .line 3
    iget v1, p0, Ll2/q0;->b:I

    .line 4
    .line 5
    add-int/lit8 v1, v1, -0x1

    .line 6
    .line 7
    iput v1, p0, Ll2/q0;->b:I

    .line 8
    .line 9
    aget p0, v0, v1

    .line 10
    .line 11
    return p0
.end method

.method public c(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/q0;->a:[I

    .line 2
    .line 3
    iget v1, p0, Ll2/q0;->b:I

    .line 4
    .line 5
    array-length v2, v0

    .line 6
    if-lt v1, v2, :cond_0

    .line 7
    .line 8
    array-length v1, v0

    .line 9
    mul-int/lit8 v1, v1, 0x2

    .line 10
    .line 11
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "copyOf(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Ll2/q0;->a:[I

    .line 21
    .line 22
    :cond_0
    iget v1, p0, Ll2/q0;->b:I

    .line 23
    .line 24
    add-int/lit8 v2, v1, 0x1

    .line 25
    .line 26
    iput v2, p0, Ll2/q0;->b:I

    .line 27
    .line 28
    aput p1, v0, v1

    .line 29
    .line 30
    return-void
.end method

.method public d(III)V
    .locals 4

    .line 1
    iget v0, p0, Ll2/q0;->b:I

    .line 2
    .line 3
    iget-object v1, p0, Ll2/q0;->a:[I

    .line 4
    .line 5
    add-int/lit8 v2, v0, 0x3

    .line 6
    .line 7
    array-length v3, v1

    .line 8
    if-lt v2, v3, :cond_0

    .line 9
    .line 10
    array-length v3, v1

    .line 11
    mul-int/lit8 v3, v3, 0x2

    .line 12
    .line 13
    invoke-static {v1, v3}, Ljava/util/Arrays;->copyOf([II)[I

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v3, "copyOf(...)"

    .line 18
    .line 19
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iput-object v1, p0, Ll2/q0;->a:[I

    .line 23
    .line 24
    :cond_0
    add-int/2addr p1, p3

    .line 25
    aput p1, v1, v0

    .line 26
    .line 27
    add-int/lit8 p1, v0, 0x1

    .line 28
    .line 29
    add-int/2addr p2, p3

    .line 30
    aput p2, v1, p1

    .line 31
    .line 32
    add-int/lit8 v0, v0, 0x2

    .line 33
    .line 34
    aput p3, v1, v0

    .line 35
    .line 36
    iput v2, p0, Ll2/q0;->b:I

    .line 37
    .line 38
    return-void
.end method

.method public e(IIII)V
    .locals 4

    .line 1
    iget v0, p0, Ll2/q0;->b:I

    .line 2
    .line 3
    iget-object v1, p0, Ll2/q0;->a:[I

    .line 4
    .line 5
    add-int/lit8 v2, v0, 0x4

    .line 6
    .line 7
    array-length v3, v1

    .line 8
    if-lt v2, v3, :cond_0

    .line 9
    .line 10
    array-length v3, v1

    .line 11
    mul-int/lit8 v3, v3, 0x2

    .line 12
    .line 13
    invoke-static {v1, v3}, Ljava/util/Arrays;->copyOf([II)[I

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v3, "copyOf(...)"

    .line 18
    .line 19
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iput-object v1, p0, Ll2/q0;->a:[I

    .line 23
    .line 24
    :cond_0
    aput p1, v1, v0

    .line 25
    .line 26
    add-int/lit8 p1, v0, 0x1

    .line 27
    .line 28
    aput p2, v1, p1

    .line 29
    .line 30
    add-int/lit8 p1, v0, 0x2

    .line 31
    .line 32
    aput p3, v1, p1

    .line 33
    .line 34
    add-int/lit8 v0, v0, 0x3

    .line 35
    .line 36
    aput p4, v1, v0

    .line 37
    .line 38
    iput v2, p0, Ll2/q0;->b:I

    .line 39
    .line 40
    return-void
.end method

.method public f(II)V
    .locals 5

    .line 1
    if-ge p1, p2, :cond_3

    .line 2
    .line 3
    add-int/lit8 v0, p1, -0x3

    .line 4
    .line 5
    move v1, p1

    .line 6
    :goto_0
    if-ge v1, p2, :cond_2

    .line 7
    .line 8
    iget-object v2, p0, Ll2/q0;->a:[I

    .line 9
    .line 10
    aget v3, v2, v1

    .line 11
    .line 12
    aget v4, v2, p2

    .line 13
    .line 14
    if-lt v3, v4, :cond_0

    .line 15
    .line 16
    if-ne v3, v4, :cond_1

    .line 17
    .line 18
    add-int/lit8 v3, v1, 0x1

    .line 19
    .line 20
    aget v3, v2, v3

    .line 21
    .line 22
    add-int/lit8 v4, p2, 0x1

    .line 23
    .line 24
    aget v2, v2, v4

    .line 25
    .line 26
    if-gt v3, v2, :cond_1

    .line 27
    .line 28
    :cond_0
    add-int/lit8 v0, v0, 0x3

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1}, Ll2/q0;->g(II)V

    .line 31
    .line 32
    .line 33
    :cond_1
    add-int/lit8 v1, v1, 0x3

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    add-int/lit8 v1, v0, 0x3

    .line 37
    .line 38
    invoke-virtual {p0, v1, p2}, Ll2/q0;->g(II)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, p1, v0}, Ll2/q0;->f(II)V

    .line 42
    .line 43
    .line 44
    add-int/lit8 v0, v0, 0x6

    .line 45
    .line 46
    invoke-virtual {p0, v0, p2}, Ll2/q0;->f(II)V

    .line 47
    .line 48
    .line 49
    :cond_3
    return-void
.end method

.method public g(II)V
    .locals 4

    .line 1
    iget-object p0, p0, Ll2/q0;->a:[I

    .line 2
    .line 3
    aget v0, p0, p1

    .line 4
    .line 5
    aget v1, p0, p2

    .line 6
    .line 7
    aput v1, p0, p1

    .line 8
    .line 9
    aput v0, p0, p2

    .line 10
    .line 11
    add-int/lit8 v0, p1, 0x1

    .line 12
    .line 13
    add-int/lit8 v1, p2, 0x1

    .line 14
    .line 15
    aget v2, p0, v0

    .line 16
    .line 17
    aget v3, p0, v1

    .line 18
    .line 19
    aput v3, p0, v0

    .line 20
    .line 21
    aput v2, p0, v1

    .line 22
    .line 23
    add-int/lit8 p1, p1, 0x2

    .line 24
    .line 25
    add-int/lit8 p2, p2, 0x2

    .line 26
    .line 27
    aget v0, p0, p1

    .line 28
    .line 29
    aget v1, p0, p2

    .line 30
    .line 31
    aput v1, p0, p1

    .line 32
    .line 33
    aput v0, p0, p2

    .line 34
    .line 35
    return-void
.end method
