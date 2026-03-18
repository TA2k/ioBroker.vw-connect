.class public final Lmx0/b0;
.super Lmx0/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/RandomAccess;


# instance fields
.field public final d:[Ljava/lang/Object;

.field public final e:I

.field public f:I

.field public g:I


# direct methods
.method public constructor <init>([Ljava/lang/Object;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmx0/b0;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    if-ltz p2, :cond_1

    .line 7
    .line 8
    array-length v0, p1

    .line 9
    if-gt p2, v0, :cond_0

    .line 10
    .line 11
    array-length p1, p1

    .line 12
    iput p1, p0, Lmx0/b0;->e:I

    .line 13
    .line 14
    iput p2, p0, Lmx0/b0;->g:I

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    const-string p0, "ring buffer filled size: "

    .line 18
    .line 19
    const-string v0, " cannot be larger than the buffer size: "

    .line 20
    .line 21
    invoke-static {p0, p2, v0}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    array-length p1, p1

    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p1

    .line 43
    :cond_1
    const-string p0, "ring buffer filled size should not be negative but it is "

    .line 44
    .line 45
    invoke-static {p2, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p1
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lmx0/b0;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public final e(I)V
    .locals 5

    .line 1
    if-ltz p1, :cond_3

    .line 2
    .line 3
    iget v0, p0, Lmx0/b0;->g:I

    .line 4
    .line 5
    if-gt p1, v0, :cond_2

    .line 6
    .line 7
    if-lez p1, :cond_1

    .line 8
    .line 9
    iget v0, p0, Lmx0/b0;->f:I

    .line 10
    .line 11
    add-int v1, v0, p1

    .line 12
    .line 13
    iget v2, p0, Lmx0/b0;->e:I

    .line 14
    .line 15
    rem-int/2addr v1, v2

    .line 16
    const/4 v3, 0x0

    .line 17
    iget-object v4, p0, Lmx0/b0;->d:[Ljava/lang/Object;

    .line 18
    .line 19
    if-le v0, v1, :cond_0

    .line 20
    .line 21
    invoke-static {v4, v0, v2, v3}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    invoke-static {v4, v0, v1, v3}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-static {v4, v0, v1, v3}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iput v1, p0, Lmx0/b0;->f:I

    .line 33
    .line 34
    iget v0, p0, Lmx0/b0;->g:I

    .line 35
    .line 36
    sub-int/2addr v0, p1

    .line 37
    iput v0, p0, Lmx0/b0;->g:I

    .line 38
    .line 39
    :cond_1
    return-void

    .line 40
    :cond_2
    const-string v0, "n shouldn\'t be greater than the buffer size: n = "

    .line 41
    .line 42
    const-string v1, ", size = "

    .line 43
    .line 44
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget p0, p0, Lmx0/b0;->g:I

    .line 49
    .line 50
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p1

    .line 67
    :cond_3
    const-string p0, "n shouldn\'t be negative but it is "

    .line 68
    .line 69
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 74
    .line 75
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lmx0/b0;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    if-ge p1, v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Lmx0/b0;->f:I

    .line 10
    .line 11
    add-int/2addr v0, p1

    .line 12
    iget p1, p0, Lmx0/b0;->e:I

    .line 13
    .line 14
    rem-int/2addr v0, p1

    .line 15
    iget-object p0, p0, Lmx0/b0;->d:[Ljava/lang/Object;

    .line 16
    .line 17
    aget-object p0, p0, v0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 21
    .line 22
    const-string v1, "index: "

    .line 23
    .line 24
    const-string v2, ", size: "

    .line 25
    .line 26
    invoke-static {v1, v2, p1, v0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lmx0/a0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lmx0/a0;-><init>(Lmx0/b0;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lmx0/b0;->c()I

    move-result v0

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p0, v0}, Lmx0/b0;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 6

    const-string v0, "array"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    array-length v0, p1

    .line 4
    iget v1, p0, Lmx0/b0;->g:I

    if-ge v0, v1, :cond_0

    .line 5
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    const-string v0, "copyOf(...)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    :cond_0
    iget v0, p0, Lmx0/b0;->g:I

    .line 7
    iget v1, p0, Lmx0/b0;->f:I

    const/4 v2, 0x0

    move v3, v2

    .line 8
    :goto_0
    iget-object v4, p0, Lmx0/b0;->d:[Ljava/lang/Object;

    if-ge v3, v0, :cond_1

    iget v5, p0, Lmx0/b0;->e:I

    if-ge v1, v5, :cond_1

    .line 9
    aget-object v4, v4, v1

    aput-object v4, p1, v3

    add-int/lit8 v3, v3, 0x1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    if-ge v3, v0, :cond_2

    .line 10
    aget-object p0, v4, v2

    aput-object p0, p1, v3

    add-int/lit8 v3, v3, 0x1

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    .line 11
    :cond_2
    array-length p0, p1

    if-ge v0, p0, :cond_3

    const/4 p0, 0x0

    .line 12
    aput-object p0, p1, v0

    :cond_3
    return-object p1
.end method
