.class public abstract Lhr/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Z

.field public e:I

.field public f:[Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    const-string v0, "initialCapacity"

    invoke-static {p1, v0}, Lhr/q;->c(ILjava/lang/String;)V

    .line 4
    new-array p1, p1, [Ljava/lang/Object;

    iput-object p1, p0, Lhr/b0;->f:[Ljava/lang/Object;

    const/4 p1, 0x0

    .line 5
    iput p1, p0, Lhr/b0;->e:I

    return-void
.end method

.method public constructor <init>([Ljo/d;ZI)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhr/b0;->f:[Ljava/lang/Object;

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    if-eqz p2, :cond_0

    const/4 v0, 0x1

    :cond_0
    iput-boolean v0, p0, Lhr/b0;->d:Z

    iput p3, p0, Lhr/b0;->e:I

    return-void
.end method

.method public static e()Lh6/i;
    .locals 2

    .line 1
    new-instance v0, Lh6/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lh6/i;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    iput-boolean v1, v0, Lh6/i;->c:Z

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iput v1, v0, Lh6/i;->b:I

    .line 11
    .line 12
    return-object v0
.end method

.method public static h(II)I
    .locals 1

    .line 1
    if-ltz p1, :cond_3

    .line 2
    .line 3
    if-gt p1, p0, :cond_0

    .line 4
    .line 5
    return p0

    .line 6
    :cond_0
    shr-int/lit8 v0, p0, 0x1

    .line 7
    .line 8
    add-int/2addr p0, v0

    .line 9
    add-int/lit8 p0, p0, 0x1

    .line 10
    .line 11
    if-ge p0, p1, :cond_1

    .line 12
    .line 13
    add-int/lit8 p1, p1, -0x1

    .line 14
    .line 15
    invoke-static {p1}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    shl-int/lit8 p0, p0, 0x1

    .line 20
    .line 21
    :cond_1
    if-gez p0, :cond_2

    .line 22
    .line 23
    const p0, 0x7fffffff

    .line 24
    .line 25
    .line 26
    :cond_2
    return p0

    .line 27
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string p1, "cannot store more than Integer.MAX_VALUE elements"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/Object;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    invoke-virtual {p0, v0}, Lhr/b0;->g(I)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 9
    .line 10
    iget v1, p0, Lhr/b0;->e:I

    .line 11
    .line 12
    add-int/lit8 v2, v1, 0x1

    .line 13
    .line 14
    iput v2, p0, Lhr/b0;->e:I

    .line 15
    .line 16
    aput-object p1, v0, v1

    .line 17
    .line 18
    return-void
.end method

.method public varargs b([Ljava/lang/Object;)V
    .locals 4

    .line 1
    array-length v0, p1

    .line 2
    invoke-static {v0, p1}, Lhr/q;->a(I[Ljava/lang/Object;)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lhr/b0;->g(I)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 9
    .line 10
    iget v2, p0, Lhr/b0;->e:I

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-static {p1, v3, v1, v2, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 14
    .line 15
    .line 16
    iget p1, p0, Lhr/b0;->e:I

    .line 17
    .line 18
    add-int/2addr p1, v0

    .line 19
    iput p1, p0, Lhr/b0;->e:I

    .line 20
    .line 21
    return-void
.end method

.method public abstract c(Ljava/lang/Object;)Lhr/b0;
.end method

.method public d(Ljava/lang/Iterable;)V
    .locals 2

    .line 1
    instance-of v0, p1, Ljava/util/Collection;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ljava/util/Collection;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-virtual {p0, v1}, Lhr/b0;->g(I)V

    .line 13
    .line 14
    .line 15
    instance-of v1, v0, Lhr/c0;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    check-cast v0, Lhr/c0;

    .line 20
    .line 21
    iget-object p1, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 22
    .line 23
    iget v1, p0, Lhr/b0;->e:I

    .line 24
    .line 25
    invoke-virtual {v0, v1, p1}, Lhr/c0;->e(I[Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iput p1, p0, Lhr/b0;->e:I

    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {p0, v0}, Lhr/b0;->c(Ljava/lang/Object;)Lhr/b0;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    return-void
.end method

.method public abstract f(Lko/c;Laq/k;)V
.end method

.method public g(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    iget v2, p0, Lhr/b0;->e:I

    .line 5
    .line 6
    add-int/2addr v2, p1

    .line 7
    invoke-static {v1, v2}, Lhr/b0;->h(II)I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    array-length v0, v0

    .line 12
    if-gt p1, v0, :cond_1

    .line 13
    .line 14
    iget-boolean v0, p0, Lhr/b0;->d:Z

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    return-void

    .line 20
    :cond_1
    :goto_0
    iget-object v0, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 21
    .line 22
    invoke-static {v0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 27
    .line 28
    const/4 p1, 0x0

    .line 29
    iput-boolean p1, p0, Lhr/b0;->d:Z

    .line 30
    .line 31
    return-void
.end method
