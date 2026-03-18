.class public final Lry0/f;
.super Lp2/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:[Ljava/lang/Object;

.field public final h:Lry0/i;


# direct methods
.method public constructor <init>(III[Ljava/lang/Object;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    const-string v0, "root"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "tail"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    invoke-direct {p0, p1, p2, v0}, Lp2/a;-><init>(III)V

    .line 13
    .line 14
    .line 15
    iput-object p5, p0, Lry0/f;->g:[Ljava/lang/Object;

    .line 16
    .line 17
    add-int/lit8 p2, p2, -0x1

    .line 18
    .line 19
    and-int/lit8 p2, p2, -0x20

    .line 20
    .line 21
    if-le p1, p2, :cond_0

    .line 22
    .line 23
    move p1, p2

    .line 24
    :cond_0
    new-instance p5, Lry0/i;

    .line 25
    .line 26
    invoke-direct {p5, p4, p1, p2, p3}, Lry0/i;-><init>([Ljava/lang/Object;III)V

    .line 27
    .line 28
    .line 29
    iput-object p5, p0, Lry0/f;->h:Lry0/i;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final next()Ljava/lang/Object;
    .locals 3

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
    iget-object v0, p0, Lry0/f;->h:Lry0/i;

    .line 8
    .line 9
    invoke-virtual {v0}, Lp2/a;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget v1, p0, Lp2/a;->e:I

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    iput v1, p0, Lp2/a;->e:I

    .line 20
    .line 21
    invoke-virtual {v0}, Lry0/i;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    iget v1, p0, Lp2/a;->e:I

    .line 27
    .line 28
    add-int/lit8 v2, v1, 0x1

    .line 29
    .line 30
    iput v2, p0, Lp2/a;->e:I

    .line 31
    .line 32
    iget v0, v0, Lp2/a;->f:I

    .line 33
    .line 34
    sub-int/2addr v1, v0

    .line 35
    iget-object p0, p0, Lry0/f;->g:[Ljava/lang/Object;

    .line 36
    .line 37
    aget-object p0, p0, v1

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 41
    .line 42
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method public final previous()Ljava/lang/Object;
    .locals 3

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
    iget-object v1, p0, Lry0/f;->h:Lry0/i;

    .line 10
    .line 11
    iget v2, v1, Lp2/a;->f:I

    .line 12
    .line 13
    if-le v0, v2, :cond_0

    .line 14
    .line 15
    add-int/lit8 v0, v0, -0x1

    .line 16
    .line 17
    iput v0, p0, Lp2/a;->e:I

    .line 18
    .line 19
    sub-int/2addr v0, v2

    .line 20
    iget-object p0, p0, Lry0/f;->g:[Ljava/lang/Object;

    .line 21
    .line 22
    aget-object p0, p0, v0

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 26
    .line 27
    iput v0, p0, Lp2/a;->e:I

    .line 28
    .line 29
    invoke-virtual {v1}, Lry0/i;->previous()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0
.end method
