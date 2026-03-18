.class public final Lky0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lky0/j;
.implements Lky0/d;


# instance fields
.field public final a:Lky0/j;

.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(Lky0/j;II)V
    .locals 1

    .line 1
    const-string v0, "sequence"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lky0/r;->a:Lky0/j;

    .line 10
    .line 11
    iput p2, p0, Lky0/r;->b:I

    .line 12
    .line 13
    iput p3, p0, Lky0/r;->c:I

    .line 14
    .line 15
    if-ltz p2, :cond_2

    .line 16
    .line 17
    if-ltz p3, :cond_1

    .line 18
    .line 19
    if-lt p3, p2, :cond_0

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    const-string p0, "endIndex should be not less than startIndex, but was "

    .line 23
    .line 24
    const-string p1, " < "

    .line 25
    .line 26
    invoke-static {p0, p1, p3, p2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p1

    .line 40
    :cond_1
    const-string p0, "endIndex should be non-negative, but is "

    .line 41
    .line 42
    invoke-static {p3, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p1

    .line 56
    :cond_2
    const-string p0, "startIndex should be non-negative, but is "

    .line 57
    .line 58
    invoke-static {p2, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p1
.end method


# virtual methods
.method public final a(I)Lky0/j;
    .locals 3

    .line 1
    iget v0, p0, Lky0/r;->c:I

    .line 2
    .line 3
    iget v1, p0, Lky0/r;->b:I

    .line 4
    .line 5
    sub-int v2, v0, v1

    .line 6
    .line 7
    if-lt p1, v2, :cond_0

    .line 8
    .line 9
    sget-object p0, Lky0/e;->a:Lky0/e;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v2, Lky0/r;

    .line 13
    .line 14
    iget-object p0, p0, Lky0/r;->a:Lky0/j;

    .line 15
    .line 16
    add-int/2addr v1, p1

    .line 17
    invoke-direct {v2, p0, v1, v0}, Lky0/r;-><init>(Lky0/j;II)V

    .line 18
    .line 19
    .line 20
    return-object v2
.end method

.method public final b(I)Lky0/j;
    .locals 2

    .line 1
    iget v0, p0, Lky0/r;->c:I

    .line 2
    .line 3
    iget v1, p0, Lky0/r;->b:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    if-lt p1, v0, :cond_0

    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v0, Lky0/r;

    .line 10
    .line 11
    iget-object p0, p0, Lky0/r;->a:Lky0/j;

    .line 12
    .line 13
    add-int/2addr p1, v1

    .line 14
    invoke-direct {v0, p0, v1, p1}, Lky0/r;-><init>(Lky0/j;II)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Landroidx/collection/o0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Landroidx/collection/o0;-><init>(Lky0/r;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
