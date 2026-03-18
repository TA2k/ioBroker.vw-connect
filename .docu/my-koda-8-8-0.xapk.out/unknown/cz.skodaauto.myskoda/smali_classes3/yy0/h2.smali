.class public final Lyy0/h2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/n1;


# instance fields
.field public final d:Lyy0/n1;

.field public final e:Lrx0/i;


# direct methods
.method public constructor <init>(Lyy0/n1;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/h2;->d:Lyy0/n1;

    .line 5
    .line 6
    check-cast p2, Lrx0/i;

    .line 7
    .line 8
    iput-object p2, p0, Lyy0/h2;->e:Lrx0/i;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final c()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lyy0/h2;->d:Lyy0/n1;

    .line 2
    .line 3
    invoke-interface {p0}, Lyy0/n1;->c()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lyy0/g2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/g2;

    .line 7
    .line 8
    iget v1, v0, Lyy0/g2;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lyy0/g2;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/g2;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lyy0/g2;-><init>(Lyy0/h2;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/g2;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/g2;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-eq v2, v3, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p2, Lyy0/f2;

    .line 52
    .line 53
    iget-object v2, p0, Lyy0/h2;->e:Lrx0/i;

    .line 54
    .line 55
    invoke-direct {p2, p1, v2}, Lyy0/f2;-><init>(Lyy0/j;Lay0/n;)V

    .line 56
    .line 57
    .line 58
    iput v3, v0, Lyy0/g2;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lyy0/h2;->d:Lyy0/n1;

    .line 61
    .line 62
    invoke-interface {p0, p2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    if-ne p0, v1, :cond_3

    .line 67
    .line 68
    return-object v1

    .line 69
    :cond_3
    :goto_1
    new-instance p0, La8/r0;

    .line 70
    .line 71
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw p0
.end method
