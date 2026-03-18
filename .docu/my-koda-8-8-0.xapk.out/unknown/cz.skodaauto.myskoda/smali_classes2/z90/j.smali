.class public final Lz90/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lz90/p;


# direct methods
.method public constructor <init>(Lz90/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/j;->a:Lz90/p;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lz90/j;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lz90/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lz90/i;

    .line 7
    .line 8
    iget v1, v0, Lz90/i;->f:I

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
    iput v1, v0, Lz90/i;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz90/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lz90/i;-><init>(Lz90/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lz90/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz90/i;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lz90/j;->a:Lz90/p;

    .line 52
    .line 53
    check-cast p0, Lx90/a;

    .line 54
    .line 55
    iget-object p0, p0, Lx90/a;->h:Lyy0/l1;

    .line 56
    .line 57
    invoke-static {p0}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    iput v3, v0, Lz90/i;->f:I

    .line 62
    .line 63
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    if-ne p1, v1, :cond_3

    .line 68
    .line 69
    return-object v1

    .line 70
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 71
    .line 72
    instance-of p0, p1, Lne0/e;

    .line 73
    .line 74
    if-eqz p0, :cond_4

    .line 75
    .line 76
    check-cast p1, Lne0/e;

    .line 77
    .line 78
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Ljava/util/List;

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_4
    instance-of p0, p1, Lne0/c;

    .line 84
    .line 85
    if-eqz p0, :cond_5

    .line 86
    .line 87
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_5
    new-instance p0, La8/r0;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 93
    .line 94
    .line 95
    throw p0
.end method
