.class public final Luk0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/u;

.field public final b:Lal0/j1;


# direct methods
.method public constructor <init>(Lal0/u;Lal0/j1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luk0/t;->a:Lal0/u;

    .line 5
    .line 6
    iput-object p2, p0, Luk0/t;->b:Lal0/j1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lxj0/f;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Luk0/t;->b(Lxj0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lxj0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Luk0/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Luk0/s;

    .line 7
    .line 8
    iget v1, v0, Luk0/s;->f:I

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
    iput v1, v0, Luk0/s;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luk0/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Luk0/s;-><init>(Luk0/t;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Luk0/s;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luk0/s;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p2, Lal0/s;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-direct {p2, p1, v2, v3}, Lal0/s;-><init>(Lxj0/f;Ljava/util/List;Z)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p0, Luk0/t;->a:Lal0/u;

    .line 58
    .line 59
    invoke-virtual {p1, p2}, Lal0/u;->a(Lal0/s;)Lzy0/j;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    new-instance p2, Ls10/a0;

    .line 64
    .line 65
    const/16 v4, 0xc

    .line 66
    .line 67
    invoke-direct {p2, p0, v2, v4}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 68
    .line 69
    .line 70
    new-instance p0, Lne0/n;

    .line 71
    .line 72
    const/4 v4, 0x5

    .line 73
    invoke-direct {p0, p1, p2, v4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 74
    .line 75
    .line 76
    new-instance p1, Lg1/d2;

    .line 77
    .line 78
    const/4 p2, 0x2

    .line 79
    const/4 v4, 0x4

    .line 80
    invoke-direct {p1, p2, v2, v4}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 81
    .line 82
    .line 83
    iput v3, v0, Luk0/s;->f:I

    .line 84
    .line 85
    invoke-static {p1, v0, p0}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v1, :cond_3

    .line 90
    .line 91
    return-object v1

    .line 92
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0
.end method
