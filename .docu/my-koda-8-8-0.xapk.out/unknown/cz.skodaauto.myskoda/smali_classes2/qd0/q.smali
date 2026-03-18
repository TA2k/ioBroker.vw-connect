.class public final Lqd0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lqd0/z;


# direct methods
.method public constructor <init>(Lqd0/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/q;->a:Lqd0/z;

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
    invoke-virtual {p0, p2}, Lqd0/q;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lqd0/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lqd0/p;

    .line 7
    .line 8
    iget v1, v0, Lqd0/p;->f:I

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
    iput v1, v0, Lqd0/p;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqd0/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lqd0/p;-><init>(Lqd0/q;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lqd0/p;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqd0/p;->f:I

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
    iget-object p0, p0, Lqd0/q;->a:Lqd0/z;

    .line 52
    .line 53
    check-cast p0, Lod0/v;

    .line 54
    .line 55
    iget-object p0, p0, Lod0/v;->c:Lyy0/l1;

    .line 56
    .line 57
    iput v3, v0, Lqd0/p;->f:I

    .line 58
    .line 59
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    instance-of p0, p1, Lne0/e;

    .line 67
    .line 68
    const/4 v0, 0x0

    .line 69
    if-eqz p0, :cond_4

    .line 70
    .line 71
    check-cast p1, Lne0/e;

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    move-object p1, v0

    .line 75
    :goto_2
    if-eqz p1, :cond_8

    .line 76
    .line 77
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Ljava/util/List;

    .line 80
    .line 81
    if-eqz p0, :cond_8

    .line 82
    .line 83
    check-cast p0, Ljava/lang/Iterable;

    .line 84
    .line 85
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    :cond_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    if-eqz p1, :cond_7

    .line 94
    .line 95
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    move-object v1, p1

    .line 100
    check-cast v1, Lrd0/d;

    .line 101
    .line 102
    const-string v2, "<this>"

    .line 103
    .line 104
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, v1, Lrd0/d;->c:Lrd0/f;

    .line 108
    .line 109
    sget-object v2, Lrd0/f;->f:Lrd0/f;

    .line 110
    .line 111
    if-eq v1, v2, :cond_6

    .line 112
    .line 113
    sget-object v2, Lrd0/f;->i:Lrd0/f;

    .line 114
    .line 115
    if-ne v1, v2, :cond_5

    .line 116
    .line 117
    :cond_6
    move-object v0, p1

    .line 118
    :cond_7
    check-cast v0, Lrd0/d;

    .line 119
    .line 120
    :cond_8
    return-object v0
.end method
