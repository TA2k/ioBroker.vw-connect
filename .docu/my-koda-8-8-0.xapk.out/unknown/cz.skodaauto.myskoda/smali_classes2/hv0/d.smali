.class public final Lhv0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwj0/k;

.field public final b:Lz40/g;

.field public final c:Lwj0/b0;


# direct methods
.method public constructor <init>(Lwj0/k;Lz40/g;Lwj0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/d;->a:Lwj0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/d;->b:Lz40/g;

    .line 7
    .line 8
    iput-object p3, p0, Lhv0/d;->c:Lwj0/b0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lhv0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lhv0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhv0/c;

    .line 7
    .line 8
    iget v1, v0, Lhv0/c;->f:I

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
    iput v1, v0, Lhv0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhv0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhv0/c;-><init>(Lhv0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhv0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhv0/c;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lhv0/d;->a:Lwj0/k;

    .line 54
    .line 55
    invoke-virtual {p1}, Lwj0/k;->invoke()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Lyy0/i;

    .line 60
    .line 61
    iget-object v2, p0, Lhv0/d;->b:Lz40/g;

    .line 62
    .line 63
    invoke-virtual {v2}, Lz40/g;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    check-cast v2, Lyy0/i;

    .line 68
    .line 69
    new-instance v5, Lhk0/a;

    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    invoke-direct {v5, p0, v6, v4}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 73
    .line 74
    .line 75
    iput v4, v0, Lhv0/c;->f:I

    .line 76
    .line 77
    const/4 p0, 0x2

    .line 78
    new-array p0, p0, [Lyy0/i;

    .line 79
    .line 80
    const/4 v7, 0x0

    .line 81
    aput-object p1, p0, v7

    .line 82
    .line 83
    aput-object v2, p0, v4

    .line 84
    .line 85
    new-instance p1, Lyy0/g1;

    .line 86
    .line 87
    invoke-direct {p1, v5, v6}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 88
    .line 89
    .line 90
    sget-object v2, Lyy0/h1;->d:Lyy0/h1;

    .line 91
    .line 92
    sget-object v4, Lzy0/q;->d:Lzy0/q;

    .line 93
    .line 94
    invoke-static {v2, p1, v0, v4, p0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 99
    .line 100
    if-ne p0, p1, :cond_3

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    move-object p0, v3

    .line 104
    :goto_1
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    if-ne p0, p1, :cond_4

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    move-object p0, v3

    .line 110
    :goto_2
    if-ne p0, v1, :cond_5

    .line 111
    .line 112
    return-object v1

    .line 113
    :cond_5
    :goto_3
    return-object v3
.end method
