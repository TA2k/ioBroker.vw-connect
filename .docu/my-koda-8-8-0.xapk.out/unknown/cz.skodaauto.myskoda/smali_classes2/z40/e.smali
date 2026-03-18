.class public final Lz40/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lz40/f;

.field public final b:Lwj0/a0;

.field public final c:Lwj0/q;


# direct methods
.method public constructor <init>(Lz40/f;Lwj0/a0;Lwj0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz40/e;->a:Lz40/f;

    .line 5
    .line 6
    iput-object p2, p0, Lz40/e;->b:Lwj0/a0;

    .line 7
    .line 8
    iput-object p3, p0, Lz40/e;->c:Lwj0/q;

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
    invoke-virtual {p0, p2}, Lz40/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lz40/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lz40/d;

    .line 7
    .line 8
    iget v1, v0, Lz40/d;->f:I

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
    iput v1, v0, Lz40/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz40/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lz40/d;-><init>(Lz40/e;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lz40/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz40/d;->f:I

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
    iget-object p1, p0, Lz40/e;->a:Lz40/f;

    .line 52
    .line 53
    invoke-virtual {p1}, Lz40/f;->invoke()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    check-cast p1, Lyy0/i;

    .line 58
    .line 59
    iget-object v2, p0, Lz40/e;->c:Lwj0/q;

    .line 60
    .line 61
    invoke-virtual {v2}, Lwj0/q;->invoke()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Lyy0/i;

    .line 66
    .line 67
    new-instance v4, Lal0/y0;

    .line 68
    .line 69
    const/4 v5, 0x3

    .line 70
    const/16 v6, 0x1c

    .line 71
    .line 72
    const/4 v7, 0x0

    .line 73
    invoke-direct {v4, v5, v7, v6}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    new-instance v5, Lbn0/f;

    .line 77
    .line 78
    const/4 v6, 0x5

    .line 79
    invoke-direct {v5, p1, v2, v4, v6}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 80
    .line 81
    .line 82
    invoke-static {v5}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    new-instance v2, Ly20/n;

    .line 87
    .line 88
    const/4 v4, 0x5

    .line 89
    invoke-direct {v2, p0, v4}, Ly20/n;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    iput v3, v0, Lz40/d;->f:I

    .line 93
    .line 94
    invoke-interface {p1, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v1, :cond_3

    .line 99
    .line 100
    return-object v1

    .line 101
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0
.end method
