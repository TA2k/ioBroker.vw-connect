.class public final Lkc0/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/f;

.field public final b:Lkc0/g;


# direct methods
.method public constructor <init>(Lcu0/f;Lkc0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkc0/t;->a:Lcu0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lkc0/t;->b:Lkc0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lkc0/t;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lkc0/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkc0/s;

    .line 7
    .line 8
    iget v1, v0, Lkc0/s;->f:I

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
    iput v1, v0, Lkc0/s;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkc0/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkc0/s;-><init>(Lkc0/t;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkc0/s;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkc0/s;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v5, v0, Lkc0/s;->f:I

    .line 61
    .line 62
    iget-object p1, p0, Lkc0/t;->b:Lkc0/g;

    .line 63
    .line 64
    check-cast p1, Lic0/p;

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Lic0/p;->c(Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Lyy0/i;

    .line 74
    .line 75
    new-instance v2, Lhg/q;

    .line 76
    .line 77
    const/4 v5, 0x5

    .line 78
    invoke-direct {v2, p1, v5}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 79
    .line 80
    .line 81
    invoke-static {v2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    new-instance v2, Lgt0/c;

    .line 86
    .line 87
    const/16 v5, 0x17

    .line 88
    .line 89
    invoke-direct {v2, p0, v5}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    iput v4, v0, Lkc0/s;->f:I

    .line 93
    .line 94
    new-instance p0, Lwk0/o0;

    .line 95
    .line 96
    const/16 v4, 0x11

    .line 97
    .line 98
    invoke-direct {p0, v2, v4}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 99
    .line 100
    .line 101
    invoke-interface {p1, p0, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    move-object p0, v3

    .line 109
    :goto_2
    if-ne p0, v1, :cond_6

    .line 110
    .line 111
    :goto_3
    return-object v1

    .line 112
    :cond_6
    return-object v3
.end method
