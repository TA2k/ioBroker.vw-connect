.class public final Lcs0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Las0/g;

.field public final b:Las0/e;


# direct methods
.method public constructor <init>(Las0/g;Las0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/h;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/h;->b:Las0/e;

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
    invoke-virtual {p0, p2}, Lcs0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lcs0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcs0/g;

    .line 7
    .line 8
    iget v1, v0, Lcs0/g;->f:I

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
    iput v1, v0, Lcs0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcs0/g;-><init>(Lcs0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcs0/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/g;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lcs0/g;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lcs0/h;->b:Las0/e;

    .line 61
    .line 62
    iget-object v2, p1, Las0/e;->a:Lxl0/f;

    .line 63
    .line 64
    new-instance v4, La90/s;

    .line 65
    .line 66
    const/4 v5, 0x2

    .line 67
    const/4 v6, 0x0

    .line 68
    invoke-direct {v4, p1, v6, v5}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    new-instance p1, La00/a;

    .line 72
    .line 73
    const/16 v5, 0x17

    .line 74
    .line 75
    invoke-direct {p1, v5}, La00/a;-><init>(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2, v4, p1, v6, v0}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v1, :cond_4

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_4
    :goto_1
    check-cast p1, Lne0/t;

    .line 86
    .line 87
    instance-of v2, p1, Lne0/e;

    .line 88
    .line 89
    if-eqz v2, :cond_5

    .line 90
    .line 91
    check-cast p1, Lne0/e;

    .line 92
    .line 93
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p1, Lds0/e;

    .line 96
    .line 97
    iput v3, v0, Lcs0/g;->f:I

    .line 98
    .line 99
    iget-object p0, p0, Lcs0/h;->a:Las0/g;

    .line 100
    .line 101
    invoke-virtual {p0, p1, v0}, Las0/g;->b(Lds0/e;Lrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_5

    .line 106
    .line 107
    :goto_2
    return-object v1

    .line 108
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0
.end method
