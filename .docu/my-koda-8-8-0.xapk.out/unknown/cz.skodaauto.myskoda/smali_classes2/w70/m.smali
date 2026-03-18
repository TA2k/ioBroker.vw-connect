.class public final Lw70/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbq0/o;


# direct methods
.method public constructor <init>(Lbq0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/m;->a:Lbq0/o;

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
    invoke-virtual {p0, p2}, Lw70/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lw70/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lw70/l;

    .line 7
    .line 8
    iget v1, v0, Lw70/l;->f:I

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
    iput v1, v0, Lw70/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw70/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lw70/l;-><init>(Lw70/m;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lw70/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lw70/l;->f:I

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
    iput v4, v0, Lw70/l;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lw70/m;->a:Lbq0/o;

    .line 61
    .line 62
    invoke-virtual {p0, v0}, Lbq0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v1, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    check-cast p1, Lyy0/i;

    .line 70
    .line 71
    iput v3, v0, Lw70/l;->f:I

    .line 72
    .line 73
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-ne p1, v1, :cond_5

    .line 78
    .line 79
    :goto_2
    return-object v1

    .line 80
    :cond_5
    :goto_3
    instance-of p0, p1, Lne0/e;

    .line 81
    .line 82
    const/4 v0, 0x0

    .line 83
    if-eqz p0, :cond_6

    .line 84
    .line 85
    check-cast p1, Lne0/e;

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_6
    move-object p1, v0

    .line 89
    :goto_4
    if-eqz p1, :cond_7

    .line 90
    .line 91
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Lcq0/m;

    .line 94
    .line 95
    if-eqz p0, :cond_7

    .line 96
    .line 97
    iget-object p0, p0, Lcq0/m;->a:Lcq0/e;

    .line 98
    .line 99
    if-eqz p0, :cond_7

    .line 100
    .line 101
    iget-object p0, p0, Lcq0/e;->d:Lqr0/d;

    .line 102
    .line 103
    if-eqz p0, :cond_7

    .line 104
    .line 105
    iget-wide p0, p0, Lqr0/d;->a:D

    .line 106
    .line 107
    const-wide v0, 0x408f400000000000L    # 1000.0

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    div-double/2addr p0, v0

    .line 113
    double-to-int p0, p0

    .line 114
    new-instance p1, Ljava/lang/Integer;

    .line 115
    .line 116
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 117
    .line 118
    .line 119
    return-object p1

    .line 120
    :cond_7
    return-object v0
.end method
