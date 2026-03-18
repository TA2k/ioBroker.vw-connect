.class public final Lgb0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcu0/d;

.field public final b:Lrs0/b;

.field public final c:Lgb0/c0;


# direct methods
.method public constructor <init>(Lcu0/d;Lrs0/b;Lgb0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/u;->a:Lcu0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/u;->b:Lrs0/b;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/u;->c:Lgb0/c0;

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
    invoke-virtual {p0, p2}, Lgb0/u;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lgb0/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgb0/s;

    .line 7
    .line 8
    iget v1, v0, Lgb0/s;->f:I

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
    iput v1, v0, Lgb0/s;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgb0/s;-><init>(Lgb0/u;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgb0/s;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/s;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v7, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v7, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-object v3

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
    iget-object p1, p0, Lgb0/u;->a:Lcu0/d;

    .line 54
    .line 55
    iget-object p1, p1, Lcu0/d;->a:Lcu0/h;

    .line 56
    .line 57
    move-object v5, p1

    .line 58
    check-cast v5, Lau0/g;

    .line 59
    .line 60
    iget-object p1, v5, Lau0/g;->c:Lyy0/i1;

    .line 61
    .line 62
    new-instance v4, Lau0/b;

    .line 63
    .line 64
    const/4 v8, 0x0

    .line 65
    const/4 v9, 0x0

    .line 66
    const-string v6, "vehicle"

    .line 67
    .line 68
    invoke-direct/range {v4 .. v9}, Lau0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    new-instance v2, Lne0/n;

    .line 72
    .line 73
    invoke-direct {v2, v4, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 74
    .line 75
    .line 76
    new-instance p1, Lac/l;

    .line 77
    .line 78
    const/4 v4, 0x3

    .line 79
    invoke-direct {p1, v4, v2, v6}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    new-instance v2, Lac/l;

    .line 83
    .line 84
    const/4 v4, 0x4

    .line 85
    invoke-direct {v2, v4, p1, v5}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    invoke-static {v2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    new-instance v2, Lac0/e;

    .line 93
    .line 94
    const/16 v4, 0x1c

    .line 95
    .line 96
    invoke-direct {v2, p0, v4}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    iput v7, v0, Lgb0/s;->f:I

    .line 100
    .line 101
    new-instance p0, Lcs0/s;

    .line 102
    .line 103
    const/16 v4, 0x16

    .line 104
    .line 105
    invoke-direct {p0, v2, v4}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 106
    .line 107
    .line 108
    new-instance v2, Lcs0/s;

    .line 109
    .line 110
    const/16 v4, 0x17

    .line 111
    .line 112
    invoke-direct {v2, p0, v4}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 113
    .line 114
    .line 115
    invoke-interface {p1, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v1, :cond_3

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_3
    move-object p0, v3

    .line 123
    :goto_1
    if-ne p0, v1, :cond_4

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_4
    move-object p0, v3

    .line 127
    :goto_2
    if-ne p0, v1, :cond_5

    .line 128
    .line 129
    return-object v1

    .line 130
    :cond_5
    return-object v3
.end method
