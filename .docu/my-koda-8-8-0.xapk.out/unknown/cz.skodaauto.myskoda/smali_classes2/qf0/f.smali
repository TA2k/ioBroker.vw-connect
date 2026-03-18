.class public final Lqf0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lqf0/a;

.field public final b:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lqf0/a;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqf0/f;->a:Lqf0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lqf0/f;->b:Ljava/util/ArrayList;

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
    invoke-virtual {p0, p2}, Lqf0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lqf0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lqf0/e;

    .line 7
    .line 8
    iget v1, v0, Lqf0/e;->h:I

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
    iput v1, v0, Lqf0/e;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqf0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lqf0/e;-><init>(Lqf0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lqf0/e;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqf0/e;->h:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v5, :cond_2

    .line 39
    .line 40
    if-ne v2, v4, :cond_1

    .line 41
    .line 42
    iget p0, v0, Lqf0/e;->e:I

    .line 43
    .line 44
    iget-object v2, v0, Lqf0/e;->d:Ljava/util/Iterator;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move v6, p0

    .line 50
    goto :goto_3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iput v5, v0, Lqf0/e;->h:I

    .line 67
    .line 68
    iget-object p1, p0, Lqf0/f;->a:Lqf0/a;

    .line 69
    .line 70
    check-cast p1, Lof0/b;

    .line 71
    .line 72
    iget-object p1, p1, Lof0/b;->a:Lve0/u;

    .line 73
    .line 74
    const-string v2, "PREF_DEMO_ENABLED"

    .line 75
    .line 76
    invoke-virtual {p1, v6, v2, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    if-ne p1, v1, :cond_4

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_4
    move-object p1, v3

    .line 84
    :goto_1
    if-ne p1, v1, :cond_5

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_5
    :goto_2
    new-instance p1, Lqf0/d;

    .line 88
    .line 89
    const/4 v2, 0x0

    .line 90
    invoke-direct {p1, v2}, Lqf0/d;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 94
    .line 95
    .line 96
    new-instance p1, Lqf0/d;

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    invoke-direct {p1, v2}, Lqf0/d;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {p0, p1}, Llp/nd;->n(Ljava/lang/Object;Lay0/a;)V

    .line 103
    .line 104
    .line 105
    iget-object p0, p0, Lqf0/f;->b:Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    move-object v2, p0

    .line 112
    :cond_6
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-eqz p0, :cond_7

    .line 117
    .line 118
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Lme0/a;

    .line 123
    .line 124
    iput-object v2, v0, Lqf0/e;->d:Ljava/util/Iterator;

    .line 125
    .line 126
    iput v6, v0, Lqf0/e;->e:I

    .line 127
    .line 128
    iput v4, v0, Lqf0/e;->h:I

    .line 129
    .line 130
    invoke-interface {p0, v0}, Lme0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v1, :cond_6

    .line 135
    .line 136
    :goto_4
    return-object v1

    .line 137
    :cond_7
    return-object v3
.end method
