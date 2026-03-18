.class public final Lgb0/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrs0/f;

.field public final b:Lif0/f0;

.field public final c:Len0/s;

.field public final d:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lrs0/f;Lif0/f0;Len0/s;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/c0;->a:Lrs0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/c0;->b:Lif0/f0;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/c0;->c:Len0/s;

    .line 9
    .line 10
    iput-object p4, p0, Lgb0/c0;->d:Ljava/util/ArrayList;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/d0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lgb0/c0;->b(Lss0/d0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lss0/d0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lgb0/b0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lgb0/b0;

    .line 7
    .line 8
    iget v1, v0, Lgb0/b0;->h:I

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
    iput v1, v0, Lgb0/b0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/b0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lgb0/b0;-><init>(Lgb0/c0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lgb0/b0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/b0;->h:I

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
    iget p0, v0, Lgb0/b0;->e:I

    .line 40
    .line 41
    iget-object p1, v0, Lgb0/b0;->d:Ljava/util/Iterator;

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, v0, Lgb0/b0;->h:I

    .line 63
    .line 64
    iget-object p2, p0, Lgb0/c0;->a:Lrs0/f;

    .line 65
    .line 66
    check-cast p2, Lps0/f;

    .line 67
    .line 68
    invoke-virtual {p2, p1, v0}, Lps0/f;->c(Lss0/d0;Lrx0/c;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-ne p1, v1, :cond_4

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    :goto_1
    iget-object p1, p0, Lgb0/c0;->b:Lif0/f0;

    .line 76
    .line 77
    iget-object p1, p1, Lif0/f0;->h:Lwe0/a;

    .line 78
    .line 79
    check-cast p1, Lwe0/c;

    .line 80
    .line 81
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, Lgb0/c0;->c:Len0/s;

    .line 85
    .line 86
    iget-object p1, p1, Len0/s;->f:Lwe0/a;

    .line 87
    .line 88
    check-cast p1, Lwe0/c;

    .line 89
    .line 90
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 91
    .line 92
    .line 93
    new-instance p1, Ld2/g;

    .line 94
    .line 95
    const/16 p2, 0x14

    .line 96
    .line 97
    invoke-direct {p1, p0, p2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    invoke-static {p0, p1}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Lgb0/c0;->d:Ljava/util/ArrayList;

    .line 104
    .line 105
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    const/4 p1, 0x0

    .line 110
    move v5, p1

    .line 111
    move-object p1, p0

    .line 112
    move p0, v5

    .line 113
    :cond_5
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result p2

    .line 117
    if-eqz p2, :cond_6

    .line 118
    .line 119
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    check-cast p2, Lme0/b;

    .line 124
    .line 125
    iput-object p1, v0, Lgb0/b0;->d:Ljava/util/Iterator;

    .line 126
    .line 127
    iput p0, v0, Lgb0/b0;->e:I

    .line 128
    .line 129
    iput v3, v0, Lgb0/b0;->h:I

    .line 130
    .line 131
    invoke-interface {p2, v0}, Lme0/b;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    if-ne p2, v1, :cond_5

    .line 136
    .line 137
    :goto_3
    return-object v1

    .line 138
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    return-object p0
.end method
