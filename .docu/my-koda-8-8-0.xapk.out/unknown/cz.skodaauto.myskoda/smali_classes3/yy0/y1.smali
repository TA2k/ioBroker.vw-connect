.class public final Lyy0/y1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:I

.field public final synthetic g:Lyy0/z1;


# direct methods
.method public constructor <init>(Lyy0/z1;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyy0/y1;->g:Lyy0/z1;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    new-instance v0, Lyy0/y1;

    .line 12
    .line 13
    iget-object p0, p0, Lyy0/y1;->g:Lyy0/z1;

    .line 14
    .line 15
    invoke-direct {v0, p0, p3}, Lyy0/y1;-><init>(Lyy0/z1;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lyy0/y1;->e:Lyy0/j;

    .line 19
    .line 20
    iput p2, v0, Lyy0/y1;->f:I

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lyy0/y1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lyy0/y1;->d:I

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const/4 v3, 0x4

    .line 7
    const/4 v4, 0x3

    .line 8
    const/4 v5, 0x2

    .line 9
    const/4 v6, 0x1

    .line 10
    if-eqz v1, :cond_5

    .line 11
    .line 12
    if-eq v1, v6, :cond_4

    .line 13
    .line 14
    if-eq v1, v5, :cond_3

    .line 15
    .line 16
    if-eq v1, v4, :cond_2

    .line 17
    .line 18
    if-eq v1, v3, :cond_1

    .line 19
    .line 20
    if-ne v1, v2, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    iget-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 32
    .line 33
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_3

    .line 37
    :cond_2
    iget-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_3
    iget-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_4
    :goto_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_5

    .line 53
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 57
    .line 58
    iget p1, p0, Lyy0/y1;->f:I

    .line 59
    .line 60
    if-lez p1, :cond_6

    .line 61
    .line 62
    sget-object p1, Lyy0/s1;->d:Lyy0/s1;

    .line 63
    .line 64
    iput v6, p0, Lyy0/y1;->d:I

    .line 65
    .line 66
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-ne p0, v0, :cond_a

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_6
    iget-object p1, p0, Lyy0/y1;->g:Lyy0/z1;

    .line 74
    .line 75
    iget-wide v6, p1, Lyy0/z1;->a:J

    .line 76
    .line 77
    iput-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 78
    .line 79
    iput v5, p0, Lyy0/y1;->d:I

    .line 80
    .line 81
    invoke-static {v6, v7, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-ne p1, v0, :cond_7

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_7
    :goto_1
    sget-object p1, Lyy0/s1;->e:Lyy0/s1;

    .line 89
    .line 90
    iput-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 91
    .line 92
    iput v4, p0, Lyy0/y1;->d:I

    .line 93
    .line 94
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-ne p1, v0, :cond_8

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_8
    :goto_2
    iput-object v1, p0, Lyy0/y1;->e:Lyy0/j;

    .line 102
    .line 103
    iput v3, p0, Lyy0/y1;->d:I

    .line 104
    .line 105
    const-wide v3, 0x7fffffffffffffffL

    .line 106
    .line 107
    .line 108
    .line 109
    .line 110
    invoke-static {v3, v4, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    if-ne p1, v0, :cond_9

    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_9
    :goto_3
    sget-object p1, Lyy0/s1;->f:Lyy0/s1;

    .line 118
    .line 119
    const/4 v3, 0x0

    .line 120
    iput-object v3, p0, Lyy0/y1;->e:Lyy0/j;

    .line 121
    .line 122
    iput v2, p0, Lyy0/y1;->d:I

    .line 123
    .line 124
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    if-ne p0, v0, :cond_a

    .line 129
    .line 130
    :goto_4
    return-object v0

    .line 131
    :cond_a
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0
.end method
