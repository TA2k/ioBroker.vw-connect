.class public final Lc1/y0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lc1/c1;

.field public final synthetic i:Lc1/w1;

.field public final synthetic j:F


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc1/y0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lc1/y0;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lc1/y0;->h:Lc1/c1;

    .line 6
    .line 7
    iput-object p4, p0, Lc1/y0;->i:Lc1/w1;

    .line 8
    .line 9
    iput p5, p0, Lc1/y0;->j:F

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lc1/y0;

    .line 2
    .line 3
    iget-object v4, p0, Lc1/y0;->i:Lc1/w1;

    .line 4
    .line 5
    iget v5, p0, Lc1/y0;->j:F

    .line 6
    .line 7
    iget-object v1, p0, Lc1/y0;->f:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v2, p0, Lc1/y0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v3, p0, Lc1/y0;->h:Lc1/c1;

    .line 12
    .line 13
    move-object v6, p2

    .line 14
    invoke-direct/range {v0 .. v6}, Lc1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, Lc1/y0;->e:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lc1/y0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lc1/y0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lc1/y0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lc1/y0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    iget-object v4, p0, Lc1/y0;->h:Lc1/c1;

    .line 9
    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    if-ne v1, v3, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    goto :goto_2

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lc1/y0;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p1, Lvy0/b0;

    .line 32
    .line 33
    iget-object v1, p0, Lc1/y0;->f:Ljava/lang/Object;

    .line 34
    .line 35
    iget-object v5, p0, Lc1/y0;->g:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    const/4 v7, 0x0

    .line 42
    if-nez v6, :cond_2

    .line 43
    .line 44
    invoke-static {v4}, Lc1/c1;->b0(Lc1/c1;)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    iput-object v7, v4, Lc1/c1;->r:Lc1/v0;

    .line 49
    .line 50
    iget-object v6, v4, Lc1/c1;->g:Ll2/j1;

    .line 51
    .line 52
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v6

    .line 56
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    if-eqz v6, :cond_3

    .line 61
    .line 62
    return-object v2

    .line 63
    :cond_3
    :goto_0
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    iget v6, p0, Lc1/y0;->j:F

    .line 68
    .line 69
    if-nez v5, :cond_4

    .line 70
    .line 71
    iget-object v5, p0, Lc1/y0;->i:Lc1/w1;

    .line 72
    .line 73
    invoke-virtual {v5, v1}, Lc1/w1;->p(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    const-wide/16 v8, 0x0

    .line 77
    .line 78
    invoke-virtual {v5, v8, v9}, Lc1/w1;->n(J)V

    .line 79
    .line 80
    .line 81
    iget-object v8, v4, Lc1/c1;->f:Ll2/j1;

    .line 82
    .line 83
    invoke-virtual {v8, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v5, v6}, Lc1/w1;->j(F)V

    .line 87
    .line 88
    .line 89
    :cond_4
    invoke-virtual {v4, v6}, Lc1/c1;->k0(F)V

    .line 90
    .line 91
    .line 92
    iget-object v1, v4, Lc1/c1;->q:Landroidx/collection/l0;

    .line 93
    .line 94
    invoke-virtual {v1}, Landroidx/collection/l0;->h()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eqz v1, :cond_5

    .line 99
    .line 100
    new-instance v1, La50/a;

    .line 101
    .line 102
    const/16 v5, 0x11

    .line 103
    .line 104
    invoke-direct {v1, v4, v7, v5}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 105
    .line 106
    .line 107
    const/4 v5, 0x3

    .line 108
    invoke-static {p1, v7, v7, v1, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_5
    const-wide/high16 v5, -0x8000000000000000L

    .line 113
    .line 114
    iput-wide v5, v4, Lc1/c1;->p:J

    .line 115
    .line 116
    :goto_1
    iput v3, p0, Lc1/y0;->d:I

    .line 117
    .line 118
    invoke-static {v4, p0}, Lc1/c1;->e0(Lc1/c1;Lrx0/c;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    if-ne p0, v0, :cond_6

    .line 123
    .line 124
    return-object v0

    .line 125
    :cond_6
    :goto_2
    invoke-virtual {v4}, Lc1/c1;->j0()V

    .line 126
    .line 127
    .line 128
    return-object v2
.end method
