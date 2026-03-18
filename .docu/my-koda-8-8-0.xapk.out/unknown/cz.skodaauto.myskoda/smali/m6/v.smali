.class public final Lm6/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lkotlin/jvm/internal/d0;

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lkotlin/jvm/internal/d0;

.field public final synthetic h:Lm6/w;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Z


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/d0;Lm6/w;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lm6/v;->g:Lkotlin/jvm/internal/d0;

    .line 2
    .line 3
    iput-object p2, p0, Lm6/v;->h:Lm6/w;

    .line 4
    .line 5
    iput-object p3, p0, Lm6/v;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iput-boolean p4, p0, Lm6/v;->j:Z

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lm6/v;

    .line 2
    .line 3
    iget-object v3, p0, Lm6/v;->i:Ljava/lang/Object;

    .line 4
    .line 5
    iget-boolean v4, p0, Lm6/v;->j:Z

    .line 6
    .line 7
    iget-object v1, p0, Lm6/v;->g:Lkotlin/jvm/internal/d0;

    .line 8
    .line 9
    iget-object v2, p0, Lm6/v;->h:Lm6/w;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Lm6/v;-><init>(Lkotlin/jvm/internal/d0;Lm6/w;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Lm6/v;->f:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lm6/g0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lm6/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lm6/v;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lm6/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lm6/v;->e:I

    .line 4
    .line 5
    iget-object v2, p0, Lm6/v;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v3, p0, Lm6/v;->h:Lm6/w;

    .line 8
    .line 9
    iget-object v4, p0, Lm6/v;->g:Lkotlin/jvm/internal/d0;

    .line 10
    .line 11
    const/4 v5, 0x2

    .line 12
    const/4 v6, 0x1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    if-eq v1, v6, :cond_1

    .line 16
    .line 17
    if-ne v1, v5, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_2

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
    iget-object v1, p0, Lm6/v;->d:Lkotlin/jvm/internal/d0;

    .line 32
    .line 33
    iget-object v6, p0, Lm6/v;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v6, Lm6/g0;

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lm6/v;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Lm6/g0;

    .line 47
    .line 48
    invoke-virtual {v3}, Lm6/w;->g()Lm6/i0;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iput-object p1, p0, Lm6/v;->f:Ljava/lang/Object;

    .line 53
    .line 54
    iput-object v4, p0, Lm6/v;->d:Lkotlin/jvm/internal/d0;

    .line 55
    .line 56
    iput v6, p0, Lm6/v;->e:I

    .line 57
    .line 58
    invoke-interface {v1, p0}, Lm6/i0;->e(Lm6/v;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    if-ne v1, v0, :cond_3

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    move-object v6, p1

    .line 66
    move-object p1, v1

    .line 67
    move-object v1, v4

    .line 68
    :goto_0
    check-cast p1, Ljava/lang/Number;

    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    iput p1, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 75
    .line 76
    const/4 p1, 0x0

    .line 77
    iput-object p1, p0, Lm6/v;->f:Ljava/lang/Object;

    .line 78
    .line 79
    iput-object p1, p0, Lm6/v;->d:Lkotlin/jvm/internal/d0;

    .line 80
    .line 81
    iput v5, p0, Lm6/v;->e:I

    .line 82
    .line 83
    invoke-virtual {v6, v2, p0}, Lm6/g0;->b(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-ne p1, v0, :cond_4

    .line 88
    .line 89
    :goto_1
    return-object v0

    .line 90
    :cond_4
    :goto_2
    iget-boolean p0, p0, Lm6/v;->j:Z

    .line 91
    .line 92
    if-eqz p0, :cond_6

    .line 93
    .line 94
    iget-object p0, v3, Lm6/w;->h:Lm6/x;

    .line 95
    .line 96
    new-instance p1, Lm6/d;

    .line 97
    .line 98
    if-eqz v2, :cond_5

    .line 99
    .line 100
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    goto :goto_3

    .line 105
    :cond_5
    const/4 v0, 0x0

    .line 106
    :goto_3
    iget v1, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 107
    .line 108
    invoke-direct {p1, v2, v0, v1}, Lm6/d;-><init>(Ljava/lang/Object;II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, p1}, Lm6/x;->b(Lm6/z0;)V

    .line 112
    .line 113
    .line 114
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0
.end method
