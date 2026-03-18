.class public final Lc80/d0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Ljava/util/List;


# instance fields
.field public final h:Lwq0/g;

.field public final i:Lwq0/o;

.field public final j:Lwq0/a0;

.field public final k:Lwq0/d;

.field public final l:Lwq0/e0;

.field public final m:Lwr0/i;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lss0/n;->d:Lss0/n;

    .line 2
    .line 3
    sget-object v1, Lss0/n;->e:Lss0/n;

    .line 4
    .line 5
    sget-object v2, Lss0/n;->f:Lss0/n;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lss0/n;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lc80/d0;->n:Ljava/util/List;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lwq0/g;Lwq0/o;Lwq0/a0;Lwq0/d;Lwq0/e0;Lwr0/i;)V
    .locals 2

    .line 1
    new-instance v0, Lc80/b0;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lc80/b0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lc80/d0;->h:Lwq0/g;

    .line 11
    .line 12
    iput-object p2, p0, Lc80/d0;->i:Lwq0/o;

    .line 13
    .line 14
    iput-object p3, p0, Lc80/d0;->j:Lwq0/a0;

    .line 15
    .line 16
    iput-object p4, p0, Lc80/d0;->k:Lwq0/d;

    .line 17
    .line 18
    iput-object p5, p0, Lc80/d0;->l:Lwq0/e0;

    .line 19
    .line 20
    iput-object p6, p0, Lc80/d0;->m:Lwr0/i;

    .line 21
    .line 22
    new-instance p1, Lc80/a0;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    const/4 p3, 0x0

    .line 26
    invoke-direct {p1, p0, p3, p2}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Lc80/a0;

    .line 33
    .line 34
    const/4 p2, 0x1

    .line 35
    invoke-direct {p1, p0, p3, p2}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lc80/d0;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lc80/c0;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lc80/c0;

    .line 10
    .line 11
    iget v1, v0, Lc80/c0;->g:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lc80/c0;->g:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lc80/c0;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Lc80/c0;-><init>(Lc80/d0;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Lc80/c0;->e:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lc80/c0;->g:I

    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v5, 0x1

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    iget-object v0, v0, Lc80/c0;->d:Lyq0/d;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p1, p0, Lc80/d0;->h:Lwq0/g;

    .line 66
    .line 67
    iput v5, v0, Lc80/c0;->g:I

    .line 68
    .line 69
    invoke-virtual {p1, v4, v0}, Lwq0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-ne p1, v1, :cond_4

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    :goto_1
    check-cast p1, Lyq0/d;

    .line 77
    .line 78
    iget-object v2, p0, Lc80/d0;->i:Lwq0/o;

    .line 79
    .line 80
    iput-object p1, v0, Lc80/c0;->d:Lyq0/d;

    .line 81
    .line 82
    iput v3, v0, Lc80/c0;->g:I

    .line 83
    .line 84
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v2, v0}, Lwq0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    if-ne v0, v1, :cond_5

    .line 92
    .line 93
    :goto_2
    return-object v1

    .line 94
    :cond_5
    move-object v7, v0

    .line 95
    move-object v0, p1

    .line 96
    move-object p1, v7

    .line 97
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    check-cast v1, Lc80/b0;

    .line 108
    .line 109
    sget-object v2, Lyq0/a;->a:Lyq0/a;

    .line 110
    .line 111
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    const/4 v6, 0x0

    .line 116
    if-eqz v2, :cond_6

    .line 117
    .line 118
    if-eqz p1, :cond_6

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_6
    move v5, v6

    .line 122
    :goto_4
    invoke-static {v1, v0, v6, v5, v3}, Lc80/b0;->a(Lc80/b0;Lyq0/d;ZZI)Lc80/b0;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 127
    .line 128
    .line 129
    return-object v4
.end method
