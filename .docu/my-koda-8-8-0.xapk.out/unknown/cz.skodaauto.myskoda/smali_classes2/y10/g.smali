.class public final Ly10/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lw10/g;

.field public final i:Lw10/e;

.field public final j:Lw10/a;

.field public final k:Lhq0/h;

.field public final l:Lhq0/c;

.field public final m:Ltr0/b;

.field public final n:Lij0/a;

.field public final o:Llp0/b;

.field public final p:Llp0/d;

.field public final q:Lgt0/d;

.field public final r:Lwr0/i;


# direct methods
.method public constructor <init>(Lw10/g;Lw10/e;Lw10/a;Lhq0/h;Lhq0/c;Ltr0/b;Lij0/a;Llp0/b;Llp0/d;Lgt0/d;Lwr0/i;)V
    .locals 3

    .line 1
    new-instance v0, Ly10/e;

    .line 2
    .line 3
    const/16 v1, 0xff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Ly10/e;-><init>(Ljava/util/List;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ly10/g;->h:Lw10/g;

    .line 13
    .line 14
    iput-object p2, p0, Ly10/g;->i:Lw10/e;

    .line 15
    .line 16
    iput-object p3, p0, Ly10/g;->j:Lw10/a;

    .line 17
    .line 18
    iput-object p4, p0, Ly10/g;->k:Lhq0/h;

    .line 19
    .line 20
    iput-object p5, p0, Ly10/g;->l:Lhq0/c;

    .line 21
    .line 22
    iput-object p6, p0, Ly10/g;->m:Ltr0/b;

    .line 23
    .line 24
    iput-object p7, p0, Ly10/g;->n:Lij0/a;

    .line 25
    .line 26
    iput-object p8, p0, Ly10/g;->o:Llp0/b;

    .line 27
    .line 28
    iput-object p9, p0, Ly10/g;->p:Llp0/d;

    .line 29
    .line 30
    iput-object p10, p0, Ly10/g;->q:Lgt0/d;

    .line 31
    .line 32
    iput-object p11, p0, Ly10/g;->r:Lwr0/i;

    .line 33
    .line 34
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    new-instance p2, Ly10/b;

    .line 39
    .line 40
    const/4 p3, 0x0

    .line 41
    invoke-direct {p2, p0, v2, p3}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    const/4 p3, 0x3

    .line 45
    invoke-static {p1, v2, v2, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    new-instance p1, Ly10/b;

    .line 49
    .line 50
    const/4 p2, 0x1

    .line 51
    invoke-direct {p1, p0, v2, p2}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 55
    .line 56
    .line 57
    new-instance p1, Ly10/b;

    .line 58
    .line 59
    const/4 p2, 0x2

    .line 60
    invoke-direct {p1, p0, v2, p2}, Ly10/b;-><init>(Ly10/g;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public static final h(Ly10/g;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Ly10/f;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Ly10/f;

    .line 10
    .line 11
    iget v1, v0, Ly10/f;->f:I

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
    iput v1, v0, Ly10/f;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ly10/f;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Ly10/f;-><init>(Ly10/g;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Ly10/f;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Ly10/f;->f:I

    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    const/4 v4, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Ly10/g;->h:Lw10/g;

    .line 62
    .line 63
    iput v4, v0, Ly10/f;->f:I

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    iget-object v9, p1, Lw10/g;->a:Lw10/f;

    .line 69
    .line 70
    move-object v2, v9

    .line 71
    check-cast v2, Lu10/b;

    .line 72
    .line 73
    iget-object v2, v2, Lu10/b;->a:Lcom/google/firebase/messaging/w;

    .line 74
    .line 75
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v4, Lyy0/k1;

    .line 78
    .line 79
    iget-object v2, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v2, Lez0/c;

    .line 82
    .line 83
    new-instance v5, La90/r;

    .line 84
    .line 85
    const/4 v6, 0x0

    .line 86
    const/16 v7, 0x1a

    .line 87
    .line 88
    const-class v8, Lw10/f;

    .line 89
    .line 90
    const-string v10, "isDataValid"

    .line 91
    .line 92
    const-string v11, "isDataValid()Z"

    .line 93
    .line 94
    invoke-direct/range {v5 .. v11}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v6, Lus0/a;

    .line 98
    .line 99
    const/4 v7, 0x0

    .line 100
    const/4 v8, 0x1

    .line 101
    invoke-direct {v6, p1, v7, v8}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 102
    .line 103
    .line 104
    invoke-static {v4, v2, v5, v6}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v1, :cond_4

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_4
    :goto_1
    check-cast p1, Lyy0/i;

    .line 112
    .line 113
    new-instance v2, Ly10/a;

    .line 114
    .line 115
    const/4 v4, 0x2

    .line 116
    invoke-direct {v2, p0, v4}, Ly10/a;-><init>(Ly10/g;I)V

    .line 117
    .line 118
    .line 119
    iput v3, v0, Ly10/f;->f:I

    .line 120
    .line 121
    invoke-interface {p1, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    if-ne p0, v1, :cond_5

    .line 126
    .line 127
    :goto_2
    return-object v1

    .line 128
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object p0
.end method


# virtual methods
.method public final j()V
    .locals 11

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Ly10/e;

    .line 7
    .line 8
    const/4 v9, 0x0

    .line 9
    const/16 v10, 0xf7

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x0

    .line 14
    const-string v5, ""

    .line 15
    .line 16
    const/4 v6, 0x0

    .line 17
    const/4 v7, 0x0

    .line 18
    const/4 v8, 0x0

    .line 19
    invoke-static/range {v1 .. v10}, Ly10/e;->a(Ly10/e;ZZLjava/util/ArrayList;Ljava/lang/String;Lql0/g;ZLy10/d;ZI)Ly10/e;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
