.class public final Lwk0/t2;
.super Lwk0/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final n:Lij0/a;

.field public final o:Lbq0/p;

.field public final p:Lbq0/n;

.field public final q:Lbq0/q;

.field public final r:Luk0/r0;

.field public final s:Lbq0/c;

.field public final t:Lqf0/g;

.field public final u:Lkf0/k;


# direct methods
.method public constructor <init>(Luk0/c0;Luk0/b0;Lij0/a;Lbq0/p;Lbq0/n;Lbq0/q;Luk0/r0;Lbq0/c;Lqf0/g;Lkf0/k;)V
    .locals 2

    .line 1
    const-class v0, Lvk0/t0;

    .line 2
    .line 3
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-direct {p0, p1, p2, v0}, Lwk0/z1;-><init>(Luk0/c0;Luk0/b0;Lhy0/d;)V

    .line 10
    .line 11
    .line 12
    iput-object p3, p0, Lwk0/t2;->n:Lij0/a;

    .line 13
    .line 14
    iput-object p4, p0, Lwk0/t2;->o:Lbq0/p;

    .line 15
    .line 16
    iput-object p5, p0, Lwk0/t2;->p:Lbq0/n;

    .line 17
    .line 18
    iput-object p6, p0, Lwk0/t2;->q:Lbq0/q;

    .line 19
    .line 20
    iput-object p7, p0, Lwk0/t2;->r:Luk0/r0;

    .line 21
    .line 22
    iput-object p8, p0, Lwk0/t2;->s:Lbq0/c;

    .line 23
    .line 24
    iput-object p9, p0, Lwk0/t2;->t:Lqf0/g;

    .line 25
    .line 26
    iput-object p10, p0, Lwk0/t2;->u:Lkf0/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final bridge synthetic j(Lwk0/x1;Lvk0/j0;Lwk0/y1;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p2, Lvk0/t0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lwk0/t2;->k(Lwk0/x1;Lvk0/t0;Lrx0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final k(Lwk0/x1;Lvk0/t0;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lwk0/s2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lwk0/s2;

    .line 7
    .line 8
    iget v1, v0, Lwk0/s2;->i:I

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
    iput v1, v0, Lwk0/s2;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwk0/s2;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lwk0/s2;-><init>(Lwk0/t2;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lwk0/s2;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwk0/s2;->i:I

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
    iget-boolean p0, v0, Lwk0/s2;->f:Z

    .line 40
    .line 41
    iget-object p1, v0, Lwk0/s2;->e:Lvk0/t0;

    .line 42
    .line 43
    iget-object p2, v0, Lwk0/s2;->d:Lwk0/x1;

    .line 44
    .line 45
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p2, v0, Lwk0/s2;->e:Lvk0/t0;

    .line 58
    .line 59
    iget-object p1, v0, Lwk0/s2;->d:Lwk0/x1;

    .line 60
    .line 61
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, v0, Lwk0/s2;->d:Lwk0/x1;

    .line 69
    .line 70
    iput-object p2, v0, Lwk0/s2;->e:Lvk0/t0;

    .line 71
    .line 72
    iput v4, v0, Lwk0/s2;->i:I

    .line 73
    .line 74
    iget-object p3, p0, Lwk0/t2;->t:Lqf0/g;

    .line 75
    .line 76
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p3, v0}, Lqf0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p3

    .line 83
    if-ne p3, v1, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    :goto_1
    check-cast p3, Ljava/lang/Boolean;

    .line 87
    .line 88
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 89
    .line 90
    .line 91
    move-result p3

    .line 92
    iput-object p1, v0, Lwk0/s2;->d:Lwk0/x1;

    .line 93
    .line 94
    iput-object p2, v0, Lwk0/s2;->e:Lvk0/t0;

    .line 95
    .line 96
    iput-boolean p3, v0, Lwk0/s2;->f:Z

    .line 97
    .line 98
    iput v3, v0, Lwk0/s2;->i:I

    .line 99
    .line 100
    iget-object p0, p0, Lwk0/t2;->u:Lkf0/k;

    .line 101
    .line 102
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-ne p0, v1, :cond_5

    .line 110
    .line 111
    :goto_2
    return-object v1

    .line 112
    :cond_5
    move v5, p3

    .line 113
    move-object p3, p0

    .line 114
    move p0, v5

    .line 115
    move-object v5, p2

    .line 116
    move-object p2, p1

    .line 117
    move-object p1, v5

    .line 118
    :goto_3
    check-cast p3, Lss0/b;

    .line 119
    .line 120
    sget-object v0, Lss0/e;->E1:Lss0/e;

    .line 121
    .line 122
    invoke-static {p3, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 123
    .line 124
    .line 125
    move-result p3

    .line 126
    new-instance v0, Lwk0/p2;

    .line 127
    .line 128
    iget-boolean p1, p1, Lvk0/t0;->b:Z

    .line 129
    .line 130
    xor-int/2addr p0, v4

    .line 131
    invoke-direct {v0, v3, p1, p0, p3}, Lwk0/p2;-><init>(IZZZ)V

    .line 132
    .line 133
    .line 134
    const p0, 0xefff

    .line 135
    .line 136
    .line 137
    const/4 p1, 0x0

    .line 138
    invoke-static {p2, p1, v0, p0}, Lwk0/x1;->a(Lwk0/x1;Lnx0/f;Ljava/lang/Object;I)Lwk0/x1;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0
.end method
