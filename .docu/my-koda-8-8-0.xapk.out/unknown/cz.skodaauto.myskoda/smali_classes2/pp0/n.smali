.class public final Lpp0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lkf0/o;

.field public final c:Lpp0/c0;

.field public final d:Lnp0/c;

.field public final e:Lpp0/l0;

.field public final f:Lpp0/v0;


# direct methods
.method public constructor <init>(Lkf0/k;Lkf0/o;Lpp0/c0;Lnp0/c;Lpp0/l0;Lpp0/v0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/n;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/n;->b:Lkf0/o;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/n;->c:Lpp0/c0;

    .line 9
    .line 10
    iput-object p4, p0, Lpp0/n;->d:Lnp0/c;

    .line 11
    .line 12
    iput-object p5, p0, Lpp0/n;->e:Lpp0/l0;

    .line 13
    .line 14
    iput-object p6, p0, Lpp0/n;->f:Lpp0/v0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lpp0/n;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lpp0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpp0/m;

    .line 7
    .line 8
    iget v1, v0, Lpp0/m;->f:I

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
    iput v1, v0, Lpp0/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lpp0/m;-><init>(Lpp0/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpp0/m;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/m;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lpp0/n;->c:Lpp0/c0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

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
    move-object p1, v3

    .line 54
    check-cast p1, Lnp0/b;

    .line 55
    .line 56
    iget-object p1, p1, Lnp0/b;->g:Lyy0/l1;

    .line 57
    .line 58
    iput v4, v0, Lpp0/m;->f:I

    .line 59
    .line 60
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v1, :cond_3

    .line 65
    .line 66
    return-object v1

    .line 67
    :cond_3
    :goto_1
    check-cast p1, Lqp0/o;

    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    if-eqz p1, :cond_4

    .line 71
    .line 72
    new-instance v1, Lne0/e;

    .line 73
    .line 74
    invoke-direct {v1, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    new-instance v2, Lyy0/m;

    .line 78
    .line 79
    invoke-direct {v2, v1, v0}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    sget-object v2, Lyy0/h;->d:Lyy0/h;

    .line 84
    .line 85
    :goto_2
    check-cast v3, Lnp0/b;

    .line 86
    .line 87
    iget-object v1, v3, Lnp0/b;->c:Lyy0/l1;

    .line 88
    .line 89
    new-instance v3, Lrz/k;

    .line 90
    .line 91
    const/16 v5, 0x15

    .line 92
    .line 93
    invoke-direct {v3, v1, v5}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 94
    .line 95
    .line 96
    iget-object v1, p0, Lpp0/n;->e:Lpp0/l0;

    .line 97
    .line 98
    invoke-virtual {v1}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    check-cast v1, Lyy0/i;

    .line 103
    .line 104
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    new-instance v6, Lal0/y0;

    .line 109
    .line 110
    const/4 v7, 0x3

    .line 111
    const/16 v8, 0x14

    .line 112
    .line 113
    const/4 v9, 0x0

    .line 114
    invoke-direct {v6, v7, v9, v8}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    new-instance v7, Lbn0/f;

    .line 118
    .line 119
    const/4 v8, 0x5

    .line 120
    invoke-direct {v7, v3, v1, v6, v8}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 121
    .line 122
    .line 123
    if-eqz p1, :cond_5

    .line 124
    .line 125
    move v1, v4

    .line 126
    goto :goto_3

    .line 127
    :cond_5
    move v1, v0

    .line 128
    :goto_3
    new-instance v3, Lyy0/d0;

    .line 129
    .line 130
    invoke-direct {v3, v7, v1, v0}, Lyy0/d0;-><init>(Lyy0/i;II)V

    .line 131
    .line 132
    .line 133
    new-instance v1, Lam0/i;

    .line 134
    .line 135
    invoke-direct {v1, v3, v5}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 136
    .line 137
    .line 138
    new-instance v3, Lpp0/l;

    .line 139
    .line 140
    invoke-direct {v3, v9, p0, p1}, Lpp0/l;-><init>(Lkotlin/coroutines/Continuation;Lpp0/n;Lqp0/o;)V

    .line 141
    .line 142
    .line 143
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    const/4 p1, 0x2

    .line 148
    new-array p1, p1, [Lyy0/i;

    .line 149
    .line 150
    aput-object v2, p1, v0

    .line 151
    .line 152
    aput-object p0, p1, v4

    .line 153
    .line 154
    invoke-static {p1}, Lyy0/u;->D([Lyy0/i;)Lyy0/e;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0
.end method
