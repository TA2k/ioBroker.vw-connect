.class public final Lxf0/s2;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Lpw0/a;

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lg1/z1;

.field public final synthetic i:Lay0/o;

.field public final synthetic j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;


# direct methods
.method public constructor <init>(Lg1/z1;Lay0/o;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lxf0/s2;->h:Lg1/z1;

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/s2;->i:Lay0/o;

    .line 4
    .line 5
    iput-object p3, p0, Lxf0/s2;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lxf0/s2;

    .line 2
    .line 3
    iget-object v1, p0, Lxf0/s2;->i:Lay0/o;

    .line 4
    .line 5
    iget-object v2, p0, Lxf0/s2;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 6
    .line 7
    iget-object p0, p0, Lxf0/s2;->h:Lg1/z1;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lxf0/s2;-><init>(Lg1/z1;Lay0/o;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lxf0/s2;->g:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lxf0/s2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lxf0/s2;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lxf0/s2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v3, p0, Lxf0/s2;->h:Lg1/z1;

    .line 2
    .line 3
    iget-object v6, v3, Lg1/z1;->h:Lez0/c;

    .line 4
    .line 5
    iget-object v0, p0, Lxf0/s2;->g:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v7, v0

    .line 8
    check-cast v7, Lp3/i0;

    .line 9
    .line 10
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v0, p0, Lxf0/s2;->f:I

    .line 13
    .line 14
    const/4 v9, 0x2

    .line 15
    const/4 v10, 0x1

    .line 16
    const/4 v5, 0x0

    .line 17
    if-eqz v0, :cond_3

    .line 18
    .line 19
    if-eq v0, v10, :cond_1

    .line 20
    .line 21
    if-ne v0, v9, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    iget-object v0, p0, Lxf0/s2;->e:Lpw0/a;

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :cond_2
    move-object v11, v0

    .line 41
    goto :goto_0

    .line 42
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    sget-object p1, Lge0/b;->a:Lcz0/e;

    .line 46
    .line 47
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-virtual {v6}, Lez0/c;->tryLock()Z

    .line 52
    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    iput-boolean p1, v3, Lg1/z1;->f:Z

    .line 56
    .line 57
    iput-boolean p1, v3, Lg1/z1;->g:Z

    .line 58
    .line 59
    iput-object v7, p0, Lxf0/s2;->g:Ljava/lang/Object;

    .line 60
    .line 61
    iput-object v0, p0, Lxf0/s2;->e:Lpw0/a;

    .line 62
    .line 63
    iput v10, p0, Lxf0/s2;->f:I

    .line 64
    .line 65
    invoke-static {v7, p0, v9}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v8, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :goto_0
    move-object v4, p1

    .line 73
    check-cast v4, Lp3/t;

    .line 74
    .line 75
    sget-object p1, Lxf0/v2;->a:Lg1/e1;

    .line 76
    .line 77
    iget-object v2, p0, Lxf0/s2;->i:Lay0/o;

    .line 78
    .line 79
    if-eq v2, p1, :cond_4

    .line 80
    .line 81
    new-instance v0, Lws/b;

    .line 82
    .line 83
    const/4 v1, 0x4

    .line 84
    invoke-direct/range {v0 .. v5}, Lws/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 85
    .line 86
    .line 87
    const/4 p1, 0x3

    .line 88
    invoke-static {v11, v5, v5, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 89
    .line 90
    .line 91
    :cond_4
    iput-object v5, p0, Lxf0/s2;->g:Ljava/lang/Object;

    .line 92
    .line 93
    iput-object v5, p0, Lxf0/s2;->e:Lpw0/a;

    .line 94
    .line 95
    iput v9, p0, Lxf0/s2;->f:I

    .line 96
    .line 97
    invoke-static {v7, p0}, Lxf0/v2;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v8, :cond_5

    .line 102
    .line 103
    :goto_1
    return-object v8

    .line 104
    :cond_5
    :goto_2
    check-cast p1, Lp3/t;

    .line 105
    .line 106
    if-nez p1, :cond_6

    .line 107
    .line 108
    iput-boolean v10, v3, Lg1/z1;->g:Z

    .line 109
    .line 110
    invoke-virtual {v6, v5}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_6
    iput-boolean v10, v3, Lg1/z1;->f:Z

    .line 115
    .line 116
    invoke-virtual {v6, v5}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lxf0/s2;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 120
    .line 121
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast p1, Lp3/x;

    .line 124
    .line 125
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Lay0/a;

    .line 128
    .line 129
    new-instance v0, Lp61/b;

    .line 130
    .line 131
    const/16 v1, 0x1c

    .line 132
    .line 133
    invoke-direct {v0, p0, v1}, Lp61/b;-><init>(Lay0/a;I)V

    .line 134
    .line 135
    .line 136
    invoke-static {p1, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 137
    .line 138
    .line 139
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0
.end method
