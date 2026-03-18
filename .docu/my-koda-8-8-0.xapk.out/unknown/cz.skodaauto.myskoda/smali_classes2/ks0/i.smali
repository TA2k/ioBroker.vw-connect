.class public final Lks0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lis0/d;

.field public final b:Lsg0/a;

.field public final c:Lwr0/e;


# direct methods
.method public constructor <init>(Lis0/d;Lsg0/a;Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lks0/i;->a:Lis0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lks0/i;->b:Lsg0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lks0/i;->c:Lwr0/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lks0/i;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lks0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lks0/h;

    .line 7
    .line 8
    iget v1, v0, Lks0/h;->h:I

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
    iput v1, v0, Lks0/h;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lks0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lks0/h;-><init>(Lks0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lks0/h;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lks0/h;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lks0/h;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v0, v0, Lks0/h;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object v5, p1

    .line 44
    move-object v6, v0

    .line 45
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p2, p0, Lks0/i;->b:Lsg0/a;

    .line 58
    .line 59
    iget-object p2, p2, Lsg0/a;->a:Ljava/lang/String;

    .line 60
    .line 61
    iput-object p1, v0, Lks0/h;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput-object p2, v0, Lks0/h;->e:Ljava/lang/String;

    .line 64
    .line 65
    iput v3, v0, Lks0/h;->h:I

    .line 66
    .line 67
    iget-object v2, p0, Lks0/i;->c:Lwr0/e;

    .line 68
    .line 69
    iget-object v2, v2, Lwr0/e;->a:Lwr0/g;

    .line 70
    .line 71
    check-cast v2, Lur0/g;

    .line 72
    .line 73
    invoke-virtual {v2, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-ne v0, v1, :cond_3

    .line 78
    .line 79
    return-object v1

    .line 80
    :cond_3
    move-object v6, p1

    .line 81
    move-object v5, p2

    .line 82
    move-object p2, v0

    .line 83
    :goto_1
    check-cast p2, Lyr0/e;

    .line 84
    .line 85
    if-eqz p2, :cond_4

    .line 86
    .line 87
    iget-object p1, p2, Lyr0/e;->a:Ljava/lang/String;

    .line 88
    .line 89
    :goto_2
    move-object v4, p1

    .line 90
    goto :goto_3

    .line 91
    :cond_4
    const/4 p1, 0x0

    .line 92
    goto :goto_2

    .line 93
    :goto_3
    if-nez v5, :cond_5

    .line 94
    .line 95
    const-string p1, "No vin was selected for enrollment"

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Lks0/i;->c(Ljava/lang/String;)Lyy0/m;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :cond_5
    if-nez v4, :cond_6

    .line 103
    .line 104
    const-string p1, "User id is not available"

    .line 105
    .line 106
    invoke-virtual {p0, p1}, Lks0/i;->c(Ljava/lang/String;)Lyy0/m;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0

    .line 111
    :cond_6
    iget-object v3, p0, Lks0/i;->a:Lis0/d;

    .line 112
    .line 113
    const-string p0, "oneTimeKey"

    .line 114
    .line 115
    invoke-static {v6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    iget-object p0, v3, Lis0/d;->a:Lxl0/f;

    .line 119
    .line 120
    new-instance v2, Ld40/k;

    .line 121
    .line 122
    const/4 v7, 0x0

    .line 123
    const/4 v8, 0x4

    .line 124
    invoke-direct/range {v2 .. v8}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 125
    .line 126
    .line 127
    new-instance p1, Lim0/b;

    .line 128
    .line 129
    const/4 p2, 0x4

    .line 130
    invoke-direct {p1, p2}, Lim0/b;-><init>(I)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p0, v2, p1}, Lxl0/f;->d(Lay0/k;Lay0/k;)Lyy0/m1;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0
.end method

.method public final c(Ljava/lang/String;)Lyy0/m;
    .locals 8

    .line 1
    new-instance v0, Lq61/c;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, p1, v1}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 10
    .line 11
    .line 12
    new-instance v2, Lne0/c;

    .line 13
    .line 14
    new-instance v3, Ljava/lang/Exception;

    .line 15
    .line 16
    invoke-direct {v3, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const/4 v6, 0x0

    .line 20
    const/16 v7, 0x1e

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 25
    .line 26
    .line 27
    new-instance p0, Lyy0/m;

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    invoke-direct {p0, v2, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    return-object p0
.end method
