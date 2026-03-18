.class public final Lxl0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lam0/a;


# instance fields
.field public final a:Lve0/u;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxl0/j;->a:Lve0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lxl0/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxl0/i;

    .line 7
    .line 8
    iget v1, v0, Lxl0/i;->i:I

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
    iput v1, v0, Lxl0/i;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxl0/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lxl0/i;-><init>(Lxl0/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lxl0/i;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxl0/i;->i:I

    .line 30
    .line 31
    const-string v3, "app_installation_id"

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    iget-object p0, p0, Lxl0/j;->a:Lve0/u;

    .line 37
    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v6, :cond_3

    .line 41
    .line 42
    if-eq v2, v5, :cond_2

    .line 43
    .line 44
    if-ne v2, v4, :cond_1

    .line 45
    .line 46
    iget-object p0, v0, Lxl0/i;->d:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget v2, v0, Lxl0/i;->f:I

    .line 61
    .line 62
    iget-object v5, v0, Lxl0/i;->e:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v6, v0, Lxl0/i;->d:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iput v6, v0, Lxl0/i;->i:I

    .line 78
    .line 79
    invoke-virtual {p0, v3, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    if-ne p1, v1, :cond_5

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 87
    .line 88
    if-nez p1, :cond_8

    .line 89
    .line 90
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    const-string v2, "toString(...)"

    .line 99
    .line 100
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iput-object p1, v0, Lxl0/i;->d:Ljava/lang/String;

    .line 104
    .line 105
    iput-object p1, v0, Lxl0/i;->e:Ljava/lang/String;

    .line 106
    .line 107
    const/4 v2, 0x0

    .line 108
    iput v2, v0, Lxl0/i;->f:I

    .line 109
    .line 110
    iput v5, v0, Lxl0/i;->i:I

    .line 111
    .line 112
    const-string v5, "app_installation_version"

    .line 113
    .line 114
    const-string v6, "8.8.0"

    .line 115
    .line 116
    invoke-virtual {p0, v5, v6, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    if-ne v5, v1, :cond_6

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_6
    move-object v5, p1

    .line 124
    move-object v6, v5

    .line 125
    :goto_2
    iput-object v6, v0, Lxl0/i;->d:Ljava/lang/String;

    .line 126
    .line 127
    const/4 p1, 0x0

    .line 128
    iput-object p1, v0, Lxl0/i;->e:Ljava/lang/String;

    .line 129
    .line 130
    iput v2, v0, Lxl0/i;->f:I

    .line 131
    .line 132
    iput v4, v0, Lxl0/i;->i:I

    .line 133
    .line 134
    invoke-virtual {p0, v3, v5, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    if-ne p0, v1, :cond_7

    .line 139
    .line 140
    :goto_3
    return-object v1

    .line 141
    :cond_7
    return-object v6

    .line 142
    :cond_8
    return-object p1
.end method
