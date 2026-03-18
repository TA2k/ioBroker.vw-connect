.class public final Le60/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrq0/d;

.field public final b:Le60/c;


# direct methods
.method public constructor <init>(Lrq0/d;Le60/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le60/n;->a:Lrq0/d;

    .line 5
    .line 6
    iput-object p2, p0, Le60/n;->b:Le60/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Le60/n;->b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/Map;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Le60/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Le60/l;

    .line 7
    .line 8
    iget v1, v0, Le60/l;->f:I

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
    iput v1, v0, Le60/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le60/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Le60/l;-><init>(Le60/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Le60/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le60/l;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    const-string p2, "action"

    .line 59
    .line 60
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    check-cast p1, Ljava/lang/String;

    .line 65
    .line 66
    const-string p2, "honk_and_flash"

    .line 67
    .line 68
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    iget-object v2, p0, Le60/n;->b:Le60/c;

    .line 73
    .line 74
    if-eqz p2, :cond_5

    .line 75
    .line 76
    sget-object p1, Lf60/a;->e:Lf60/a;

    .line 77
    .line 78
    invoke-virtual {v2, p1}, Le60/c;->a(Lf60/a;)Lzy0/j;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iput v4, v0, Le60/l;->f:I

    .line 87
    .line 88
    invoke-static {p1, v0}, Lyy0/u;->z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    if-ne p2, v1, :cond_4

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_5
    const-string p2, "flash"

    .line 99
    .line 100
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-eqz p1, :cond_7

    .line 105
    .line 106
    sget-object p1, Lf60/a;->d:Lf60/a;

    .line 107
    .line 108
    invoke-virtual {v2, p1}, Le60/c;->a(Lf60/a;)Lzy0/j;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    iput v3, v0, Le60/l;->f:I

    .line 117
    .line 118
    invoke-static {p1, v0}, Lyy0/u;->z(Lyy0/i;Lrx0/c;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    if-ne p2, v1, :cond_6

    .line 123
    .line 124
    :goto_2
    return-object v1

    .line 125
    :cond_6
    :goto_3
    check-cast p2, Lne0/t;

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_7
    new-instance p2, Lne0/e;

    .line 129
    .line 130
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    invoke-direct {p2, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :goto_4
    instance-of p1, p2, Lne0/c;

    .line 136
    .line 137
    if-eqz p1, :cond_8

    .line 138
    .line 139
    move-object p1, p2

    .line 140
    check-cast p1, Lne0/c;

    .line 141
    .line 142
    sget-object v0, Lge0/a;->d:Lge0/a;

    .line 143
    .line 144
    new-instance v1, Le60/m;

    .line 145
    .line 146
    const/4 v2, 0x0

    .line 147
    const/4 v3, 0x0

    .line 148
    invoke-direct {v1, v2, p0, p1, v3}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 149
    .line 150
    .line 151
    const/4 p0, 0x3

    .line 152
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 153
    .line 154
    .line 155
    :cond_8
    return-object p2
.end method
