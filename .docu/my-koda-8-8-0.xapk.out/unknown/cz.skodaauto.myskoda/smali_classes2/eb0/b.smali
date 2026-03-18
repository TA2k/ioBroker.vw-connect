.class public final Leb0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Leb0/b;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Leb0/b;->b:Lti0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Leb0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Leb0/a;

    .line 7
    .line 8
    iget v1, v0, Leb0/a;->f:I

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
    iput v1, v0, Leb0/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Leb0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Leb0/a;-><init>(Leb0/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Leb0/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Leb0/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    new-instance p1, La90/s;

    .line 53
    .line 54
    const/4 v2, 0x7

    .line 55
    invoke-direct {p1, p0, v3, v2}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    new-instance v2, Ldj/a;

    .line 59
    .line 60
    const/16 v5, 0x1c

    .line 61
    .line 62
    invoke-direct {v2, v5}, Ldj/a;-><init>(I)V

    .line 63
    .line 64
    .line 65
    iput v4, v0, Leb0/a;->f:I

    .line 66
    .line 67
    iget-object p0, p0, Leb0/b;->a:Lxl0/f;

    .line 68
    .line 69
    invoke-virtual {p0, p1, v2, v3, v0}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-ne p1, v1, :cond_3

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 77
    .line 78
    const-string p0, "<this>"

    .line 79
    .line 80
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    instance-of p0, p1, Lne0/e;

    .line 84
    .line 85
    if-eqz p0, :cond_4

    .line 86
    .line 87
    return-object p1

    .line 88
    :cond_4
    instance-of p0, p1, Lne0/c;

    .line 89
    .line 90
    if-eqz p0, :cond_a

    .line 91
    .line 92
    move-object v6, p1

    .line 93
    check-cast v6, Lne0/c;

    .line 94
    .line 95
    iget-object p0, v6, Lne0/c;->a:Ljava/lang/Throwable;

    .line 96
    .line 97
    instance-of p1, p0, Lbm0/d;

    .line 98
    .line 99
    if-eqz p1, :cond_5

    .line 100
    .line 101
    check-cast p0, Lbm0/d;

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_5
    move-object p0, v3

    .line 105
    :goto_2
    if-eqz p0, :cond_6

    .line 106
    .line 107
    iget p0, p0, Lbm0/d;->d:I

    .line 108
    .line 109
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    :cond_6
    if-nez v3, :cond_7

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_7
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    const/16 v0, 0x194

    .line 121
    .line 122
    if-ne p0, v0, :cond_8

    .line 123
    .line 124
    new-instance v7, Lne0/c;

    .line 125
    .line 126
    sget-object v8, Lss0/q;->d:Lss0/q;

    .line 127
    .line 128
    const/4 v11, 0x0

    .line 129
    const/16 v12, 0x1e

    .line 130
    .line 131
    const/4 v9, 0x0

    .line 132
    const/4 v10, 0x0

    .line 133
    invoke-direct/range {v7 .. v12}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 134
    .line 135
    .line 136
    move-object v6, v7

    .line 137
    goto :goto_4

    .line 138
    :cond_8
    :goto_3
    if-eqz p1, :cond_9

    .line 139
    .line 140
    new-instance v4, Lne0/c;

    .line 141
    .line 142
    new-instance v5, Lss0/c0;

    .line 143
    .line 144
    invoke-direct {v5}, Lss0/c0;-><init>()V

    .line 145
    .line 146
    .line 147
    const/4 v8, 0x0

    .line 148
    const/16 v9, 0x1c

    .line 149
    .line 150
    const/4 v7, 0x0

    .line 151
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 152
    .line 153
    .line 154
    move-object v6, v4

    .line 155
    :cond_9
    :goto_4
    return-object v6

    .line 156
    :cond_a
    new-instance p0, La8/r0;

    .line 157
    .line 158
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 159
    .line 160
    .line 161
    throw p0
.end method
