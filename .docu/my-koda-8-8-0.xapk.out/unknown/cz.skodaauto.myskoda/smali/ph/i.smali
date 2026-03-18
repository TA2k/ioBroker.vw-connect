.class public final Lph/i;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljh/b;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljh/b;)V
    .locals 9

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lph/i;->d:Ljh/b;

    .line 5
    .line 6
    new-instance v0, Lph/j;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v1, 0x0

    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct/range {v0 .. v5}, Lph/j;-><init>(Ljava/lang/String;ZZZZ)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lph/i;->e:Lyy0/c2;

    .line 21
    .line 22
    new-instance v0, Lag/r;

    .line 23
    .line 24
    const/16 v1, 0xa

    .line 25
    .line 26
    invoke-direct {v0, p1, v1}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    check-cast p1, Lph/j;

    .line 38
    .line 39
    const-string v2, "<this>"

    .line 40
    .line 41
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-boolean v4, p1, Lph/j;->a:Z

    .line 45
    .line 46
    iget-boolean v6, p1, Lph/j;->c:Z

    .line 47
    .line 48
    iget-boolean v5, p1, Lph/j;->b:Z

    .line 49
    .line 50
    iget-boolean v7, p1, Lph/j;->e:Z

    .line 51
    .line 52
    iget-object v8, p1, Lph/j;->d:Ljava/lang/String;

    .line 53
    .line 54
    new-instance v3, Lph/g;

    .line 55
    .line 56
    invoke-direct/range {v3 .. v8}, Lph/g;-><init>(ZZZZLjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sget-object p1, Lyy0/u1;->a:Lyy0/w1;

    .line 60
    .line 61
    invoke-static {v0, v1, p1, v3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iput-object p1, p0, Lph/i;->f:Lyy0/l1;

    .line 66
    .line 67
    return-void
.end method


# virtual methods
.method public final a(Lph/f;)V
    .locals 10

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lph/b;->a:Lph/b;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const-string v1, "<this>"

    .line 13
    .line 14
    iget-object v2, p0, Lph/i;->e:Lyy0/c2;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    move-object v3, p0

    .line 26
    check-cast v3, Lph/j;

    .line 27
    .line 28
    iget-boolean p1, v3, Lph/j;->a:Z

    .line 29
    .line 30
    xor-int/lit8 v4, p1, 0x1

    .line 31
    .line 32
    const/4 v8, 0x0

    .line 33
    const/16 v9, 0x1e

    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    invoke-static/range {v3 .. v9}, Lph/j;->a(Lph/j;ZZZLjava/lang/String;ZI)Lph/j;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    sget-object v0, Lph/e;->a:Lph/e;

    .line 50
    .line 51
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    :cond_2
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    move-object v3, p0

    .line 65
    check-cast v3, Lph/j;

    .line 66
    .line 67
    const/4 v8, 0x0

    .line 68
    const/16 v9, 0x13

    .line 69
    .line 70
    const/4 v4, 0x0

    .line 71
    const/4 v5, 0x0

    .line 72
    const/4 v6, 0x0

    .line 73
    const/4 v7, 0x0

    .line 74
    invoke-static/range {v3 .. v9}, Lph/j;->a(Lph/j;ZZZLjava/lang/String;ZI)Lph/j;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {v2, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    if-eqz p0, :cond_2

    .line 83
    .line 84
    :goto_0
    return-void

    .line 85
    :cond_3
    sget-object v0, Lph/d;->a:Lph/d;

    .line 86
    .line 87
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_4

    .line 92
    .line 93
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    new-instance v0, Ln00/f;

    .line 98
    .line 99
    const/16 v1, 0xb

    .line 100
    .line 101
    const/4 v2, 0x0

    .line 102
    invoke-direct {v0, p0, v2, v1}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 103
    .line 104
    .line 105
    const/4 p0, 0x3

    .line 106
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :cond_4
    instance-of v0, p1, Lph/c;

    .line 111
    .line 112
    if-eqz v0, :cond_5

    .line 113
    .line 114
    check-cast p1, Lph/c;

    .line 115
    .line 116
    iget-object v0, p1, Lph/c;->a:Ljava/lang/String;

    .line 117
    .line 118
    new-instance v3, Lpg/m;

    .line 119
    .line 120
    const/4 p1, 0x1

    .line 121
    invoke-direct {v3, p0, p1}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    const/4 v4, 0x0

    .line 125
    const/16 v5, 0x16

    .line 126
    .line 127
    const/4 v1, 0x0

    .line 128
    const/4 v2, 0x0

    .line 129
    invoke-static/range {v0 .. v5}, Lqc/a;->a(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/k;Lzb/s0;I)V

    .line 130
    .line 131
    .line 132
    return-void

    .line 133
    :cond_5
    new-instance p0, La8/r0;

    .line 134
    .line 135
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 136
    .line 137
    .line 138
    throw p0
.end method
