.class public final Lse/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lse/f;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v1}, Lse/f;-><init>(ZZZ)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lse/g;->d:Lyy0/c2;

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    new-instance v3, Lse/f;

    .line 21
    .line 22
    invoke-direct {v3, v1, v1, v1}, Lse/f;-><init>(ZZZ)V

    .line 23
    .line 24
    .line 25
    sget-object v1, Lyy0/u1;->a:Lyy0/w1;

    .line 26
    .line 27
    invoke-static {v0, v2, v1, v3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput-object v0, p0, Lse/g;->e:Lyy0/l1;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public final a(Lse/e;)V
    .locals 3

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lse/b;->a:Lse/b;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x1

    .line 13
    const/4 v2, 0x0

    .line 14
    iget-object p0, p0, Lse/g;->d:Lyy0/c2;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    move-object v0, p1

    .line 23
    check-cast v0, Lse/f;

    .line 24
    .line 25
    new-instance v0, Lse/f;

    .line 26
    .line 27
    invoke-direct {v0, v1, v2, v2}, Lse/f;-><init>(ZZZ)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-eqz p1, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    sget-object v0, Lse/c;->a:Lse/c;

    .line 38
    .line 39
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    :cond_2
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    move-object v0, p1

    .line 50
    check-cast v0, Lse/f;

    .line 51
    .line 52
    new-instance v0, Lse/f;

    .line 53
    .line 54
    invoke-direct {v0, v2, v1, v2}, Lse/f;-><init>(ZZZ)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-eqz p1, :cond_2

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_3
    sget-object v0, Lse/a;->a:Lse/a;

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_5

    .line 71
    .line 72
    :cond_4
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    move-object v0, p1

    .line 77
    check-cast v0, Lse/f;

    .line 78
    .line 79
    new-instance v0, Lse/f;

    .line 80
    .line 81
    invoke-direct {v0, v2, v2, v1}, Lse/f;-><init>(ZZZ)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    if-eqz p1, :cond_4

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_5
    sget-object v0, Lse/d;->a:Lse/d;

    .line 92
    .line 93
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-eqz p1, :cond_7

    .line 98
    .line 99
    :cond_6
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    move-object v0, p1

    .line 104
    check-cast v0, Lse/f;

    .line 105
    .line 106
    new-instance v0, Lse/f;

    .line 107
    .line 108
    invoke-direct {v0, v2, v2, v2}, Lse/f;-><init>(ZZZ)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    if-eqz p1, :cond_6

    .line 116
    .line 117
    :goto_0
    return-void

    .line 118
    :cond_7
    new-instance p0, La8/r0;

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 121
    .line 122
    .line 123
    throw p0
.end method
