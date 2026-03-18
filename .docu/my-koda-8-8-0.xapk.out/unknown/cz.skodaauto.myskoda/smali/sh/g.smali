.class public final Lsh/g;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lsh/h;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1}, Lsh/h;-><init>(ZZ)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lsh/g;->d:Lyy0/c2;

    .line 15
    .line 16
    new-instance v1, Lag/r;

    .line 17
    .line 18
    const/16 v2, 0xe

    .line 19
    .line 20
    invoke-direct {v1, v0, v2}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lsh/h;

    .line 32
    .line 33
    const-string v3, "<this>"

    .line 34
    .line 35
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v3, Lsh/e;

    .line 39
    .line 40
    iget-boolean v4, v0, Lsh/h;->a:Z

    .line 41
    .line 42
    iget-boolean v0, v0, Lsh/h;->b:Z

    .line 43
    .line 44
    invoke-direct {v3, v4, v0}, Lsh/e;-><init>(ZZ)V

    .line 45
    .line 46
    .line 47
    sget-object v0, Lyy0/u1;->a:Lyy0/w1;

    .line 48
    .line 49
    invoke-static {v1, v2, v0, v3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    iput-object v0, p0, Lsh/g;->e:Lyy0/l1;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final a(Lsh/d;)V
    .locals 3

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lsh/c;->a:Lsh/c;

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
    iget-object p0, p0, Lsh/g;->d:Lyy0/c2;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    move-object v0, p1

    .line 26
    check-cast v0, Lsh/h;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    new-instance v0, Lsh/h;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, v1}, Lsh/h;-><init>(ZZ)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    sget-object v0, Lsh/a;->a:Lsh/a;

    .line 45
    .line 46
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    const/4 v2, 0x1

    .line 51
    if-eqz v0, :cond_3

    .line 52
    .line 53
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    move-object v0, p1

    .line 61
    check-cast v0, Lsh/h;

    .line 62
    .line 63
    iget-boolean v1, v0, Lsh/h;->b:Z

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    new-instance v0, Lsh/h;

    .line 69
    .line 70
    invoke-direct {v0, v2, v1}, Lsh/h;-><init>(ZZ)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    if-eqz p1, :cond_2

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    sget-object v0, Lsh/b;->a:Lsh/b;

    .line 81
    .line 82
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_5

    .line 87
    .line 88
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    :cond_4
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    move-object v0, p1

    .line 96
    check-cast v0, Lsh/h;

    .line 97
    .line 98
    iget-boolean v1, v0, Lsh/h;->a:Z

    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    new-instance v0, Lsh/h;

    .line 104
    .line 105
    invoke-direct {v0, v1, v2}, Lsh/h;-><init>(ZZ)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    if-eqz p1, :cond_4

    .line 113
    .line 114
    :goto_0
    return-void

    .line 115
    :cond_5
    new-instance p0, La8/r0;

    .line 116
    .line 117
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 118
    .line 119
    .line 120
    throw p0
.end method
