.class public final Luh/g;
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
    new-instance v0, Luh/h;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1, v1}, Luh/h;-><init>(ZZ)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Luh/g;->d:Lyy0/c2;

    .line 15
    .line 16
    new-instance v1, Lag/r;

    .line 17
    .line 18
    const/16 v2, 0x10

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
    check-cast v0, Luh/h;

    .line 32
    .line 33
    const-string v3, "<this>"

    .line 34
    .line 35
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    new-instance v3, Luh/e;

    .line 39
    .line 40
    iget-boolean v4, v0, Luh/h;->a:Z

    .line 41
    .line 42
    iget-boolean v0, v0, Luh/h;->b:Z

    .line 43
    .line 44
    invoke-direct {v3, v4, v0}, Luh/e;-><init>(ZZ)V

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
    iput-object v0, p0, Luh/g;->e:Lyy0/l1;

    .line 54
    .line 55
    return-void
.end method


# virtual methods
.method public final a(Luh/d;)V
    .locals 3

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Luh/a;->a:Luh/a;

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
    const-string v2, "<this>"

    .line 14
    .line 15
    iget-object p0, p0, Luh/g;->d:Lyy0/c2;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    move-object v0, p1

    .line 27
    check-cast v0, Luh/h;

    .line 28
    .line 29
    iget-boolean v2, v0, Luh/h;->b:Z

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    new-instance v0, Luh/h;

    .line 35
    .line 36
    invoke-direct {v0, v1, v2}, Luh/h;-><init>(ZZ)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-eqz p1, :cond_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    sget-object v0, Luh/b;->a:Luh/b;

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    :cond_2
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    move-object v0, p1

    .line 62
    check-cast v0, Luh/h;

    .line 63
    .line 64
    iget-boolean v2, v0, Luh/h;->a:Z

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    new-instance v0, Luh/h;

    .line 70
    .line 71
    invoke-direct {v0, v2, v1}, Luh/h;-><init>(ZZ)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    if-eqz p1, :cond_2

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_3
    sget-object v0, Luh/c;->a:Luh/c;

    .line 82
    .line 83
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    if-eqz p1, :cond_5

    .line 88
    .line 89
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    :cond_4
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    move-object v0, p1

    .line 97
    check-cast v0, Luh/h;

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    new-instance v0, Luh/h;

    .line 103
    .line 104
    const/4 v1, 0x0

    .line 105
    invoke-direct {v0, v1, v1}, Luh/h;-><init>(ZZ)V

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
