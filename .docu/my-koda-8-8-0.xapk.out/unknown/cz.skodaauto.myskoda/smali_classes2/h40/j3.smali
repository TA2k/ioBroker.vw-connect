.class public final Lh40/j3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/d2;


# direct methods
.method public constructor <init>(Ltr0/b;Lf40/d2;Lf40/d0;Lij0/a;Lf40/x0;)V
    .locals 3

    .line 1
    new-instance v0, Lh40/i3;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const-string v2, ""

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lh40/i3;-><init>(Ljava/util/List;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lh40/j3;->h:Ltr0/b;

    .line 14
    .line 15
    iput-object p2, p0, Lh40/j3;->i:Lf40/d2;

    .line 16
    .line 17
    invoke-virtual {p5}, Lf40/x0;->invoke()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Ljava/lang/Boolean;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move p1, p2

    .line 32
    :goto_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object p5

    .line 36
    check-cast p5, Lh40/i3;

    .line 37
    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    const p1, 0x7f120d0d

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    const p1, 0x7f120d0e

    .line 45
    .line 46
    .line 47
    :goto_1
    new-array p2, p2, [Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p4, Ljj0/f;

    .line 50
    .line 51
    invoke-virtual {p4, p1, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    const/4 p2, 0x1

    .line 56
    const/4 p4, 0x0

    .line 57
    invoke-static {p5, p4, p1, p2}, Lh40/i3;->a(Lh40/i3;Ljava/util/ArrayList;Ljava/lang/String;I)Lh40/i3;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p3}, Lf40/d0;->invoke()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, Lg40/k0;

    .line 69
    .line 70
    if-eqz p1, :cond_3

    .line 71
    .line 72
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    check-cast p2, Lh40/i3;

    .line 77
    .line 78
    iget-object p1, p1, Lg40/k0;->c:Ljava/util/ArrayList;

    .line 79
    .line 80
    new-instance p3, Ljava/util/ArrayList;

    .line 81
    .line 82
    const/16 p5, 0xa

    .line 83
    .line 84
    invoke-static {p1, p5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 85
    .line 86
    .line 87
    move-result p5

    .line 88
    invoke-direct {p3, p5}, Ljava/util/ArrayList;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result p5

    .line 99
    if-eqz p5, :cond_2

    .line 100
    .line 101
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p5

    .line 105
    check-cast p5, Lg40/w0;

    .line 106
    .line 107
    new-instance v0, Lh40/h3;

    .line 108
    .line 109
    iget-object v1, p5, Lg40/w0;->c:Ljava/lang/String;

    .line 110
    .line 111
    iget p5, p5, Lg40/w0;->d:I

    .line 112
    .line 113
    invoke-direct {v0, v1, p5}, Lh40/h3;-><init>(Ljava/lang/String;I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_2
    const/4 p1, 0x2

    .line 121
    invoke-static {p2, p3, p4, p1}, Lh40/i3;->a(Lh40/i3;Ljava/util/ArrayList;Ljava/lang/String;I)Lh40/i3;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 126
    .line 127
    .line 128
    :cond_3
    return-void
.end method
