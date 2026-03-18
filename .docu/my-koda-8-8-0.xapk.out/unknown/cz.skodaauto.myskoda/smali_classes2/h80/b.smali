.class public final Lh80/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf80/b;

.field public final j:Lbd0/c;

.field public final k:Lij0/a;

.field public final l:Lg80/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lf80/b;Lbd0/c;Lij0/a;Lf80/e;Lf80/d;)V
    .locals 8

    .line 1
    new-instance v0, Lh80/a;

    .line 2
    .line 3
    const/4 v5, 0x1

    .line 4
    const/4 v6, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const-string v2, ""

    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct/range {v0 .. v6}, Lh80/a;-><init>(Lql0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lh80/b;->h:Ltr0/b;

    .line 17
    .line 18
    iput-object p2, p0, Lh80/b;->i:Lf80/b;

    .line 19
    .line 20
    iput-object p3, p0, Lh80/b;->j:Lbd0/c;

    .line 21
    .line 22
    iput-object p4, p0, Lh80/b;->k:Lij0/a;

    .line 23
    .line 24
    invoke-virtual {p5}, Lf80/e;->invoke()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Lne0/t;

    .line 29
    .line 30
    instance-of p2, p1, Lne0/e;

    .line 31
    .line 32
    if-eqz p2, :cond_3

    .line 33
    .line 34
    check-cast p1, Lne0/e;

    .line 35
    .line 36
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lg80/a;

    .line 39
    .line 40
    iput-object p1, p0, Lh80/b;->l:Lg80/a;

    .line 41
    .line 42
    const/4 p2, 0x0

    .line 43
    if-eqz p1, :cond_2

    .line 44
    .line 45
    iget-object p1, p1, Lg80/a;->f:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p6}, Lf80/d;->invoke()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p3

    .line 51
    check-cast p3, Lg80/d;

    .line 52
    .line 53
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 54
    .line 55
    .line 56
    move-result-object p4

    .line 57
    move-object v0, p4

    .line 58
    check-cast v0, Lh80/a;

    .line 59
    .line 60
    const-string p4, "\n"

    .line 61
    .line 62
    const/4 p5, 0x0

    .line 63
    const-string p6, "<br>"

    .line 64
    .line 65
    invoke-static {p5, p1, p6, p4}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    if-eqz p3, :cond_0

    .line 70
    .line 71
    iget-object p1, p3, Lg80/d;->b:Ljava/lang/String;

    .line 72
    .line 73
    move-object v3, p1

    .line 74
    goto :goto_0

    .line 75
    :cond_0
    move-object v3, p2

    .line 76
    :goto_0
    if-eqz p3, :cond_1

    .line 77
    .line 78
    iget-object p2, p3, Lg80/d;->c:Ljava/lang/String;

    .line 79
    .line 80
    :cond_1
    move-object v4, p2

    .line 81
    const/4 v6, 0x0

    .line 82
    const/16 v7, 0x31

    .line 83
    .line 84
    const/4 v1, 0x0

    .line 85
    const/4 v5, 0x0

    .line 86
    invoke-static/range {v0 .. v7}, Lh80/a;->a(Lh80/a;Lql0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZI)Lh80/a;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    goto :goto_1

    .line 91
    :cond_2
    const-string p0, "selectedLoyaltyProduct"

    .line 92
    .line 93
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p2

    .line 97
    :cond_3
    instance-of p2, p1, Lne0/c;

    .line 98
    .line 99
    if-eqz p2, :cond_4

    .line 100
    .line 101
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 102
    .line 103
    .line 104
    move-result-object p2

    .line 105
    move-object v0, p2

    .line 106
    check-cast v0, Lh80/a;

    .line 107
    .line 108
    check-cast p1, Lne0/c;

    .line 109
    .line 110
    invoke-static {p1, p4}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    const/4 v6, 0x0

    .line 115
    const/16 v7, 0x3e

    .line 116
    .line 117
    const/4 v2, 0x0

    .line 118
    const/4 v3, 0x0

    .line 119
    const/4 v4, 0x0

    .line 120
    const/4 v5, 0x0

    .line 121
    invoke-static/range {v0 .. v7}, Lh80/a;->a(Lh80/a;Lql0/g;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZI)Lh80/a;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    :goto_1
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 126
    .line 127
    .line 128
    return-void

    .line 129
    :cond_4
    new-instance p0, La8/r0;

    .line 130
    .line 131
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 132
    .line 133
    .line 134
    throw p0
.end method
