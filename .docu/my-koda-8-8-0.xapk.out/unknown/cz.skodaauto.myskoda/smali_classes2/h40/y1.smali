.class public final Lh40/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/z1;


# direct methods
.method public synthetic constructor <init>(Lh40/z1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/y1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/y1;->e:Lh40/z1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p2, p0, Lh40/y1;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/y1;->e:Lh40/z1;

    .line 9
    .line 10
    invoke-static {p0}, Lh40/z1;->h(Lh40/z1;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 17
    .line 18
    instance-of p2, p1, Lne0/c;

    .line 19
    .line 20
    iget-object p0, p0, Lh40/y1;->e:Lh40/z1;

    .line 21
    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    move-object v0, p2

    .line 29
    check-cast v0, Lh40/u1;

    .line 30
    .line 31
    const/4 v8, 0x0

    .line 32
    const/16 v9, 0xfb

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v7, 0x0

    .line 41
    invoke-static/range {v0 .. v9}, Lh40/u1;->a(Lh40/u1;Lh40/z;ZZLql0/g;ZZZZI)Lh40/u1;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    new-instance v0, Lg60/w;

    .line 53
    .line 54
    invoke-direct {v0, p0, p1, v1}, Lg60/w;-><init>(Lh40/z1;Lne0/s;Lkotlin/coroutines/Continuation;)V

    .line 55
    .line 56
    .line 57
    const/4 p0, 0x3

    .line 58
    invoke-static {p2, v1, v1, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 63
    .line 64
    if-eqz p2, :cond_1

    .line 65
    .line 66
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    move-object v0, p1

    .line 71
    check-cast v0, Lh40/u1;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    const/16 v9, 0xfb

    .line 75
    .line 76
    const/4 v1, 0x0

    .line 77
    const/4 v2, 0x0

    .line 78
    const/4 v3, 0x0

    .line 79
    const/4 v4, 0x0

    .line 80
    const/4 v5, 0x0

    .line 81
    const/4 v6, 0x0

    .line 82
    const/4 v7, 0x0

    .line 83
    invoke-static/range {v0 .. v9}, Lh40/u1;->a(Lh40/u1;Lh40/z;ZZLql0/g;ZZZZI)Lh40/u1;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 88
    .line 89
    .line 90
    invoke-static {p0}, Lh40/z1;->h(Lh40/z1;)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_1
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 95
    .line 96
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-eqz p1, :cond_2

    .line 101
    .line 102
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    move-object v0, p1

    .line 107
    check-cast v0, Lh40/u1;

    .line 108
    .line 109
    const/4 v8, 0x0

    .line 110
    const/16 v9, 0xfb

    .line 111
    .line 112
    const/4 v1, 0x0

    .line 113
    const/4 v2, 0x0

    .line 114
    const/4 v3, 0x1

    .line 115
    const/4 v4, 0x0

    .line 116
    const/4 v5, 0x0

    .line 117
    const/4 v6, 0x0

    .line 118
    const/4 v7, 0x0

    .line 119
    invoke-static/range {v0 .. v9}, Lh40/u1;->a(Lh40/u1;Lh40/z;ZZLql0/g;ZZZZI)Lh40/u1;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 124
    .line 125
    .line 126
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    return-object p0

    .line 129
    :cond_2
    new-instance p0, La8/r0;

    .line 130
    .line 131
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 132
    .line 133
    .line 134
    throw p0

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
