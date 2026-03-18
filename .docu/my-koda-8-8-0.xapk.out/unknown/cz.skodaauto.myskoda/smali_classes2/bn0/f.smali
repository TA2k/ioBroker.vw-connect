.class public final Lbn0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/i;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lbn0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbn0/f;->e:Lyy0/i;

    .line 4
    .line 5
    iput-object p2, p0, Lbn0/f;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lbn0/f;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lbn0/f;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    iget-object v3, p0, Lbn0/f;->g:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object v4, p0, Lbn0/f;->f:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object p0, p0, Lbn0/f;->e:Lyy0/i;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast v4, Lyy0/i;

    .line 16
    .line 17
    new-array v0, v1, [Lyy0/i;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    aput-object p0, v0, v1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    aput-object v4, v0, p0

    .line 24
    .line 25
    new-instance p0, Lyy0/g1;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {p0, v3, v1}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    sget-object v1, Lyy0/h1;->d:Lyy0/h1;

    .line 32
    .line 33
    invoke-static {v1, p0, p2, p1, v0}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    if-ne p0, p1, :cond_0

    .line 40
    .line 41
    move-object v2, p0

    .line 42
    :cond_0
    return-object v2

    .line 43
    :pswitch_0
    new-instance v0, Laa/h0;

    .line 44
    .line 45
    check-cast v4, Ljava/util/Set;

    .line 46
    .line 47
    check-cast v3, Lve0/u;

    .line 48
    .line 49
    const/16 v1, 0xc

    .line 50
    .line 51
    invoke-direct {v0, p1, v4, v3, v1}, Laa/h0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 59
    .line 60
    if-ne p0, p1, :cond_1

    .line 61
    .line 62
    move-object v2, p0

    .line 63
    :cond_1
    return-object v2

    .line 64
    :pswitch_1
    check-cast p0, Lrz/k;

    .line 65
    .line 66
    new-instance v0, Laa/h0;

    .line 67
    .line 68
    check-cast v4, Lq10/q;

    .line 69
    .line 70
    check-cast v3, Lmc/e;

    .line 71
    .line 72
    const/16 v1, 0xa

    .line 73
    .line 74
    invoke-direct {v0, p1, v4, v3, v1}, Laa/h0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0, v0, p2}, Lrz/k;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    if-ne p0, p1, :cond_2

    .line 84
    .line 85
    move-object v2, p0

    .line 86
    :cond_2
    return-object v2

    .line 87
    :pswitch_2
    check-cast p0, Lyy0/m1;

    .line 88
    .line 89
    new-instance v0, Laa/h0;

    .line 90
    .line 91
    check-cast v4, Lif0/f0;

    .line 92
    .line 93
    check-cast v3, Ljava/lang/String;

    .line 94
    .line 95
    const/4 v1, 0x7

    .line 96
    invoke-direct {v0, p1, v4, v3, v1}, Laa/h0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p0, v0, p2}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 104
    .line 105
    if-ne p0, p1, :cond_3

    .line 106
    .line 107
    move-object v2, p0

    .line 108
    :cond_3
    return-object v2

    .line 109
    :pswitch_3
    new-instance v0, Laa/h0;

    .line 110
    .line 111
    check-cast v4, Liv0/f;

    .line 112
    .line 113
    check-cast v3, Lhv0/q;

    .line 114
    .line 115
    const/4 v1, 0x6

    .line 116
    invoke-direct {v0, p1, v4, v3, v1}, Laa/h0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 117
    .line 118
    .line 119
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 124
    .line 125
    if-ne p0, p1, :cond_4

    .line 126
    .line 127
    move-object v2, p0

    .line 128
    :cond_4
    return-object v2

    .line 129
    :pswitch_4
    check-cast p0, Lyy0/m1;

    .line 130
    .line 131
    new-instance v0, Laa/h0;

    .line 132
    .line 133
    check-cast v4, Lbn0/g;

    .line 134
    .line 135
    check-cast v3, Lcn0/f;

    .line 136
    .line 137
    invoke-direct {v0, p1, v4, v3, v1}, Laa/h0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0, v0, p2}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 145
    .line 146
    if-ne p0, p1, :cond_5

    .line 147
    .line 148
    move-object v2, p0

    .line 149
    :cond_5
    return-object v2

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
