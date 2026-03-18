.class public final Lc00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/h;


# direct methods
.method public synthetic constructor <init>(Lc00/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc00/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/b;->e:Lc00/h;

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
    .locals 11

    .line 1
    iget v0, p0, Lc00/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of v0, p1, Lne0/c;

    .line 9
    .line 10
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object p0, p0, Lc00/b;->e:Lc00/h;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lc00/h;->q:Ljn0/c;

    .line 17
    .line 18
    check-cast p1, Lne0/c;

    .line 19
    .line 20
    invoke-virtual {p0, p1, p2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 25
    .line 26
    if-ne p0, p1, :cond_1

    .line 27
    .line 28
    move-object v1, p0

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    instance-of p1, p1, Lne0/e;

    .line 31
    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lc00/c;

    .line 39
    .line 40
    iget-object p2, p0, Lc00/h;->l:Lij0/a;

    .line 41
    .line 42
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 43
    .line 44
    invoke-static {p1, p2, v0}, Ljp/wb;->e(Lc00/c;Lij0/a;Ljava/lang/Boolean;)Lc00/c;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    :goto_0
    return-object v1

    .line 52
    :cond_2
    new-instance p0, La8/r0;

    .line 53
    .line 54
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :pswitch_0
    check-cast p1, Lne0/t;

    .line 59
    .line 60
    instance-of v0, p1, Lne0/c;

    .line 61
    .line 62
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    iget-object p0, p0, Lc00/b;->e:Lc00/h;

    .line 65
    .line 66
    if-eqz v0, :cond_3

    .line 67
    .line 68
    iget-object p0, p0, Lc00/h;->q:Ljn0/c;

    .line 69
    .line 70
    check-cast p1, Lne0/c;

    .line 71
    .line 72
    invoke-virtual {p0, p1, p2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 77
    .line 78
    if-ne p0, p1, :cond_4

    .line 79
    .line 80
    move-object v1, p0

    .line 81
    goto :goto_1

    .line 82
    :cond_3
    instance-of p1, p1, Lne0/e;

    .line 83
    .line 84
    if-eqz p1, :cond_5

    .line 85
    .line 86
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    check-cast p1, Lc00/c;

    .line 91
    .line 92
    iget-object p2, p0, Lc00/h;->l:Lij0/a;

    .line 93
    .line 94
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 95
    .line 96
    invoke-static {p1, p2, v0}, Ljp/wb;->e(Lc00/c;Lij0/a;Ljava/lang/Boolean;)Lc00/c;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 101
    .line 102
    .line 103
    :cond_4
    :goto_1
    return-object v1

    .line 104
    :cond_5
    new-instance p0, La8/r0;

    .line 105
    .line 106
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 107
    .line 108
    .line 109
    throw p0

    .line 110
    :pswitch_1
    check-cast p1, Lss0/j0;

    .line 111
    .line 112
    new-instance p1, Lc00/c;

    .line 113
    .line 114
    const/4 p2, 0x0

    .line 115
    const/16 v0, 0x3ff

    .line 116
    .line 117
    invoke-direct {p1, v0, p2, p2}, Lc00/c;-><init>(ILjava/lang/String;Llf0/i;)V

    .line 118
    .line 119
    .line 120
    iget-object p0, p0, Lc00/b;->e:Lc00/h;

    .line 121
    .line 122
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 123
    .line 124
    .line 125
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_2
    check-cast p1, Ljava/lang/Boolean;

    .line 129
    .line 130
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 131
    .line 132
    .line 133
    move-result v7

    .line 134
    iget-object p0, p0, Lc00/b;->e:Lc00/h;

    .line 135
    .line 136
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    move-object v0, p1

    .line 141
    check-cast v0, Lc00/c;

    .line 142
    .line 143
    const/4 v9, 0x0

    .line 144
    const/16 v10, 0x37f

    .line 145
    .line 146
    const/4 v1, 0x0

    .line 147
    const/4 v2, 0x0

    .line 148
    const/4 v3, 0x0

    .line 149
    const/4 v4, 0x0

    .line 150
    const/4 v5, 0x0

    .line 151
    const/4 v6, 0x0

    .line 152
    const/4 v8, 0x0

    .line 153
    invoke-static/range {v0 .. v10}, Lc00/c;->a(Lc00/c;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;ZI)Lc00/c;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 158
    .line 159
    .line 160
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    return-object p0

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
