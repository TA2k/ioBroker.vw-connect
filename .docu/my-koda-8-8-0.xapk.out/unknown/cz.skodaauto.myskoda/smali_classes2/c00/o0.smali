.class public final Lc00/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/q0;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Lc00/q0;ZI)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/o0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/o0;->e:Lc00/q0;

    .line 4
    .line 5
    iput-boolean p2, p0, Lc00/o0;->f:Z

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget p2, p0, Lc00/o0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/c;

    .line 9
    .line 10
    iget-object v0, p0, Lc00/o0;->e:Lc00/q0;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    move-object v1, p0

    .line 19
    check-cast v1, Lc00/n0;

    .line 20
    .line 21
    check-cast p1, Lne0/c;

    .line 22
    .line 23
    iget-object p0, v0, Lc00/q0;->p:Lij0/a;

    .line 24
    .line 25
    invoke-static {p1, p0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 26
    .line 27
    .line 28
    move-result-object v11

    .line 29
    const/16 v12, 0x1ff

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    const/4 v3, 0x0

    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v7, 0x0

    .line 37
    const/4 v8, 0x0

    .line 38
    const/4 v9, 0x0

    .line 39
    const/4 v10, 0x0

    .line 40
    invoke-static/range {v1 .. v12}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    instance-of p1, p1, Lne0/e;

    .line 46
    .line 47
    if-eqz p1, :cond_1

    .line 48
    .line 49
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    move-object v1, p1

    .line 54
    check-cast v1, Lc00/n0;

    .line 55
    .line 56
    iget-boolean p0, p0, Lc00/o0;->f:Z

    .line 57
    .line 58
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    const/4 v11, 0x0

    .line 63
    const/16 v12, 0x3fd

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    const/4 v4, 0x0

    .line 67
    const/4 v5, 0x0

    .line 68
    const/4 v6, 0x0

    .line 69
    const/4 v7, 0x0

    .line 70
    const/4 v8, 0x0

    .line 71
    const/4 v9, 0x0

    .line 72
    const/4 v10, 0x0

    .line 73
    invoke-static/range {v1 .. v12}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    :goto_0
    invoke-virtual {v0, p0}, Lql0/j;->g(Lql0/h;)V

    .line 78
    .line 79
    .line 80
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_1
    new-instance p0, La8/r0;

    .line 84
    .line 85
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :pswitch_0
    check-cast p1, Lne0/t;

    .line 90
    .line 91
    instance-of p2, p1, Lne0/c;

    .line 92
    .line 93
    iget-object v0, p0, Lc00/o0;->e:Lc00/q0;

    .line 94
    .line 95
    if-eqz p2, :cond_2

    .line 96
    .line 97
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    move-object v1, p0

    .line 102
    check-cast v1, Lc00/n0;

    .line 103
    .line 104
    check-cast p1, Lne0/c;

    .line 105
    .line 106
    iget-object p0, v0, Lc00/q0;->p:Lij0/a;

    .line 107
    .line 108
    invoke-static {p1, p0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 109
    .line 110
    .line 111
    move-result-object v11

    .line 112
    const/16 v12, 0x1ff

    .line 113
    .line 114
    const/4 v2, 0x0

    .line 115
    const/4 v3, 0x0

    .line 116
    const/4 v4, 0x0

    .line 117
    const/4 v5, 0x0

    .line 118
    const/4 v6, 0x0

    .line 119
    const/4 v7, 0x0

    .line 120
    const/4 v8, 0x0

    .line 121
    const/4 v9, 0x0

    .line 122
    const/4 v10, 0x0

    .line 123
    invoke-static/range {v1 .. v12}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    goto :goto_1

    .line 128
    :cond_2
    instance-of p1, p1, Lne0/e;

    .line 129
    .line 130
    if-eqz p1, :cond_3

    .line 131
    .line 132
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    move-object v1, p1

    .line 137
    check-cast v1, Lc00/n0;

    .line 138
    .line 139
    iget-boolean p0, p0, Lc00/o0;->f:Z

    .line 140
    .line 141
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    const/4 v11, 0x0

    .line 146
    const/16 v12, 0x3fe

    .line 147
    .line 148
    const/4 v3, 0x0

    .line 149
    const/4 v4, 0x0

    .line 150
    const/4 v5, 0x0

    .line 151
    const/4 v6, 0x0

    .line 152
    const/4 v7, 0x0

    .line 153
    const/4 v8, 0x0

    .line 154
    const/4 v9, 0x0

    .line 155
    const/4 v10, 0x0

    .line 156
    invoke-static/range {v1 .. v12}, Lc00/n0;->a(Lc00/n0;Ljava/lang/Boolean;Ljava/lang/Boolean;ZZZZZZILql0/g;I)Lc00/n0;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    :goto_1
    invoke-virtual {v0, p0}, Lql0/j;->g(Lql0/h;)V

    .line 161
    .line 162
    .line 163
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    return-object p0

    .line 166
    :cond_3
    new-instance p0, La8/r0;

    .line 167
    .line 168
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 169
    .line 170
    .line 171
    throw p0

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
