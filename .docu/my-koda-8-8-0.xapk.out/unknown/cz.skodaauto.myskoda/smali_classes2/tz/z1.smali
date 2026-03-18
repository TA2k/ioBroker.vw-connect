.class public final Ltz/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/i2;


# direct methods
.method public synthetic constructor <init>(Ltz/i2;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltz/z1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/z1;->e:Ltz/i2;

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
    .locals 9

    .line 1
    iget p2, p0, Ltz/z1;->d:I

    .line 2
    .line 3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Ltz/z1;->e:Ltz/i2;

    .line 6
    .line 7
    packed-switch p2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Lne0/s;

    .line 11
    .line 12
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 13
    .line 14
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-nez p2, :cond_3

    .line 19
    .line 20
    instance-of p2, p1, Lne0/c;

    .line 21
    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 26
    .line 27
    if-eqz p2, :cond_2

    .line 28
    .line 29
    sget-object p2, Ltz/i2;->v:Lhl0/b;

    .line 30
    .line 31
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    move-object v1, p2

    .line 36
    check-cast v1, Ltz/f2;

    .line 37
    .line 38
    check-cast p1, Lne0/e;

    .line 39
    .line 40
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Ljava/lang/Iterable;

    .line 43
    .line 44
    new-instance v2, Ljava/util/ArrayList;

    .line 45
    .line 46
    const/16 p2, 0xa

    .line 47
    .line 48
    invoke-static {p1, p2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    invoke-direct {v2, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 53
    .line 54
    .line 55
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    if-eqz p2, :cond_1

    .line 64
    .line 65
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    check-cast p2, Lrd0/p;

    .line 70
    .line 71
    const-string v3, "<this>"

    .line 72
    .line 73
    invoke-static {p2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    new-instance v3, Lxj0/f;

    .line 77
    .line 78
    iget-wide v4, p2, Lrd0/p;->a:D

    .line 79
    .line 80
    iget-wide v6, p2, Lrd0/p;->b:D

    .line 81
    .line 82
    invoke-direct {v3, v4, v5, v6, v7}, Lxj0/f;-><init>(DD)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_1
    const/4 v7, 0x0

    .line 90
    const/16 v8, 0x3e

    .line 91
    .line 92
    const/4 v3, 0x0

    .line 93
    const/4 v4, 0x0

    .line 94
    const/4 v5, 0x0

    .line 95
    const/4 v6, 0x0

    .line 96
    invoke-static/range {v1 .. v8}, Ltz/f2;->a(Ltz/f2;Ljava/util/List;Lxj0/f;Ljava/lang/String;ZZZI)Ltz/f2;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    goto :goto_2

    .line 101
    :cond_2
    new-instance p0, La8/r0;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_3
    :goto_1
    sget-object p1, Ltz/i2;->v:Lhl0/b;

    .line 108
    .line 109
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    move-object v1, p1

    .line 114
    check-cast v1, Ltz/f2;

    .line 115
    .line 116
    const/4 v7, 0x0

    .line 117
    const/16 v8, 0x3e

    .line 118
    .line 119
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 120
    .line 121
    const/4 v3, 0x0

    .line 122
    const/4 v4, 0x0

    .line 123
    const/4 v5, 0x0

    .line 124
    const/4 v6, 0x0

    .line 125
    invoke-static/range {v1 .. v8}, Ltz/f2;->a(Ltz/f2;Ljava/util/List;Lxj0/f;Ljava/lang/String;ZZZI)Ltz/f2;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    :goto_2
    sget-object p2, Ltz/i2;->v:Lhl0/b;

    .line 130
    .line 131
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 132
    .line 133
    .line 134
    return-object v0

    .line 135
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 136
    .line 137
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    sget-object p1, Ltz/i2;->v:Lhl0/b;

    .line 142
    .line 143
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    move-object v1, p1

    .line 148
    check-cast v1, Ltz/f2;

    .line 149
    .line 150
    const/4 v7, 0x0

    .line 151
    const/16 v8, 0x37

    .line 152
    .line 153
    const/4 v2, 0x0

    .line 154
    const/4 v3, 0x0

    .line 155
    const/4 v4, 0x0

    .line 156
    const/4 v6, 0x0

    .line 157
    invoke-static/range {v1 .. v8}, Ltz/f2;->a(Ltz/f2;Ljava/util/List;Lxj0/f;Ljava/lang/String;ZZZI)Ltz/f2;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 162
    .line 163
    .line 164
    if-eqz v5, :cond_4

    .line 165
    .line 166
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    new-instance p2, Ltz/a2;

    .line 171
    .line 172
    const/4 v1, 0x5

    .line 173
    const/4 v2, 0x0

    .line 174
    invoke-direct {p2, p0, v2, v1}, Ltz/a2;-><init>(Ltz/i2;Lkotlin/coroutines/Continuation;I)V

    .line 175
    .line 176
    .line 177
    const/4 p0, 0x3

    .line 178
    invoke-static {p1, v2, v2, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 179
    .line 180
    .line 181
    :cond_4
    return-object v0

    .line 182
    nop

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
