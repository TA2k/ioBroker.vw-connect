.class public final Le2/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Le2/y;->d:I

    iput-object p2, p0, Le2/y;->e:Ljava/lang/Object;

    iput-object p3, p0, Le2/y;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lt1/w0;Le2/w0;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Le2/y;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/y;->f:Ljava/lang/Object;

    iput-object p2, p0, Le2/y;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Le2/y;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lff/a;

    .line 7
    .line 8
    iget-object v0, p0, Le2/y;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v4, v0

    .line 11
    check-cast v4, Lt1/w0;

    .line 12
    .line 13
    iget-object p0, p0, Le2/y;->e:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v5, p0

    .line 16
    check-cast v5, Le2/w0;

    .line 17
    .line 18
    const/16 v7, 0xa

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v6, 0x0

    .line 22
    move-object v2, p1

    .line 23
    invoke-direct/range {v1 .. v7}, Lff/a;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v1, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    if-ne p0, p1, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    :goto_0
    return-object p0

    .line 38
    :pswitch_0
    move-object v2, p1

    .line 39
    iget-object p1, p0, Le2/y;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Ll2/b1;

    .line 42
    .line 43
    iget-object p0, p0, Le2/y;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lay0/k;

    .line 46
    .line 47
    new-instance v0, Lmg/d;

    .line 48
    .line 49
    const/4 v1, 0x4

    .line 50
    invoke-direct {v0, p1, p0, v1}, Lmg/d;-><init>(Ll2/b1;Lay0/k;I)V

    .line 51
    .line 52
    .line 53
    const/4 p0, 0x7

    .line 54
    const/4 p1, 0x0

    .line 55
    invoke-static {v2, p1, v0, p2, p0}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    if-ne p0, p1, :cond_1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    :goto_1
    return-object p0

    .line 67
    :pswitch_1
    move-object v2, p1

    .line 68
    iget-object p1, p0, Le2/y;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p1, Ll2/b1;

    .line 71
    .line 72
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Ljava/lang/Boolean;

    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-nez v0, :cond_2

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_2
    new-instance v0, Lg1/l1;

    .line 86
    .line 87
    iget-object p0, p0, Le2/y;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast p0, Li91/l1;

    .line 90
    .line 91
    const/4 v1, 0x0

    .line 92
    const/4 v3, 0x3

    .line 93
    invoke-direct {v0, v3, p1, p0, v1}, Lg1/l1;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v2, v0, p2}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 101
    .line 102
    if-ne p0, p1, :cond_3

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_3
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    :goto_3
    return-object p0

    .line 108
    :pswitch_2
    move-object v2, p1

    .line 109
    iget-object p1, p0, Le2/y;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Ll2/t2;

    .line 112
    .line 113
    iget-object p0, p0, Le2/y;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p0, Lay0/k;

    .line 116
    .line 117
    new-instance v0, Let/g;

    .line 118
    .line 119
    const/16 v1, 0x18

    .line 120
    .line 121
    invoke-direct {v0, v1, p1, p0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    const/4 p0, 0x7

    .line 125
    const/4 p1, 0x0

    .line 126
    invoke-static {v2, p1, v0, p2, p0}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 131
    .line 132
    if-ne p0, p1, :cond_4

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    :goto_4
    return-object p0

    .line 138
    :pswitch_3
    move-object v2, p1

    .line 139
    new-instance v6, Lbb/g0;

    .line 140
    .line 141
    move-object p1, v2

    .line 142
    check-cast p1, Lp3/j0;

    .line 143
    .line 144
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    iget-object p1, p1, Lv3/h0;->C:Lw3/h2;

    .line 152
    .line 153
    invoke-direct {v6, p1}, Lbb/g0;-><init>(Lw3/h2;)V

    .line 154
    .line 155
    .line 156
    new-instance v3, Lb2/a;

    .line 157
    .line 158
    iget-object p1, p0, Le2/y;->e:Ljava/lang/Object;

    .line 159
    .line 160
    move-object v5, p1

    .line 161
    check-cast v5, Lcom/google/android/gms/internal/measurement/i4;

    .line 162
    .line 163
    iget-object p0, p0, Le2/y;->f:Ljava/lang/Object;

    .line 164
    .line 165
    move-object v7, p0

    .line 166
    check-cast v7, Lt1/w0;

    .line 167
    .line 168
    const/4 v8, 0x0

    .line 169
    const/4 v4, 0x1

    .line 170
    invoke-direct/range {v3 .. v8}, Lb2/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 171
    .line 172
    .line 173
    invoke-static {v2, v3, p2}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    if-ne p0, p1, :cond_5

    .line 180
    .line 181
    goto :goto_5

    .line 182
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    :goto_5
    return-object p0

    .line 185
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
