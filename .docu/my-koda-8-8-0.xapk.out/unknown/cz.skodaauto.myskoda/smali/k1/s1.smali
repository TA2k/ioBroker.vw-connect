.class public final Lk1/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lk1/s1;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Lk1/s1;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 5
    .line 6
    const v2, 0x15733969

    .line 7
    .line 8
    .line 9
    packed-switch p0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p1, Lx2/s;

    .line 13
    .line 14
    check-cast p2, Ll2/o;

    .line 15
    .line 16
    check-cast p3, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    check-cast p2, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 27
    .line 28
    invoke-static {p2}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p3

    .line 40
    if-nez p1, :cond_0

    .line 41
    .line 42
    if-ne p3, v1, :cond_1

    .line 43
    .line 44
    :cond_0
    iget-object p0, p0, Lk1/r1;->f:Lk1/b;

    .line 45
    .line 46
    new-instance p3, Lk1/n0;

    .line 47
    .line 48
    invoke-direct {p3, p0}, Lk1/n0;-><init>(Lk1/q1;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    check-cast p3, Lk1/n0;

    .line 55
    .line 56
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 57
    .line 58
    .line 59
    return-object p3

    .line 60
    :pswitch_0
    check-cast p1, Lx2/s;

    .line 61
    .line 62
    check-cast p2, Ll2/o;

    .line 63
    .line 64
    check-cast p3, Ljava/lang/Number;

    .line 65
    .line 66
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 67
    .line 68
    .line 69
    check-cast p2, Ll2/t;

    .line 70
    .line 71
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 75
    .line 76
    invoke-static {p2}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p3

    .line 88
    if-nez p1, :cond_2

    .line 89
    .line 90
    if-ne p3, v1, :cond_3

    .line 91
    .line 92
    :cond_2
    iget-object p0, p0, Lk1/r1;->k:Lk1/l1;

    .line 93
    .line 94
    new-instance p3, Lk1/n0;

    .line 95
    .line 96
    invoke-direct {p3, p0}, Lk1/n0;-><init>(Lk1/q1;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :cond_3
    check-cast p3, Lk1/n0;

    .line 103
    .line 104
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 105
    .line 106
    .line 107
    return-object p3

    .line 108
    :pswitch_1
    check-cast p1, Lx2/s;

    .line 109
    .line 110
    check-cast p2, Ll2/o;

    .line 111
    .line 112
    check-cast p3, Ljava/lang/Number;

    .line 113
    .line 114
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 115
    .line 116
    .line 117
    check-cast p2, Ll2/t;

    .line 118
    .line 119
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 120
    .line 121
    .line 122
    sget-object p0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 123
    .line 124
    invoke-static {p2}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p3

    .line 136
    if-nez p1, :cond_4

    .line 137
    .line 138
    if-ne p3, v1, :cond_5

    .line 139
    .line 140
    :cond_4
    iget-object p0, p0, Lk1/r1;->e:Lk1/b;

    .line 141
    .line 142
    new-instance p3, Lk1/n0;

    .line 143
    .line 144
    invoke-direct {p3, p0}, Lk1/n0;-><init>(Lk1/q1;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    :cond_5
    check-cast p3, Lk1/n0;

    .line 151
    .line 152
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    return-object p3

    .line 156
    :pswitch_2
    check-cast p1, Lx2/s;

    .line 157
    .line 158
    check-cast p2, Ll2/o;

    .line 159
    .line 160
    check-cast p3, Ljava/lang/Number;

    .line 161
    .line 162
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 163
    .line 164
    .line 165
    check-cast p2, Ll2/t;

    .line 166
    .line 167
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    sget-object p0, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 171
    .line 172
    invoke-static {p2}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p1

    .line 180
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p3

    .line 184
    if-nez p1, :cond_6

    .line 185
    .line 186
    if-ne p3, v1, :cond_7

    .line 187
    .line 188
    :cond_6
    iget-object p0, p0, Lk1/r1;->c:Lk1/b;

    .line 189
    .line 190
    new-instance p3, Lk1/n0;

    .line 191
    .line 192
    invoke-direct {p3, p0}, Lk1/n0;-><init>(Lk1/q1;)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    :cond_7
    check-cast p3, Lk1/n0;

    .line 199
    .line 200
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    return-object p3

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
