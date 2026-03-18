.class public final synthetic Lce/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lce/u;


# direct methods
.method public synthetic constructor <init>(Lce/u;I)V
    .locals 0

    .line 1
    iput p2, p0, Lce/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lce/f;->e:Lce/u;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lce/f;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_3

    .line 31
    .line 32
    iget-object v2, p0, Lce/f;->e:Lce/u;

    .line 33
    .line 34
    iget-object p0, v2, Lce/u;->j:Lyy0/l1;

    .line 35
    .line 36
    invoke-static {p0, p1}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Llc/q;

    .line 45
    .line 46
    sget-object p2, Lzb/x;->b:Ll2/u2;

    .line 47
    .line 48
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    const-string v0, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.cpoi.presentation.CpoiUi"

    .line 53
    .line 54
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    check-cast p2, Lce/k;

    .line 58
    .line 59
    invoke-virtual {p1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    if-nez v0, :cond_1

    .line 68
    .line 69
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 70
    .line 71
    if-ne v1, v0, :cond_2

    .line 72
    .line 73
    :cond_1
    new-instance v0, Laf/b;

    .line 74
    .line 75
    const/4 v6, 0x0

    .line 76
    const/16 v7, 0x10

    .line 77
    .line 78
    const/4 v1, 0x1

    .line 79
    const-class v3, Lce/u;

    .line 80
    .line 81
    const-string v4, "onUiEvent"

    .line 82
    .line 83
    const-string v5, "onUiEvent(Lcariad/charging/multicharge/kitten/cpoi/presentation/CpoiUiEvent;)V"

    .line 84
    .line 85
    invoke-direct/range {v0 .. v7}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object v1, v0

    .line 92
    :cond_2
    check-cast v1, Lhy0/g;

    .line 93
    .line 94
    check-cast v1, Lay0/k;

    .line 95
    .line 96
    const/16 v0, 0x8

    .line 97
    .line 98
    invoke-interface {p2, p0, v1, p1, v0}, Lce/k;->y(Llc/q;Lay0/k;Ll2/o;I)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 103
    .line 104
    .line 105
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 109
    .line 110
    const/4 v1, 0x2

    .line 111
    const/4 v2, 0x1

    .line 112
    if-eq v0, v1, :cond_4

    .line 113
    .line 114
    move v0, v2

    .line 115
    goto :goto_2

    .line 116
    :cond_4
    const/4 v0, 0x0

    .line 117
    :goto_2
    and-int/2addr p2, v2

    .line 118
    check-cast p1, Ll2/t;

    .line 119
    .line 120
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 121
    .line 122
    .line 123
    move-result p2

    .line 124
    if-eqz p2, :cond_7

    .line 125
    .line 126
    iget-object v2, p0, Lce/f;->e:Lce/u;

    .line 127
    .line 128
    iget-object p0, v2, Lce/u;->i:Lyy0/l1;

    .line 129
    .line 130
    invoke-static {p0, p1}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    check-cast p0, Llc/q;

    .line 139
    .line 140
    sget-object p2, Lzb/x;->b:Ll2/u2;

    .line 141
    .line 142
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    const-string v0, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.cpoi.presentation.CpoiUi"

    .line 147
    .line 148
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    check-cast p2, Lce/k;

    .line 152
    .line 153
    invoke-virtual {p1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    if-nez v0, :cond_5

    .line 162
    .line 163
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 164
    .line 165
    if-ne v1, v0, :cond_6

    .line 166
    .line 167
    :cond_5
    new-instance v0, Laf/b;

    .line 168
    .line 169
    const/4 v6, 0x0

    .line 170
    const/16 v7, 0xf

    .line 171
    .line 172
    const/4 v1, 0x1

    .line 173
    const-class v3, Lce/u;

    .line 174
    .line 175
    const-string v4, "onUiEvent"

    .line 176
    .line 177
    const-string v5, "onUiEvent(Lcariad/charging/multicharge/kitten/cpoi/presentation/CpoiUiEvent;)V"

    .line 178
    .line 179
    invoke-direct/range {v0 .. v7}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    move-object v1, v0

    .line 186
    :cond_6
    check-cast v1, Lhy0/g;

    .line 187
    .line 188
    check-cast v1, Lay0/k;

    .line 189
    .line 190
    const/16 v0, 0x8

    .line 191
    .line 192
    invoke-interface {p2, p0, v1, p1, v0}, Lce/k;->X(Llc/q;Lay0/k;Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 197
    .line 198
    .line 199
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    return-object p0

    .line 202
    nop

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
