.class public final synthetic Lvh/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvh/w;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lvh/w;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvh/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvh/g;->e:Lvh/w;

    .line 4
    .line 5
    iput-object p2, p0, Lvh/g;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lvh/g;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    check-cast p3, Ll2/o;

    .line 8
    .line 9
    check-cast p4, Ljava/lang/Integer;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    const-string v0, "$this$composable"

    .line 15
    .line 16
    const-string v1, "it"

    .line 17
    .line 18
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lvh/g;->e:Lvh/w;

    .line 22
    .line 23
    iget-object p1, p1, Lvh/w;->e:Lvh/v;

    .line 24
    .line 25
    iget-object p1, p1, Lvh/v;->d:Lzg/f1;

    .line 26
    .line 27
    check-cast p3, Ll2/t;

    .line 28
    .line 29
    iget-object p0, p0, Lvh/g;->f:Lay0/k;

    .line 30
    .line 31
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p4

    .line 39
    if-nez p2, :cond_0

    .line 40
    .line 41
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 42
    .line 43
    if-ne p4, p2, :cond_1

    .line 44
    .line 45
    :cond_0
    new-instance p4, Lv2/k;

    .line 46
    .line 47
    const/4 p2, 0x4

    .line 48
    invoke-direct {p4, p2, p0}, Lv2/k;-><init>(ILay0/k;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    check-cast p4, Lay0/k;

    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    invoke-static {p1, p4, p3, p0}, Llp/oe;->a(Lzg/f1;Lay0/k;Ll2/o;I)V

    .line 58
    .line 59
    .line 60
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_0
    const-string v0, "$this$composable"

    .line 64
    .line 65
    const-string v1, "it"

    .line 66
    .line 67
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object p1, p0, Lvh/g;->e:Lvh/w;

    .line 71
    .line 72
    iget-object p1, p1, Lvh/w;->e:Lvh/v;

    .line 73
    .line 74
    iget-object p1, p1, Lvh/v;->b:Ljava/lang/Integer;

    .line 75
    .line 76
    check-cast p3, Ll2/t;

    .line 77
    .line 78
    iget-object p0, p0, Lvh/g;->f:Lay0/k;

    .line 79
    .line 80
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p4

    .line 88
    if-nez p2, :cond_2

    .line 89
    .line 90
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 91
    .line 92
    if-ne p4, p2, :cond_3

    .line 93
    .line 94
    :cond_2
    new-instance p4, Lv2/k;

    .line 95
    .line 96
    const/4 p2, 0x3

    .line 97
    invoke-direct {p4, p2, p0}, Lv2/k;-><init>(ILay0/k;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p3, p4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_3
    check-cast p4, Lay0/k;

    .line 104
    .line 105
    const/4 p0, 0x0

    .line 106
    invoke-static {p1, p4, p3, p0}, La/a;->c(Ljava/lang/Integer;Lay0/k;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_1
    const-string v0, "$this$composable"

    .line 111
    .line 112
    const-string v1, "it"

    .line 113
    .line 114
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-static {p3}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    check-cast p3, Ll2/t;

    .line 122
    .line 123
    iget-object p2, p0, Lvh/g;->f:Lay0/k;

    .line 124
    .line 125
    invoke-virtual {p3, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result p4

    .line 129
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    if-nez p4, :cond_4

    .line 134
    .line 135
    sget-object p4, Ll2/n;->a:Ll2/x0;

    .line 136
    .line 137
    if-ne v0, p4, :cond_5

    .line 138
    .line 139
    :cond_4
    new-instance v0, Lv2/k;

    .line 140
    .line 141
    const/4 p4, 0x5

    .line 142
    invoke-direct {v0, p4, p2}, Lv2/k;-><init>(ILay0/k;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_5
    check-cast v0, Lay0/k;

    .line 149
    .line 150
    iget-object p0, p0, Lvh/g;->e:Lvh/w;

    .line 151
    .line 152
    const/4 p2, 0x0

    .line 153
    invoke-interface {p1, p0, v0, p3, p2}, Leh/n;->o0(Lvh/w;Lay0/k;Ll2/o;I)V

    .line 154
    .line 155
    .line 156
    goto :goto_0

    .line 157
    :pswitch_2
    const-string v0, "$this$composable"

    .line 158
    .line 159
    const-string v1, "it"

    .line 160
    .line 161
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-object p1, p0, Lvh/g;->e:Lvh/w;

    .line 165
    .line 166
    iget-object p2, p1, Lvh/w;->e:Lvh/v;

    .line 167
    .line 168
    iget-object p2, p2, Lvh/v;->c:Ljava/lang/Integer;

    .line 169
    .line 170
    iget-object p1, p1, Lvh/w;->f:Lvh/u;

    .line 171
    .line 172
    check-cast p3, Ll2/t;

    .line 173
    .line 174
    iget-object p0, p0, Lvh/g;->f:Lay0/k;

    .line 175
    .line 176
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p4

    .line 180
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    if-nez p4, :cond_6

    .line 185
    .line 186
    sget-object p4, Ll2/n;->a:Ll2/x0;

    .line 187
    .line 188
    if-ne v0, p4, :cond_7

    .line 189
    .line 190
    :cond_6
    new-instance v0, Lv2/k;

    .line 191
    .line 192
    const/4 p4, 0x1

    .line 193
    invoke-direct {v0, p4, p0}, Lv2/k;-><init>(ILay0/k;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_7
    check-cast v0, Lay0/k;

    .line 200
    .line 201
    const/4 p0, 0x0

    .line 202
    invoke-static {p2, p1, v0, p3, p0}, Llp/id;->b(Ljava/lang/Integer;Lvh/u;Lay0/k;Ll2/o;I)V

    .line 203
    .line 204
    .line 205
    goto/16 :goto_0

    .line 206
    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
