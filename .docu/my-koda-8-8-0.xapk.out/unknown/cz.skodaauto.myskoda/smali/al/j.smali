.class public final synthetic Lal/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Llh/g;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Llh/g;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lal/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lal/j;->e:Llh/g;

    .line 4
    .line 5
    iput-object p2, p0, Lal/j;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lal/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lx2/s;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "modifier"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, p3, 0x6

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    move-object v0, p2

    .line 26
    check-cast v0, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr p3, v0

    .line 38
    :cond_1
    and-int/lit8 v0, p3, 0x13

    .line 39
    .line 40
    const/16 v1, 0x12

    .line 41
    .line 42
    if-eq v0, v1, :cond_2

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    const/4 v0, 0x0

    .line 47
    :goto_1
    and-int/lit8 v1, p3, 0x1

    .line 48
    .line 49
    check-cast p2, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    shl-int/lit8 p3, p3, 0x6

    .line 58
    .line 59
    and-int/lit16 p3, p3, 0x380

    .line 60
    .line 61
    iget-object v0, p0, Lal/j;->f:Lay0/k;

    .line 62
    .line 63
    iget-object p0, p0, Lal/j;->e:Llh/g;

    .line 64
    .line 65
    invoke-static {p3, v0, p2, p0, p1}, Lwk/a;->j(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 70
    .line 71
    .line 72
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_0
    const-string v0, "modifier"

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    and-int/lit8 v0, p3, 0x6

    .line 81
    .line 82
    if-nez v0, :cond_5

    .line 83
    .line 84
    move-object v0, p2

    .line 85
    check-cast v0, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_4

    .line 92
    .line 93
    const/4 v0, 0x4

    .line 94
    goto :goto_3

    .line 95
    :cond_4
    const/4 v0, 0x2

    .line 96
    :goto_3
    or-int/2addr p3, v0

    .line 97
    :cond_5
    and-int/lit8 v0, p3, 0x13

    .line 98
    .line 99
    const/16 v1, 0x12

    .line 100
    .line 101
    if-eq v0, v1, :cond_6

    .line 102
    .line 103
    const/4 v0, 0x1

    .line 104
    goto :goto_4

    .line 105
    :cond_6
    const/4 v0, 0x0

    .line 106
    :goto_4
    and-int/lit8 v1, p3, 0x1

    .line 107
    .line 108
    check-cast p2, Ll2/t;

    .line 109
    .line 110
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-eqz v0, :cond_7

    .line 115
    .line 116
    and-int/lit8 p3, p3, 0xe

    .line 117
    .line 118
    iget-object v0, p0, Lal/j;->f:Lay0/k;

    .line 119
    .line 120
    iget-object p0, p0, Lal/j;->e:Llh/g;

    .line 121
    .line 122
    invoke-static {p3, v0, p2, p0, p1}, Lwk/a;->e(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 123
    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_7
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 127
    .line 128
    .line 129
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_1
    const-string v0, "modifier"

    .line 133
    .line 134
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    and-int/lit8 v0, p3, 0x6

    .line 138
    .line 139
    if-nez v0, :cond_9

    .line 140
    .line 141
    move-object v0, p2

    .line 142
    check-cast v0, Ll2/t;

    .line 143
    .line 144
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-eqz v0, :cond_8

    .line 149
    .line 150
    const/4 v0, 0x4

    .line 151
    goto :goto_6

    .line 152
    :cond_8
    const/4 v0, 0x2

    .line 153
    :goto_6
    or-int/2addr p3, v0

    .line 154
    :cond_9
    and-int/lit8 v0, p3, 0x13

    .line 155
    .line 156
    const/16 v1, 0x12

    .line 157
    .line 158
    if-eq v0, v1, :cond_a

    .line 159
    .line 160
    const/4 v0, 0x1

    .line 161
    goto :goto_7

    .line 162
    :cond_a
    const/4 v0, 0x0

    .line 163
    :goto_7
    and-int/lit8 v1, p3, 0x1

    .line 164
    .line 165
    check-cast p2, Ll2/t;

    .line 166
    .line 167
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-eqz v0, :cond_b

    .line 172
    .line 173
    and-int/lit8 p3, p3, 0xe

    .line 174
    .line 175
    iget-object v0, p0, Lal/j;->f:Lay0/k;

    .line 176
    .line 177
    iget-object p0, p0, Lal/j;->e:Llh/g;

    .line 178
    .line 179
    invoke-static {p3, v0, p2, p0, p1}, Lal/a;->b(ILay0/k;Ll2/o;Llh/g;Lx2/s;)V

    .line 180
    .line 181
    .line 182
    goto :goto_8

    .line 183
    :cond_b
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 184
    .line 185
    .line 186
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    return-object p0

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
