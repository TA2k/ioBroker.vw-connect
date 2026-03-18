.class public final synthetic Ld00/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx2/s;II)V
    .locals 0

    .line 1
    iput p4, p0, Ld00/j;->d:I

    iput-object p1, p0, Ld00/j;->f:Ljava/lang/String;

    iput-object p2, p0, Ld00/j;->e:Lx2/s;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;II)V
    .locals 0

    .line 2
    iput p4, p0, Ld00/j;->d:I

    iput-object p1, p0, Ld00/j;->e:Lx2/s;

    iput-object p2, p0, Ld00/j;->f:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld00/j;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x7

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 19
    .line 20
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 21
    .line 22
    invoke-static {p2, v0, p1, p0}, Lz61/m;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    const/4 p2, 0x7

    .line 29
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 34
    .line 35
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 36
    .line 37
    invoke-static {p2, v0, p1, p0}, Lz61/a;->e(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_1
    const/4 p2, 0x1

    .line 42
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 47
    .line 48
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 49
    .line 50
    invoke-static {p2, v0, p1, p0}, Lxf0/r0;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_2
    const/4 p2, 0x7

    .line 55
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 60
    .line 61
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 62
    .line 63
    invoke-static {p2, v0, p1, p0}, Lkp/w5;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_3
    const/4 p2, 0x7

    .line 68
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 73
    .line 74
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 75
    .line 76
    invoke-static {p2, v0, p1, p0}, Lkp/w5;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_4
    const/4 p2, 0x1

    .line 81
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 86
    .line 87
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 88
    .line 89
    invoke-static {p2, v0, p1, p0}, Lr30/h;->l(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_5
    const/16 p2, 0x6d81

    .line 94
    .line 95
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 100
    .line 101
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 102
    .line 103
    invoke-static {p2, v0, p1, p0}, Lkc/d;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_6
    const/16 p2, 0x6d81

    .line 108
    .line 109
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 114
    .line 115
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 116
    .line 117
    invoke-static {p2, v0, p1, p0}, Lkc/d;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 118
    .line 119
    .line 120
    goto :goto_0

    .line 121
    :pswitch_7
    const/4 p2, 0x1

    .line 122
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 127
    .line 128
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 129
    .line 130
    invoke-static {p2, v0, p1, p0}, Li91/u3;->f(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 131
    .line 132
    .line 133
    goto :goto_0

    .line 134
    :pswitch_8
    const/4 p2, 0x1

    .line 135
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 140
    .line 141
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 142
    .line 143
    invoke-static {p2, v0, p1, p0}, Li40/o0;->d(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 144
    .line 145
    .line 146
    goto :goto_0

    .line 147
    :pswitch_9
    const/16 p2, 0x37

    .line 148
    .line 149
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 150
    .line 151
    .line 152
    move-result p2

    .line 153
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 154
    .line 155
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 156
    .line 157
    invoke-static {p2, v0, p1, p0}, Ldl0/e;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 158
    .line 159
    .line 160
    goto/16 :goto_0

    .line 161
    .line 162
    :pswitch_a
    const/4 p2, 0x7

    .line 163
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 168
    .line 169
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 170
    .line 171
    invoke-static {p2, v0, p1, p0}, Ld00/o;->G(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 172
    .line 173
    .line 174
    goto/16 :goto_0

    .line 175
    .line 176
    :pswitch_b
    const/4 p2, 0x7

    .line 177
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    iget-object v0, p0, Ld00/j;->f:Ljava/lang/String;

    .line 182
    .line 183
    iget-object p0, p0, Ld00/j;->e:Lx2/s;

    .line 184
    .line 185
    invoke-static {p2, v0, p1, p0}, Ld00/o;->E(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 186
    .line 187
    .line 188
    goto/16 :goto_0

    .line 189
    .line 190
    nop

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
