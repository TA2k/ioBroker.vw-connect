.class public final synthetic Li2/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;ZII)V
    .locals 0

    .line 1
    iput p4, p0, Li2/r;->d:I

    iput-object p1, p0, Li2/r;->f:Lay0/a;

    iput-boolean p2, p0, Li2/r;->e:Z

    iput p3, p0, Li2/r;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/a;II)V
    .locals 0

    .line 2
    iput p4, p0, Li2/r;->d:I

    iput-boolean p1, p0, Li2/r;->e:Z

    iput-object p2, p0, Li2/r;->f:Lay0/a;

    iput p3, p0, Li2/r;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li2/r;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    iget p2, p0, Li2/r;->g:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 22
    .line 23
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lz70/l;->h(ZLay0/a;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    iget p2, p0, Li2/r;->g:I

    .line 35
    .line 36
    or-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 43
    .line 44
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 45
    .line 46
    invoke-static {v0, p0, p1, p2}, Lym0/a;->l(ZLay0/a;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    iget p2, p0, Li2/r;->g:I

    .line 54
    .line 55
    or-int/lit8 p2, p2, 0x1

    .line 56
    .line 57
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 62
    .line 63
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 64
    .line 65
    invoke-static {v0, p0, p1, p2}, Lym0/a;->i(ZLay0/a;Ll2/o;I)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget p2, p0, Li2/r;->g:I

    .line 73
    .line 74
    or-int/lit8 p2, p2, 0x1

    .line 75
    .line 76
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 81
    .line 82
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 83
    .line 84
    invoke-static {v0, p0, p1, p2}, Llp/qe;->d(ZLay0/a;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 89
    .line 90
    .line 91
    iget p2, p0, Li2/r;->g:I

    .line 92
    .line 93
    or-int/lit8 p2, p2, 0x1

    .line 94
    .line 95
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 100
    .line 101
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 102
    .line 103
    invoke-static {v0, p0, p1, p2}, Ljp/yg;->f(ZLay0/a;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    iget p2, p0, Li2/r;->g:I

    .line 111
    .line 112
    or-int/lit8 p2, p2, 0x1

    .line 113
    .line 114
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 119
    .line 120
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 121
    .line 122
    invoke-static {v0, p0, p1, p2}, Lm60/a;->b(ZLay0/a;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    iget p2, p0, Li2/r;->g:I

    .line 130
    .line 131
    or-int/lit8 p2, p2, 0x1

    .line 132
    .line 133
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 134
    .line 135
    .line 136
    move-result p2

    .line 137
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 138
    .line 139
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 140
    .line 141
    invoke-static {v0, p0, p1, p2}, Lit0/b;->d(ZLay0/a;Ll2/o;I)V

    .line 142
    .line 143
    .line 144
    goto :goto_0

    .line 145
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 146
    .line 147
    .line 148
    iget p2, p0, Li2/r;->g:I

    .line 149
    .line 150
    or-int/lit8 p2, p2, 0x1

    .line 151
    .line 152
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 157
    .line 158
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 159
    .line 160
    invoke-static {v0, p0, p1, p2}, Li50/z;->d(ZLay0/a;Ll2/o;I)V

    .line 161
    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    iget p2, p0, Li2/r;->g:I

    .line 169
    .line 170
    or-int/lit8 p2, p2, 0x1

    .line 171
    .line 172
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 173
    .line 174
    .line 175
    move-result p2

    .line 176
    iget-boolean v0, p0, Li2/r;->e:Z

    .line 177
    .line 178
    iget-object p0, p0, Li2/r;->f:Lay0/a;

    .line 179
    .line 180
    invoke-static {v0, p0, p1, p2}, Li2/a1;->a(ZLay0/a;Ll2/o;I)V

    .line 181
    .line 182
    .line 183
    goto/16 :goto_0

    .line 184
    .line 185
    :pswitch_data_0
    .packed-switch 0x0
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
