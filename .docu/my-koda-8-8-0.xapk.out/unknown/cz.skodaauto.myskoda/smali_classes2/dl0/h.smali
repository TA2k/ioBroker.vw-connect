.class public final synthetic Ldl0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lx2/s;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IIIILx2/s;)V
    .locals 0

    .line 1
    iput p4, p0, Ldl0/h;->d:I

    iput-object p5, p0, Ldl0/h;->f:Lx2/s;

    iput p1, p0, Ldl0/h;->e:I

    iput p2, p0, Ldl0/h;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILx2/s;II)V
    .locals 0

    .line 2
    iput p4, p0, Ldl0/h;->d:I

    iput p1, p0, Ldl0/h;->e:I

    iput-object p2, p0, Ldl0/h;->f:Lx2/s;

    iput p3, p0, Ldl0/h;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;III)V
    .locals 0

    .line 3
    iput p4, p0, Ldl0/h;->d:I

    iput-object p1, p0, Ldl0/h;->f:Lx2/s;

    iput p2, p0, Ldl0/h;->e:I

    iput p3, p0, Ldl0/h;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ldl0/h;->d:I

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
    iget p2, p0, Ldl0/h;->g:I

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
    iget v0, p0, Ldl0/h;->e:I

    .line 22
    .line 23
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 24
    .line 25
    invoke-static {v0, p2, p1, p0}, Lxf0/i0;->e(IILl2/o;Lx2/s;)V

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
    iget p2, p0, Ldl0/h;->e:I

    .line 32
    .line 33
    or-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget v0, p0, Ldl0/h;->g:I

    .line 40
    .line 41
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 42
    .line 43
    invoke-static {p2, v0, p1, p0}, Li91/j0;->m0(IILl2/o;Lx2/s;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_1
    iget p2, p0, Ldl0/h;->e:I

    .line 48
    .line 49
    or-int/lit8 p2, p2, 0x1

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget v0, p0, Ldl0/h;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 58
    .line 59
    invoke-static {p2, v0, p1, p0}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    const/16 p2, 0xd81

    .line 64
    .line 65
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    iget v0, p0, Ldl0/h;->e:I

    .line 70
    .line 71
    iget v1, p0, Ldl0/h;->g:I

    .line 72
    .line 73
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 74
    .line 75
    invoke-static {v0, v1, p2, p1, p0}, Li91/j0;->V(IIILl2/o;Lx2/s;)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_3
    const/4 p2, 0x1

    .line 80
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    iget v0, p0, Ldl0/h;->e:I

    .line 85
    .line 86
    iget v1, p0, Ldl0/h;->g:I

    .line 87
    .line 88
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 89
    .line 90
    invoke-static {v0, v1, p2, p1, p0}, Li91/y2;->a(IIILl2/o;Lx2/s;)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :pswitch_4
    iget p2, p0, Ldl0/h;->e:I

    .line 95
    .line 96
    or-int/lit8 p2, p2, 0x1

    .line 97
    .line 98
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    iget v0, p0, Ldl0/h;->g:I

    .line 103
    .line 104
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 105
    .line 106
    invoke-static {p2, v0, p1, p0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_5
    iget p2, p0, Ldl0/h;->g:I

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
    iget v0, p0, Ldl0/h;->e:I

    .line 119
    .line 120
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 121
    .line 122
    invoke-static {v0, p2, p1, p0}, Li40/l1;->Z(IILl2/o;Lx2/s;)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    :pswitch_6
    iget p2, p0, Ldl0/h;->g:I

    .line 127
    .line 128
    or-int/lit8 p2, p2, 0x1

    .line 129
    .line 130
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 131
    .line 132
    .line 133
    move-result p2

    .line 134
    iget v0, p0, Ldl0/h;->e:I

    .line 135
    .line 136
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 137
    .line 138
    invoke-static {v0, p2, p1, p0}, Li40/l1;->V(IILl2/o;Lx2/s;)V

    .line 139
    .line 140
    .line 141
    goto :goto_0

    .line 142
    :pswitch_7
    iget p2, p0, Ldl0/h;->g:I

    .line 143
    .line 144
    or-int/lit8 p2, p2, 0x1

    .line 145
    .line 146
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    iget v0, p0, Ldl0/h;->e:I

    .line 151
    .line 152
    iget-object p0, p0, Ldl0/h;->f:Lx2/s;

    .line 153
    .line 154
    invoke-static {v0, p2, p1, p0}, Ldl0/e;->i(IILl2/o;Lx2/s;)V

    .line 155
    .line 156
    .line 157
    goto/16 :goto_0

    .line 158
    .line 159
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
