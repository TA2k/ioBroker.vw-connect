.class public final synthetic La71/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lay0/a;Z)V
    .locals 0

    .line 1
    const/4 p1, 0x3

    iput p1, p0, La71/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La71/p;->f:Lay0/a;

    iput-object p3, p0, La71/p;->g:Lay0/a;

    iput-boolean p4, p0, La71/p;->e:Z

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lay0/a;Z)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, La71/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p3, p0, La71/p;->e:Z

    iput-object p1, p0, La71/p;->f:Lay0/a;

    iput-object p2, p0, La71/p;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/a;Lay0/a;II)V
    .locals 0

    .line 3
    iput p5, p0, La71/p;->d:I

    iput-boolean p1, p0, La71/p;->e:Z

    iput-object p2, p0, La71/p;->f:Lay0/a;

    iput-object p3, p0, La71/p;->g:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, La71/p;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, La71/p;->f:Lay0/a;

    .line 19
    .line 20
    iget-object v1, p0, La71/p;->g:Lay0/a;

    .line 21
    .line 22
    iget-boolean p0, p0, La71/p;->e:Z

    .line 23
    .line 24
    invoke-static {p2, v0, v1, p1, p0}, Luz/k0;->b0(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    iget-object v0, p0, La71/p;->f:Lay0/a;

    .line 39
    .line 40
    iget-object v1, p0, La71/p;->g:Lay0/a;

    .line 41
    .line 42
    iget-boolean p0, p0, La71/p;->e:Z

    .line 43
    .line 44
    invoke-static {p2, v0, v1, p1, p0}, Loz/e;->h(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    const/4 p2, 0x1

    .line 52
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    iget-object v0, p0, La71/p;->f:Lay0/a;

    .line 57
    .line 58
    iget-object v1, p0, La71/p;->g:Lay0/a;

    .line 59
    .line 60
    iget-boolean p0, p0, La71/p;->e:Z

    .line 61
    .line 62
    invoke-static {p2, v0, v1, p1, p0}, Ljp/sb;->a(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const/16 p2, 0x31

    .line 70
    .line 71
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    iget-object v0, p0, La71/p;->f:Lay0/a;

    .line 76
    .line 77
    iget-object v1, p0, La71/p;->g:Lay0/a;

    .line 78
    .line 79
    iget-boolean p0, p0, La71/p;->e:Z

    .line 80
    .line 81
    invoke-static {p2, v0, v1, p1, p0}, Ljp/ra;->h(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    const/4 p2, 0x1

    .line 89
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    iget-object v0, p0, La71/p;->f:Lay0/a;

    .line 94
    .line 95
    iget-object v1, p0, La71/p;->g:Lay0/a;

    .line 96
    .line 97
    iget-boolean p0, p0, La71/p;->e:Z

    .line 98
    .line 99
    invoke-static {p2, v0, v1, p1, p0}, Ln70/a;->K(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    and-int/lit8 v0, p2, 0x3

    .line 108
    .line 109
    const/4 v1, 0x2

    .line 110
    const/4 v2, 0x1

    .line 111
    if-eq v0, v1, :cond_0

    .line 112
    .line 113
    move v0, v2

    .line 114
    goto :goto_1

    .line 115
    :cond_0
    const/4 v0, 0x0

    .line 116
    :goto_1
    and-int/2addr p2, v2

    .line 117
    move-object v8, p1

    .line 118
    check-cast v8, Ll2/t;

    .line 119
    .line 120
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-eqz p1, :cond_1

    .line 125
    .line 126
    sget-object p1, Lh71/o;->a:Ll2/u2;

    .line 127
    .line 128
    invoke-virtual {v8, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    check-cast p1, Lh71/n;

    .line 133
    .line 134
    iget p1, p1, Lh71/n;->i:F

    .line 135
    .line 136
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 137
    .line 138
    invoke-static {p2, p1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    const/high16 p2, 0x3f800000    # 1.0f

    .line 143
    .line 144
    invoke-static {p1, p2, v2}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    sget-object p1, Lh71/q;->a:Ll2/e0;

    .line 149
    .line 150
    invoke-virtual {v8, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    check-cast p1, Lh71/p;

    .line 155
    .line 156
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    const v4, 0x7f0805c6

    .line 160
    .line 161
    .line 162
    const/4 v9, 0x0

    .line 163
    iget-boolean v5, p0, La71/p;->e:Z

    .line 164
    .line 165
    iget-object v6, p0, La71/p;->f:Lay0/a;

    .line 166
    .line 167
    iget-object v7, p0, La71/p;->g:Lay0/a;

    .line 168
    .line 169
    invoke-static/range {v3 .. v9}, Lkp/r7;->a(Lx2/s;IZLay0/a;Lay0/a;Ll2/o;I)V

    .line 170
    .line 171
    .line 172
    goto :goto_2

    .line 173
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 174
    .line 175
    .line 176
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    return-object p0

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
