.class public final synthetic Ldl0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Z

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILay0/a;Lx2/s;ZI)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Ldl0/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldl0/g;->e:I

    iput-object p2, p0, Ldl0/g;->i:Ljava/lang/Object;

    iput-object p3, p0, Ldl0/g;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Ldl0/g;->f:Z

    iput p5, p0, Ldl0/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(IZLx2/s;Ljava/lang/Integer;II)V
    .locals 0

    .line 2
    const/4 p5, 0x1

    iput p5, p0, Ldl0/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldl0/g;->e:I

    iput-boolean p2, p0, Ldl0/g;->f:Z

    iput-object p3, p0, Ldl0/g;->h:Ljava/lang/Object;

    iput-object p4, p0, Ldl0/g;->i:Ljava/lang/Object;

    iput p6, p0, Ldl0/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(I[BZLay0/k;I)V
    .locals 1

    .line 3
    const/4 v0, 0x4

    iput v0, p0, Ldl0/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldl0/g;->e:I

    iput-object p2, p0, Ldl0/g;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Ldl0/g;->f:Z

    iput-object p4, p0, Ldl0/g;->i:Ljava/lang/Object;

    iput p5, p0, Ldl0/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lcl0/o;Lay0/a;ZII)V
    .locals 1

    .line 4
    const/4 v0, 0x0

    iput v0, p0, Ldl0/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldl0/g;->h:Ljava/lang/Object;

    iput-object p2, p0, Ldl0/g;->i:Ljava/lang/Object;

    iput-boolean p3, p0, Ldl0/g;->f:Z

    iput p4, p0, Ldl0/g;->e:I

    iput p5, p0, Ldl0/g;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lh50/w0;Lx2/s;ZII)V
    .locals 1

    .line 5
    const/4 v0, 0x2

    iput v0, p0, Ldl0/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldl0/g;->h:Ljava/lang/Object;

    iput-object p2, p0, Ldl0/g;->i:Ljava/lang/Object;

    iput-boolean p3, p0, Ldl0/g;->f:Z

    iput p4, p0, Ldl0/g;->e:I

    iput p5, p0, Ldl0/g;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Ldl0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldl0/g;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v2, v0

    .line 9
    check-cast v2, [B

    .line 10
    .line 11
    iget-object v0, p0, Ldl0/g;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lay0/k;

    .line 15
    .line 16
    move-object v5, p1

    .line 17
    check-cast v5, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget p1, p0, Ldl0/g;->g:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    iget v1, p0, Ldl0/g;->e:I

    .line 33
    .line 34
    iget-boolean v3, p0, Ldl0/g;->f:Z

    .line 35
    .line 36
    invoke-static/range {v1 .. v6}, Lw00/a;->q(I[BZLay0/k;Ll2/o;I)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    iget-object v0, p0, Ldl0/g;->i:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v3, v0

    .line 45
    check-cast v3, Lay0/a;

    .line 46
    .line 47
    iget-object v0, p0, Ldl0/g;->h:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v5, v0

    .line 50
    check-cast v5, Lx2/s;

    .line 51
    .line 52
    move-object v4, p1

    .line 53
    check-cast v4, Ll2/o;

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Integer;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    iget p1, p0, Ldl0/g;->g:I

    .line 61
    .line 62
    or-int/lit8 p1, p1, 0x1

    .line 63
    .line 64
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    iget v1, p0, Ldl0/g;->e:I

    .line 69
    .line 70
    iget-boolean v6, p0, Ldl0/g;->f:Z

    .line 71
    .line 72
    invoke-static/range {v1 .. v6}, Li91/j0;->S(IILay0/a;Ll2/o;Lx2/s;Z)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :pswitch_1
    iget-object v0, p0, Ldl0/g;->h:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v1, v0

    .line 79
    check-cast v1, Lh50/w0;

    .line 80
    .line 81
    iget-object v0, p0, Ldl0/g;->i:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v2, v0

    .line 84
    check-cast v2, Lx2/s;

    .line 85
    .line 86
    move-object v4, p1

    .line 87
    check-cast v4, Ll2/o;

    .line 88
    .line 89
    check-cast p2, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    iget p1, p0, Ldl0/g;->e:I

    .line 95
    .line 96
    or-int/lit8 p1, p1, 0x1

    .line 97
    .line 98
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    iget-boolean v3, p0, Ldl0/g;->f:Z

    .line 103
    .line 104
    iget v6, p0, Ldl0/g;->g:I

    .line 105
    .line 106
    invoke-static/range {v1 .. v6}, Li50/c;->q(Lh50/w0;Lx2/s;ZLl2/o;II)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_2
    iget-object v0, p0, Ldl0/g;->h:Ljava/lang/Object;

    .line 111
    .line 112
    move-object v3, v0

    .line 113
    check-cast v3, Lx2/s;

    .line 114
    .line 115
    iget-object v0, p0, Ldl0/g;->i:Ljava/lang/Object;

    .line 116
    .line 117
    move-object v4, v0

    .line 118
    check-cast v4, Ljava/lang/Integer;

    .line 119
    .line 120
    move-object v5, p1

    .line 121
    check-cast v5, Ll2/o;

    .line 122
    .line 123
    check-cast p2, Ljava/lang/Integer;

    .line 124
    .line 125
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    const/4 p1, 0x1

    .line 129
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    iget v1, p0, Ldl0/g;->e:I

    .line 134
    .line 135
    iget-boolean v2, p0, Ldl0/g;->f:Z

    .line 136
    .line 137
    iget v7, p0, Ldl0/g;->g:I

    .line 138
    .line 139
    invoke-static/range {v1 .. v7}, Li40/q;->j(IZLx2/s;Ljava/lang/Integer;Ll2/o;II)V

    .line 140
    .line 141
    .line 142
    goto :goto_0

    .line 143
    :pswitch_3
    iget-object v0, p0, Ldl0/g;->h:Ljava/lang/Object;

    .line 144
    .line 145
    move-object v1, v0

    .line 146
    check-cast v1, Lcl0/o;

    .line 147
    .line 148
    iget-object v0, p0, Ldl0/g;->i:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v2, v0

    .line 151
    check-cast v2, Lay0/a;

    .line 152
    .line 153
    move-object v4, p1

    .line 154
    check-cast v4, Ll2/o;

    .line 155
    .line 156
    check-cast p2, Ljava/lang/Integer;

    .line 157
    .line 158
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    iget p1, p0, Ldl0/g;->e:I

    .line 162
    .line 163
    or-int/lit8 p1, p1, 0x1

    .line 164
    .line 165
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 166
    .line 167
    .line 168
    move-result v5

    .line 169
    iget-boolean v3, p0, Ldl0/g;->f:Z

    .line 170
    .line 171
    iget v6, p0, Ldl0/g;->g:I

    .line 172
    .line 173
    invoke-static/range {v1 .. v6}, Ldl0/e;->g(Lcl0/o;Lay0/a;ZLl2/o;II)V

    .line 174
    .line 175
    .line 176
    goto/16 :goto_0

    .line 177
    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
