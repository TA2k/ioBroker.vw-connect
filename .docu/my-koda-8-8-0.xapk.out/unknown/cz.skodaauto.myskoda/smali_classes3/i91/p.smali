.class public final synthetic Li91/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Integer;

.field public final synthetic j:I

.field public final synthetic k:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;Lx2/s;ZLjava/lang/Integer;III)V
    .locals 0

    .line 1
    iput p8, p0, Li91/p;->d:I

    iput-object p1, p0, Li91/p;->e:Ljava/lang/String;

    iput-object p2, p0, Li91/p;->f:Lay0/a;

    iput-object p3, p0, Li91/p;->g:Lx2/s;

    iput-boolean p4, p0, Li91/p;->h:Z

    iput-object p5, p0, Li91/p;->i:Ljava/lang/Integer;

    iput p6, p0, Li91/p;->j:I

    iput p7, p0, Li91/p;->k:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/Integer;Lay0/a;ZLx2/s;II)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li91/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/p;->e:Ljava/lang/String;

    iput-object p2, p0, Li91/p;->i:Ljava/lang/Integer;

    iput-object p3, p0, Li91/p;->f:Lay0/a;

    iput-boolean p4, p0, Li91/p;->h:Z

    iput-object p5, p0, Li91/p;->g:Lx2/s;

    iput p6, p0, Li91/p;->j:I

    iput p7, p0, Li91/p;->k:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li91/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget p1, p0, Li91/p;->j:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget v2, p0, Li91/p;->k:I

    .line 23
    .line 24
    iget-object v3, p0, Li91/p;->f:Lay0/a;

    .line 25
    .line 26
    iget-object v4, p0, Li91/p;->i:Ljava/lang/Integer;

    .line 27
    .line 28
    iget-object v5, p0, Li91/p;->e:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v7, p0, Li91/p;->g:Lx2/s;

    .line 31
    .line 32
    iget-boolean v8, p0, Li91/p;->h:Z

    .line 33
    .line 34
    invoke-static/range {v1 .. v8}, Li91/j0;->h0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    move-object v5, p1

    .line 41
    check-cast v5, Ll2/o;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    iget p1, p0, Li91/p;->j:I

    .line 49
    .line 50
    or-int/lit8 p1, p1, 0x1

    .line 51
    .line 52
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget v1, p0, Li91/p;->k:I

    .line 57
    .line 58
    iget-object v2, p0, Li91/p;->f:Lay0/a;

    .line 59
    .line 60
    iget-object v3, p0, Li91/p;->i:Ljava/lang/Integer;

    .line 61
    .line 62
    iget-object v4, p0, Li91/p;->e:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v6, p0, Li91/p;->g:Lx2/s;

    .line 65
    .line 66
    iget-boolean v7, p0, Li91/p;->h:Z

    .line 67
    .line 68
    invoke-static/range {v0 .. v7}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_1
    move-object v5, p1

    .line 73
    check-cast v5, Ll2/o;

    .line 74
    .line 75
    check-cast p2, Ljava/lang/Integer;

    .line 76
    .line 77
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    iget p1, p0, Li91/p;->j:I

    .line 81
    .line 82
    or-int/lit8 p1, p1, 0x1

    .line 83
    .line 84
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    iget v1, p0, Li91/p;->k:I

    .line 89
    .line 90
    iget-object v2, p0, Li91/p;->f:Lay0/a;

    .line 91
    .line 92
    iget-object v3, p0, Li91/p;->i:Ljava/lang/Integer;

    .line 93
    .line 94
    iget-object v4, p0, Li91/p;->e:Ljava/lang/String;

    .line 95
    .line 96
    iget-object v6, p0, Li91/p;->g:Lx2/s;

    .line 97
    .line 98
    iget-boolean v7, p0, Li91/p;->h:Z

    .line 99
    .line 100
    invoke-static/range {v0 .. v7}, Li91/j0;->R(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :pswitch_2
    move-object v5, p1

    .line 105
    check-cast v5, Ll2/o;

    .line 106
    .line 107
    check-cast p2, Ljava/lang/Integer;

    .line 108
    .line 109
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    iget p1, p0, Li91/p;->j:I

    .line 113
    .line 114
    or-int/lit8 p1, p1, 0x1

    .line 115
    .line 116
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    iget v1, p0, Li91/p;->k:I

    .line 121
    .line 122
    iget-object v2, p0, Li91/p;->f:Lay0/a;

    .line 123
    .line 124
    iget-object v3, p0, Li91/p;->i:Ljava/lang/Integer;

    .line 125
    .line 126
    iget-object v4, p0, Li91/p;->e:Ljava/lang/String;

    .line 127
    .line 128
    iget-object v6, p0, Li91/p;->g:Lx2/s;

    .line 129
    .line 130
    iget-boolean v7, p0, Li91/p;->h:Z

    .line 131
    .line 132
    invoke-static/range {v0 .. v7}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 133
    .line 134
    .line 135
    goto :goto_0

    .line 136
    :pswitch_3
    move-object v5, p1

    .line 137
    check-cast v5, Ll2/o;

    .line 138
    .line 139
    check-cast p2, Ljava/lang/Integer;

    .line 140
    .line 141
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    iget p1, p0, Li91/p;->j:I

    .line 145
    .line 146
    or-int/lit8 p1, p1, 0x1

    .line 147
    .line 148
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    iget v1, p0, Li91/p;->k:I

    .line 153
    .line 154
    iget-object v2, p0, Li91/p;->f:Lay0/a;

    .line 155
    .line 156
    iget-object v3, p0, Li91/p;->i:Ljava/lang/Integer;

    .line 157
    .line 158
    iget-object v4, p0, Li91/p;->e:Ljava/lang/String;

    .line 159
    .line 160
    iget-object v6, p0, Li91/p;->g:Lx2/s;

    .line 161
    .line 162
    iget-boolean v7, p0, Li91/p;->h:Z

    .line 163
    .line 164
    invoke-static/range {v0 .. v7}, Li91/j0;->Q(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 165
    .line 166
    .line 167
    goto/16 :goto_0

    .line 168
    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
