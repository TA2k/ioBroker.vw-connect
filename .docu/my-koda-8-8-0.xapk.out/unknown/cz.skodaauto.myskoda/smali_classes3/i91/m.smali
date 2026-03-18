.class public final synthetic Li91/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:I

.field public final synthetic l:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lay0/a;Lx2/s;Ljava/lang/Integer;ZZIII)V
    .locals 0

    .line 1
    iput p9, p0, Li91/m;->d:I

    iput-object p1, p0, Li91/m;->e:Ljava/lang/String;

    iput-object p2, p0, Li91/m;->f:Lay0/a;

    iput-object p3, p0, Li91/m;->g:Lx2/s;

    iput-object p4, p0, Li91/m;->h:Ljava/lang/Integer;

    iput-boolean p5, p0, Li91/m;->i:Z

    iput-boolean p6, p0, Li91/m;->j:Z

    iput p7, p0, Li91/m;->k:I

    iput p8, p0, Li91/m;->l:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/Integer;Lay0/a;ZLx2/s;ZII)V
    .locals 1

    .line 2
    const/4 v0, 0x4

    iput v0, p0, Li91/m;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/m;->e:Ljava/lang/String;

    iput-object p2, p0, Li91/m;->h:Ljava/lang/Integer;

    iput-object p3, p0, Li91/m;->f:Lay0/a;

    iput-boolean p4, p0, Li91/m;->i:Z

    iput-object p5, p0, Li91/m;->g:Lx2/s;

    iput-boolean p6, p0, Li91/m;->j:Z

    iput p7, p0, Li91/m;->k:I

    iput p8, p0, Li91/m;->l:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Li91/m;->d:I

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
    iget p1, p0, Li91/m;->k:I

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
    iget v2, p0, Li91/m;->l:I

    .line 23
    .line 24
    iget-object v3, p0, Li91/m;->f:Lay0/a;

    .line 25
    .line 26
    iget-object v4, p0, Li91/m;->h:Ljava/lang/Integer;

    .line 27
    .line 28
    iget-object v5, p0, Li91/m;->e:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v7, p0, Li91/m;->g:Lx2/s;

    .line 31
    .line 32
    iget-boolean v8, p0, Li91/m;->i:Z

    .line 33
    .line 34
    iget-boolean v9, p0, Li91/m;->j:Z

    .line 35
    .line 36
    invoke-static/range {v1 .. v9}, Li91/j0;->g0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

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
    move-object v5, p1

    .line 43
    check-cast v5, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget p1, p0, Li91/m;->k:I

    .line 51
    .line 52
    or-int/lit8 p1, p1, 0x1

    .line 53
    .line 54
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget v1, p0, Li91/m;->l:I

    .line 59
    .line 60
    iget-object v2, p0, Li91/m;->f:Lay0/a;

    .line 61
    .line 62
    iget-object v3, p0, Li91/m;->h:Ljava/lang/Integer;

    .line 63
    .line 64
    iget-object v4, p0, Li91/m;->e:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v6, p0, Li91/m;->g:Lx2/s;

    .line 67
    .line 68
    iget-boolean v7, p0, Li91/m;->i:Z

    .line 69
    .line 70
    iget-boolean v8, p0, Li91/m;->j:Z

    .line 71
    .line 72
    invoke-static/range {v0 .. v8}, Li91/j0;->u0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :pswitch_1
    move-object v5, p1

    .line 77
    check-cast v5, Ll2/o;

    .line 78
    .line 79
    check-cast p2, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iget p1, p0, Li91/m;->k:I

    .line 85
    .line 86
    or-int/lit8 p1, p1, 0x1

    .line 87
    .line 88
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    iget v1, p0, Li91/m;->l:I

    .line 93
    .line 94
    iget-object v2, p0, Li91/m;->f:Lay0/a;

    .line 95
    .line 96
    iget-object v3, p0, Li91/m;->h:Ljava/lang/Integer;

    .line 97
    .line 98
    iget-object v4, p0, Li91/m;->e:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v6, p0, Li91/m;->g:Lx2/s;

    .line 101
    .line 102
    iget-boolean v7, p0, Li91/m;->i:Z

    .line 103
    .line 104
    iget-boolean v8, p0, Li91/m;->j:Z

    .line 105
    .line 106
    invoke-static/range {v0 .. v8}, Li91/j0;->f0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_2
    move-object v5, p1

    .line 111
    check-cast v5, Ll2/o;

    .line 112
    .line 113
    check-cast p2, Ljava/lang/Integer;

    .line 114
    .line 115
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    iget p1, p0, Li91/m;->k:I

    .line 119
    .line 120
    or-int/lit8 p1, p1, 0x1

    .line 121
    .line 122
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    iget v1, p0, Li91/m;->l:I

    .line 127
    .line 128
    iget-object v2, p0, Li91/m;->f:Lay0/a;

    .line 129
    .line 130
    iget-object v3, p0, Li91/m;->h:Ljava/lang/Integer;

    .line 131
    .line 132
    iget-object v4, p0, Li91/m;->e:Ljava/lang/String;

    .line 133
    .line 134
    iget-object v6, p0, Li91/m;->g:Lx2/s;

    .line 135
    .line 136
    iget-boolean v7, p0, Li91/m;->i:Z

    .line 137
    .line 138
    iget-boolean v8, p0, Li91/m;->j:Z

    .line 139
    .line 140
    invoke-static/range {v0 .. v8}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 141
    .line 142
    .line 143
    goto :goto_0

    .line 144
    :pswitch_3
    move-object v5, p1

    .line 145
    check-cast v5, Ll2/o;

    .line 146
    .line 147
    check-cast p2, Ljava/lang/Integer;

    .line 148
    .line 149
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    iget p1, p0, Li91/m;->k:I

    .line 153
    .line 154
    or-int/lit8 p1, p1, 0x1

    .line 155
    .line 156
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    iget v1, p0, Li91/m;->l:I

    .line 161
    .line 162
    iget-object v2, p0, Li91/m;->f:Lay0/a;

    .line 163
    .line 164
    iget-object v3, p0, Li91/m;->h:Ljava/lang/Integer;

    .line 165
    .line 166
    iget-object v4, p0, Li91/m;->e:Ljava/lang/String;

    .line 167
    .line 168
    iget-object v6, p0, Li91/m;->g:Lx2/s;

    .line 169
    .line 170
    iget-boolean v7, p0, Li91/m;->i:Z

    .line 171
    .line 172
    iget-boolean v8, p0, Li91/m;->j:Z

    .line 173
    .line 174
    invoke-static/range {v0 .. v8}, Li91/j0;->W(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 175
    .line 176
    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
