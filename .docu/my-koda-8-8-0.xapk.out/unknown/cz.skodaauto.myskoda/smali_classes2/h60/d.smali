.class public final synthetic Lh60/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lhi/a;ZZLt2/b;II)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    iput v0, p0, Lh60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh60/d;->j:Ljava/lang/Object;

    iput-boolean p2, p0, Lh60/d;->e:Z

    iput-boolean p3, p0, Lh60/d;->f:Z

    iput-object p4, p0, Lh60/d;->h:Ljava/lang/Object;

    iput p5, p0, Lh60/d;->g:I

    iput p6, p0, Lh60/d;->i:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/String;ZZI)V
    .locals 1

    .line 2
    const/4 v0, 0x3

    iput v0, p0, Lh60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh60/d;->j:Ljava/lang/Object;

    iput-object p3, p0, Lh60/d;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lh60/d;->e:Z

    iput-boolean p5, p0, Lh60/d;->f:Z

    iput p2, p0, Lh60/d;->g:I

    iput p6, p0, Lh60/d;->i:I

    return-void
.end method

.method public synthetic constructor <init>(ZLx2/s;ZLay0/k;II)V
    .locals 1

    .line 3
    const/4 v0, 0x2

    iput v0, p0, Lh60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lh60/d;->e:Z

    iput-object p2, p0, Lh60/d;->j:Ljava/lang/Object;

    iput-boolean p3, p0, Lh60/d;->f:Z

    iput-object p4, p0, Lh60/d;->h:Ljava/lang/Object;

    iput p5, p0, Lh60/d;->g:I

    iput p6, p0, Lh60/d;->i:I

    return-void
.end method

.method public synthetic constructor <init>(ZZILjava/lang/String;Lay0/a;I)V
    .locals 1

    .line 4
    const/4 v0, 0x0

    iput v0, p0, Lh60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lh60/d;->e:Z

    iput-boolean p2, p0, Lh60/d;->f:Z

    iput p3, p0, Lh60/d;->g:I

    iput-object p4, p0, Lh60/d;->j:Ljava/lang/Object;

    iput-object p5, p0, Lh60/d;->h:Ljava/lang/Object;

    iput p6, p0, Lh60/d;->i:I

    return-void
.end method

.method public synthetic constructor <init>(ZZLh50/i0;ILay0/a;I)V
    .locals 1

    .line 5
    const/4 v0, 0x1

    iput v0, p0, Lh60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lh60/d;->e:Z

    iput-boolean p2, p0, Lh60/d;->f:Z

    iput-object p3, p0, Lh60/d;->j:Ljava/lang/Object;

    iput p4, p0, Lh60/d;->g:I

    iput-object p5, p0, Lh60/d;->h:Ljava/lang/Object;

    iput p6, p0, Lh60/d;->i:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lh60/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh60/d;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lhi/a;

    .line 10
    .line 11
    iget-object v0, p0, Lh60/d;->h:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v4, v0

    .line 14
    check-cast v4, Lt2/b;

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
    iget p1, p0, Lh60/d;->g:I

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
    iget-boolean v2, p0, Lh60/d;->e:Z

    .line 33
    .line 34
    iget-boolean v3, p0, Lh60/d;->f:Z

    .line 35
    .line 36
    iget v7, p0, Lh60/d;->i:I

    .line 37
    .line 38
    invoke-static/range {v1 .. v7}, Lzb/x;->a(Lhi/a;ZZLt2/b;Ll2/o;II)V

    .line 39
    .line 40
    .line 41
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_0
    iget-object v0, p0, Lh60/d;->j:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v1, v0

    .line 47
    check-cast v1, Ljava/lang/String;

    .line 48
    .line 49
    iget-object v0, p0, Lh60/d;->h:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v2, v0

    .line 52
    check-cast v2, Ljava/lang/String;

    .line 53
    .line 54
    move-object v5, p1

    .line 55
    check-cast v5, Ll2/o;

    .line 56
    .line 57
    check-cast p2, Ljava/lang/Integer;

    .line 58
    .line 59
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    iget p1, p0, Lh60/d;->g:I

    .line 63
    .line 64
    or-int/lit8 p1, p1, 0x1

    .line 65
    .line 66
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    iget-boolean v3, p0, Lh60/d;->e:Z

    .line 71
    .line 72
    iget-boolean v4, p0, Lh60/d;->f:Z

    .line 73
    .line 74
    iget v7, p0, Lh60/d;->i:I

    .line 75
    .line 76
    invoke-static/range {v1 .. v7}, Lw00/a;->t(Ljava/lang/String;Ljava/lang/String;ZZLl2/o;II)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_1
    iget-object v0, p0, Lh60/d;->j:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v2, v0

    .line 83
    check-cast v2, Lx2/s;

    .line 84
    .line 85
    iget-object v0, p0, Lh60/d;->h:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v4, v0

    .line 88
    check-cast v4, Lay0/k;

    .line 89
    .line 90
    move-object v5, p1

    .line 91
    check-cast v5, Ll2/o;

    .line 92
    .line 93
    check-cast p2, Ljava/lang/Integer;

    .line 94
    .line 95
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    iget p1, p0, Lh60/d;->g:I

    .line 99
    .line 100
    or-int/lit8 p1, p1, 0x1

    .line 101
    .line 102
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 103
    .line 104
    .line 105
    move-result v6

    .line 106
    iget-boolean v1, p0, Lh60/d;->e:Z

    .line 107
    .line 108
    iget-boolean v3, p0, Lh60/d;->f:Z

    .line 109
    .line 110
    iget v7, p0, Lh60/d;->i:I

    .line 111
    .line 112
    invoke-static/range {v1 .. v7}, Li91/y3;->b(ZLx2/s;ZLay0/k;Ll2/o;II)V

    .line 113
    .line 114
    .line 115
    goto :goto_0

    .line 116
    :pswitch_2
    iget-object v0, p0, Lh60/d;->j:Ljava/lang/Object;

    .line 117
    .line 118
    move-object v3, v0

    .line 119
    check-cast v3, Lh50/i0;

    .line 120
    .line 121
    iget-object v0, p0, Lh60/d;->h:Ljava/lang/Object;

    .line 122
    .line 123
    move-object v5, v0

    .line 124
    check-cast v5, Lay0/a;

    .line 125
    .line 126
    move-object v6, p1

    .line 127
    check-cast v6, Ll2/o;

    .line 128
    .line 129
    check-cast p2, Ljava/lang/Integer;

    .line 130
    .line 131
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    iget p1, p0, Lh60/d;->i:I

    .line 135
    .line 136
    or-int/lit8 p1, p1, 0x1

    .line 137
    .line 138
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    iget-boolean v1, p0, Lh60/d;->e:Z

    .line 143
    .line 144
    iget-boolean v2, p0, Lh60/d;->f:Z

    .line 145
    .line 146
    iget v4, p0, Lh60/d;->g:I

    .line 147
    .line 148
    invoke-static/range {v1 .. v7}, Li50/z;->c(ZZLh50/i0;ILay0/a;Ll2/o;I)V

    .line 149
    .line 150
    .line 151
    goto :goto_0

    .line 152
    :pswitch_3
    iget-object v0, p0, Lh60/d;->j:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v4, v0

    .line 155
    check-cast v4, Ljava/lang/String;

    .line 156
    .line 157
    iget-object v0, p0, Lh60/d;->h:Ljava/lang/Object;

    .line 158
    .line 159
    move-object v5, v0

    .line 160
    check-cast v5, Lay0/a;

    .line 161
    .line 162
    move-object v6, p1

    .line 163
    check-cast v6, Ll2/o;

    .line 164
    .line 165
    check-cast p2, Ljava/lang/Integer;

    .line 166
    .line 167
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    iget p1, p0, Lh60/d;->i:I

    .line 171
    .line 172
    or-int/lit8 p1, p1, 0x1

    .line 173
    .line 174
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 175
    .line 176
    .line 177
    move-result v7

    .line 178
    iget-boolean v1, p0, Lh60/d;->e:Z

    .line 179
    .line 180
    iget-boolean v2, p0, Lh60/d;->f:Z

    .line 181
    .line 182
    iget v3, p0, Lh60/d;->g:I

    .line 183
    .line 184
    invoke-static/range {v1 .. v7}, Lh60/a;->c(ZZILjava/lang/String;Lay0/a;Ll2/o;I)V

    .line 185
    .line 186
    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
