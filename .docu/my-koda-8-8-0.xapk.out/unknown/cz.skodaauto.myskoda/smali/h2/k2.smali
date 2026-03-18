.class public final synthetic Lh2/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Z

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lh2/g4;Lx2/s;Lh2/g2;Lh2/z1;Lay0/n;Lay0/n;ZLc3/q;I)V
    .locals 0

    .line 1
    const/4 p9, 0x1

    iput p9, p0, Lh2/k2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/k2;->k:Ljava/lang/Object;

    iput-object p2, p0, Lh2/k2;->e:Ljava/lang/Object;

    iput-object p3, p0, Lh2/k2;->f:Ljava/lang/Object;

    iput-object p4, p0, Lh2/k2;->g:Ljava/lang/Object;

    iput-object p5, p0, Lh2/k2;->h:Ljava/lang/Object;

    iput-object p6, p0, Lh2/k2;->l:Ljava/lang/Object;

    iput-boolean p7, p0, Lh2/k2;->i:Z

    iput-object p8, p0, Lh2/k2;->j:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;II)V
    .locals 0

    .line 2
    iput p10, p0, Lh2/k2;->d:I

    iput-object p1, p0, Lh2/k2;->k:Ljava/lang/Object;

    iput-object p2, p0, Lh2/k2;->e:Ljava/lang/Object;

    iput-object p3, p0, Lh2/k2;->f:Ljava/lang/Object;

    iput-object p4, p0, Lh2/k2;->g:Ljava/lang/Object;

    iput-object p5, p0, Lh2/k2;->l:Ljava/lang/Object;

    iput-object p6, p0, Lh2/k2;->h:Ljava/lang/Object;

    iput-boolean p7, p0, Lh2/k2;->i:Z

    iput-object p8, p0, Lh2/k2;->j:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lh2/k2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/k2;->k:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lza0/q;

    .line 10
    .line 11
    iget-object v0, p0, Lh2/k2;->e:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ly6/q;

    .line 15
    .line 16
    iget-object v0, p0, Lh2/k2;->f:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v0, p0, Lh2/k2;->g:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v4, v0

    .line 24
    check-cast v4, Ljava/lang/String;

    .line 25
    .line 26
    iget-object v0, p0, Lh2/k2;->l:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v5, v0

    .line 29
    check-cast v5, Ljava/lang/String;

    .line 30
    .line 31
    iget-object v0, p0, Lh2/k2;->h:Ljava/lang/Object;

    .line 32
    .line 33
    move-object v6, v0

    .line 34
    check-cast v6, Ljava/lang/String;

    .line 35
    .line 36
    iget-object v0, p0, Lh2/k2;->j:Ljava/lang/Object;

    .line 37
    .line 38
    move-object v8, v0

    .line 39
    check-cast v8, Ljava/lang/Boolean;

    .line 40
    .line 41
    move-object v9, p1

    .line 42
    check-cast v9, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const p1, 0x1000001

    .line 50
    .line 51
    .line 52
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v10

    .line 56
    iget-boolean v7, p0, Lh2/k2;->i:Z

    .line 57
    .line 58
    invoke-virtual/range {v1 .. v10}, Lza0/q;->e(Ly6/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Boolean;Ll2/o;I)V

    .line 59
    .line 60
    .line 61
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    return-object p0

    .line 64
    :pswitch_0
    iget-object v0, p0, Lh2/k2;->k:Ljava/lang/Object;

    .line 65
    .line 66
    move-object v1, v0

    .line 67
    check-cast v1, Lh2/g4;

    .line 68
    .line 69
    iget-object v0, p0, Lh2/k2;->e:Ljava/lang/Object;

    .line 70
    .line 71
    move-object v2, v0

    .line 72
    check-cast v2, Lx2/s;

    .line 73
    .line 74
    iget-object v0, p0, Lh2/k2;->f:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v3, v0

    .line 77
    check-cast v3, Lh2/g2;

    .line 78
    .line 79
    iget-object v0, p0, Lh2/k2;->g:Ljava/lang/Object;

    .line 80
    .line 81
    move-object v4, v0

    .line 82
    check-cast v4, Lh2/z1;

    .line 83
    .line 84
    iget-object v0, p0, Lh2/k2;->h:Ljava/lang/Object;

    .line 85
    .line 86
    move-object v5, v0

    .line 87
    check-cast v5, Lay0/n;

    .line 88
    .line 89
    iget-object v0, p0, Lh2/k2;->l:Ljava/lang/Object;

    .line 90
    .line 91
    move-object v6, v0

    .line 92
    check-cast v6, Lay0/n;

    .line 93
    .line 94
    iget-object v0, p0, Lh2/k2;->j:Ljava/lang/Object;

    .line 95
    .line 96
    move-object v8, v0

    .line 97
    check-cast v8, Lc3/q;

    .line 98
    .line 99
    move-object v9, p1

    .line 100
    check-cast v9, Ll2/o;

    .line 101
    .line 102
    check-cast p2, Ljava/lang/Integer;

    .line 103
    .line 104
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const p1, 0x180001

    .line 108
    .line 109
    .line 110
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 111
    .line 112
    .line 113
    move-result v10

    .line 114
    iget-boolean v7, p0, Lh2/k2;->i:Z

    .line 115
    .line 116
    invoke-static/range {v1 .. v10}, Lh2/f4;->a(Lh2/g4;Lx2/s;Lh2/g2;Lh2/z1;Lay0/n;Lay0/n;ZLc3/q;Ll2/o;I)V

    .line 117
    .line 118
    .line 119
    goto :goto_0

    .line 120
    :pswitch_1
    iget-object v0, p0, Lh2/k2;->k:Ljava/lang/Object;

    .line 121
    .line 122
    move-object v1, v0

    .line 123
    check-cast v1, Lh2/o3;

    .line 124
    .line 125
    iget-object v0, p0, Lh2/k2;->e:Ljava/lang/Object;

    .line 126
    .line 127
    move-object v2, v0

    .line 128
    check-cast v2, Lx2/s;

    .line 129
    .line 130
    iget-object v0, p0, Lh2/k2;->f:Ljava/lang/Object;

    .line 131
    .line 132
    move-object v3, v0

    .line 133
    check-cast v3, Lh2/g2;

    .line 134
    .line 135
    iget-object v0, p0, Lh2/k2;->g:Ljava/lang/Object;

    .line 136
    .line 137
    move-object v4, v0

    .line 138
    check-cast v4, Lh2/z1;

    .line 139
    .line 140
    iget-object v0, p0, Lh2/k2;->l:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v5, v0

    .line 143
    check-cast v5, Lt2/b;

    .line 144
    .line 145
    iget-object v0, p0, Lh2/k2;->h:Ljava/lang/Object;

    .line 146
    .line 147
    move-object v6, v0

    .line 148
    check-cast v6, Lay0/n;

    .line 149
    .line 150
    iget-object v0, p0, Lh2/k2;->j:Ljava/lang/Object;

    .line 151
    .line 152
    move-object v8, v0

    .line 153
    check-cast v8, Lc3/q;

    .line 154
    .line 155
    move-object v9, p1

    .line 156
    check-cast v9, Ll2/o;

    .line 157
    .line 158
    check-cast p2, Ljava/lang/Integer;

    .line 159
    .line 160
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    const/16 p1, 0x6001

    .line 164
    .line 165
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 166
    .line 167
    .line 168
    move-result v10

    .line 169
    iget-boolean v7, p0, Lh2/k2;->i:Z

    .line 170
    .line 171
    invoke-static/range {v1 .. v10}, Lh2/m3;->b(Lh2/o3;Lx2/s;Lh2/g2;Lh2/z1;Lt2/b;Lay0/n;ZLc3/q;Ll2/o;I)V

    .line 172
    .line 173
    .line 174
    goto :goto_0

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
