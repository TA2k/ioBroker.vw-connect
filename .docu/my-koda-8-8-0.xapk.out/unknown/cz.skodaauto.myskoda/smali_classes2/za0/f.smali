.class public final synthetic Lza0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lza0/f;->d:I

    iput-object p3, p0, Lza0/f;->e:Ljava/lang/Object;

    iput-object p4, p0, Lza0/f;->f:Ljava/lang/Object;

    iput-object p5, p0, Lza0/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lza0/q;Lya0/a;Lyl/l;I)V
    .locals 0

    .line 2
    const/4 p4, 0x2

    iput p4, p0, Lza0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lza0/f;->e:Ljava/lang/Object;

    iput-object p2, p0, Lza0/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lza0/f;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lza0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/List;

    .line 9
    .line 10
    iget-object v1, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lyl/l;

    .line 13
    .line 14
    iget-object p0, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lay0/k;

    .line 17
    .line 18
    check-cast p1, Ll2/o;

    .line 19
    .line 20
    check-cast p2, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    const/4 p2, 0x1

    .line 26
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    invoke-static {v0, v1, p0, p1, p2}, Lzj0/j;->j(Ljava/util/List;Lyl/l;Lay0/k;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lxh/e;

    .line 39
    .line 40
    iget-object v1, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lxh/e;

    .line 43
    .line 44
    iget-object p0, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lyy0/l1;

    .line 47
    .line 48
    check-cast p1, Ll2/o;

    .line 49
    .line 50
    check-cast p2, Ljava/lang/Integer;

    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const/4 p2, 0x1

    .line 56
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    invoke-static {v0, v1, p0, p1, p2}, Ljp/y0;->a(Lxh/e;Lxh/e;Lyy0/l1;Ll2/o;I)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :pswitch_1
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Ljava/lang/String;

    .line 67
    .line 68
    iget-object v1, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v1, Lx2/s;

    .line 71
    .line 72
    iget-object p0, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lt2/b;

    .line 75
    .line 76
    check-cast p1, Ll2/o;

    .line 77
    .line 78
    check-cast p2, Ljava/lang/Integer;

    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    const/16 p2, 0x181

    .line 84
    .line 85
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    invoke-static {v0, v1, p0, p1, p2}, Lzb/b;->c(Ljava/lang/String;Lx2/s;Lt2/b;Ll2/o;I)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_2
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lza0/q;

    .line 96
    .line 97
    iget-object v1, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v1, Lya0/a;

    .line 100
    .line 101
    iget-object p0, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast p0, Lyl/l;

    .line 104
    .line 105
    check-cast p1, Ll2/o;

    .line 106
    .line 107
    check-cast p2, Ljava/lang/Integer;

    .line 108
    .line 109
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    const/16 p2, 0x201

    .line 113
    .line 114
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    invoke-virtual {v0, v1, p0, p1, p2}, Lza0/q;->d(Lya0/a;Lyl/l;Ll2/o;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :pswitch_3
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Lza0/q;

    .line 125
    .line 126
    iget-object v1, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v1, Ly6/q;

    .line 129
    .line 130
    iget-object p0, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p0, Ljava/lang/String;

    .line 133
    .line 134
    check-cast p1, Ll2/o;

    .line 135
    .line 136
    check-cast p2, Ljava/lang/Integer;

    .line 137
    .line 138
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    const/16 p2, 0x201

    .line 142
    .line 143
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    invoke-virtual {v0, v1, p0, p1, p2}, Lza0/q;->m(Ly6/q;Ljava/lang/String;Ll2/o;I)V

    .line 148
    .line 149
    .line 150
    goto :goto_0

    .line 151
    :pswitch_4
    iget-object v0, p0, Lza0/f;->e:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v0, Lza0/q;

    .line 154
    .line 155
    iget-object v1, p0, Lza0/f;->f:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v1, Ly6/q;

    .line 158
    .line 159
    iget-object p0, p0, Lza0/f;->g:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p0, Lya0/a;

    .line 162
    .line 163
    check-cast p1, Ll2/o;

    .line 164
    .line 165
    check-cast p2, Ljava/lang/Integer;

    .line 166
    .line 167
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    const/16 p2, 0x201

    .line 171
    .line 172
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 173
    .line 174
    .line 175
    move-result p2

    .line 176
    invoke-virtual {v0, v1, p0, p1, p2}, Lza0/q;->l(Ly6/q;Lya0/a;Ll2/o;I)V

    .line 177
    .line 178
    .line 179
    goto/16 :goto_0

    .line 180
    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
