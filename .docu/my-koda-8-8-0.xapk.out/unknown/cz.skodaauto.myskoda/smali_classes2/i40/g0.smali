.class public final synthetic Li40/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(JLay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Li40/g0;->e:J

    iput-object p3, p0, Li40/g0;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;JI)V
    .locals 0

    .line 2
    iput p4, p0, Li40/g0;->d:I

    iput-object p1, p0, Li40/g0;->f:Lay0/a;

    iput-wide p2, p0, Li40/g0;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Li40/g0;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v8, p1

    .line 25
    check-cast v8, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    new-instance v4, Li91/x2;

    .line 34
    .line 35
    iget-object p1, p0, Li40/g0;->f:Lay0/a;

    .line 36
    .line 37
    const/4 p2, 0x3

    .line 38
    invoke-direct {v4, p1, p2}, Li91/x2;-><init>(Lay0/a;I)V

    .line 39
    .line 40
    .line 41
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 42
    .line 43
    sget-object p2, Le3/j0;->a:Le3/i0;

    .line 44
    .line 45
    iget-wide v0, p0, Li40/g0;->e:J

    .line 46
    .line 47
    invoke-static {p1, v0, v1, p2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    const/high16 v9, 0x6000000

    .line 52
    .line 53
    const/16 v10, 0x2be

    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    const/4 v3, 0x0

    .line 57
    const/4 v5, 0x0

    .line 58
    const/4 v6, 0x1

    .line 59
    const/4 v7, 0x0

    .line 60
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 65
    .line 66
    .line 67
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0

    .line 70
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 71
    .line 72
    const/4 v1, 0x2

    .line 73
    const/4 v2, 0x1

    .line 74
    if-eq v0, v1, :cond_2

    .line 75
    .line 76
    move v0, v2

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    const/4 v0, 0x0

    .line 79
    :goto_2
    and-int/2addr p2, v2

    .line 80
    move-object v5, p1

    .line 81
    check-cast v5, Ll2/t;

    .line 82
    .line 83
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    if-eqz p1, :cond_3

    .line 88
    .line 89
    new-instance p1, La71/k;

    .line 90
    .line 91
    const/16 p2, 0xa

    .line 92
    .line 93
    iget-object v0, p0, Li40/g0;->f:Lay0/a;

    .line 94
    .line 95
    invoke-direct {p1, v0, p2}, La71/k;-><init>(Lay0/a;I)V

    .line 96
    .line 97
    .line 98
    const p2, 0x67207196

    .line 99
    .line 100
    .line 101
    invoke-static {p2, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    const/16 v6, 0x180

    .line 106
    .line 107
    const/4 v7, 0x1

    .line 108
    const/4 v1, 0x0

    .line 109
    iget-wide v2, p0, Li40/g0;->e:J

    .line 110
    .line 111
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_3
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_1
    and-int/lit8 v0, p2, 0x3

    .line 122
    .line 123
    const/4 v1, 0x2

    .line 124
    const/4 v2, 0x1

    .line 125
    if-eq v0, v1, :cond_4

    .line 126
    .line 127
    move v0, v2

    .line 128
    goto :goto_4

    .line 129
    :cond_4
    const/4 v0, 0x0

    .line 130
    :goto_4
    and-int/2addr p2, v2

    .line 131
    move-object v8, p1

    .line 132
    check-cast v8, Ll2/t;

    .line 133
    .line 134
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_5

    .line 139
    .line 140
    new-instance v4, Li91/x2;

    .line 141
    .line 142
    iget-object p1, p0, Li40/g0;->f:Lay0/a;

    .line 143
    .line 144
    const/4 p2, 0x3

    .line 145
    invoke-direct {v4, p1, p2}, Li91/x2;-><init>(Lay0/a;I)V

    .line 146
    .line 147
    .line 148
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 149
    .line 150
    sget-object p2, Le3/j0;->a:Le3/i0;

    .line 151
    .line 152
    iget-wide v0, p0, Li40/g0;->e:J

    .line 153
    .line 154
    invoke-static {p1, v0, v1, p2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    const/high16 v9, 0x6000000

    .line 159
    .line 160
    const/16 v10, 0x2be

    .line 161
    .line 162
    const/4 v2, 0x0

    .line 163
    const/4 v3, 0x0

    .line 164
    const/4 v5, 0x0

    .line 165
    const/4 v6, 0x1

    .line 166
    const/4 v7, 0x0

    .line 167
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 168
    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_5
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 172
    .line 173
    .line 174
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
