.class public final synthetic Lco0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lbo0/q;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lbo0/q;Lay0/a;I)V
    .locals 0

    .line 1
    const/4 p3, 0x2

    iput p3, p0, Lco0/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lco0/k;->e:Lbo0/q;

    iput-object p2, p0, Lco0/k;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lbo0/q;Lay0/a;IB)V
    .locals 0

    .line 2
    iput p3, p0, Lco0/k;->d:I

    iput-object p1, p0, Lco0/k;->e:Lbo0/q;

    iput-object p2, p0, Lco0/k;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lco0/k;->d:I

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
    iget-object v0, p0, Lco0/k;->e:Lbo0/q;

    .line 19
    .line 20
    iget-object p0, p0, Lco0/k;->f:Lay0/a;

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Lco0/c;->k(Lbo0/q;Lay0/a;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    and-int/lit8 v0, p2, 0x3

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x1

    .line 37
    if-eq v0, v1, :cond_0

    .line 38
    .line 39
    move v0, v3

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move v0, v2

    .line 42
    :goto_0
    and-int/2addr p2, v3

    .line 43
    move-object v7, p1

    .line 44
    check-cast v7, Ll2/t;

    .line 45
    .line 46
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_2

    .line 51
    .line 52
    iget-object p1, p0, Lco0/k;->e:Lbo0/q;

    .line 53
    .line 54
    iget-boolean p2, p1, Lbo0/q;->i:Z

    .line 55
    .line 56
    if-eqz p2, :cond_1

    .line 57
    .line 58
    const p2, -0x539f29c3

    .line 59
    .line 60
    .line 61
    invoke-virtual {v7, p2}, Ll2/t;->Y(I)V

    .line 62
    .line 63
    .line 64
    new-instance p2, Lal/d;

    .line 65
    .line 66
    const/16 v0, 0xb

    .line 67
    .line 68
    iget-object p0, p0, Lco0/k;->f:Lay0/a;

    .line 69
    .line 70
    invoke-direct {p2, v0, p1, p0}, Lal/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    const p0, -0xb24765a

    .line 74
    .line 75
    .line 76
    invoke-static {p0, v7, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    const/16 v8, 0x180

    .line 81
    .line 82
    const/4 v9, 0x3

    .line 83
    const/4 v3, 0x0

    .line 84
    const-wide/16 v4, 0x0

    .line 85
    .line 86
    invoke-static/range {v3 .. v9}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 87
    .line 88
    .line 89
    :goto_1
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_1
    const p0, -0x53d766f6

    .line 94
    .line 95
    .line 96
    invoke-virtual {v7, p0}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    and-int/lit8 v0, p2, 0x3

    .line 111
    .line 112
    const/4 v1, 0x2

    .line 113
    const/4 v2, 0x1

    .line 114
    if-eq v0, v1, :cond_3

    .line 115
    .line 116
    move v0, v2

    .line 117
    goto :goto_3

    .line 118
    :cond_3
    const/4 v0, 0x0

    .line 119
    :goto_3
    and-int/2addr p2, v2

    .line 120
    move-object v8, p1

    .line 121
    check-cast v8, Ll2/t;

    .line 122
    .line 123
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-eqz p1, :cond_4

    .line 128
    .line 129
    iget-object p1, p0, Lco0/k;->e:Lbo0/q;

    .line 130
    .line 131
    iget-object v2, p1, Lbo0/q;->a:Ljava/lang/String;

    .line 132
    .line 133
    new-instance v4, Li91/w2;

    .line 134
    .line 135
    iget-object p0, p0, Lco0/k;->f:Lay0/a;

    .line 136
    .line 137
    const/4 p1, 0x3

    .line 138
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 139
    .line 140
    .line 141
    const/4 v9, 0x0

    .line 142
    const/16 v10, 0x3bd

    .line 143
    .line 144
    const/4 v1, 0x0

    .line 145
    const/4 v3, 0x0

    .line 146
    const/4 v5, 0x0

    .line 147
    const/4 v6, 0x0

    .line 148
    const/4 v7, 0x0

    .line 149
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 150
    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_4
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 154
    .line 155
    .line 156
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
