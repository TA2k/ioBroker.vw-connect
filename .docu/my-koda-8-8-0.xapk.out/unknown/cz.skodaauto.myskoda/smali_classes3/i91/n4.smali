.class public final synthetic Li91/n4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroidx/datastore/preferences/protobuf/k;


# direct methods
.method public synthetic constructor <init>(Landroidx/datastore/preferences/protobuf/k;I)V
    .locals 0

    .line 1
    const/4 p2, 0x2

    iput p2, p0, Li91/n4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/n4;->e:Landroidx/datastore/preferences/protobuf/k;

    return-void
.end method

.method public synthetic constructor <init>(Landroidx/datastore/preferences/protobuf/k;IB)V
    .locals 0

    .line 2
    iput p2, p0, Li91/n4;->d:I

    iput-object p1, p0, Li91/n4;->e:Landroidx/datastore/preferences/protobuf/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Li91/n4;->d:I

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
    iget-object p0, p0, Li91/n4;->e:Landroidx/datastore/preferences/protobuf/k;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Li91/o4;->c(Landroidx/datastore/preferences/protobuf/k;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    and-int/lit8 v0, p2, 0x3

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    const/4 v2, 0x1

    .line 34
    const/4 v3, 0x0

    .line 35
    if-eq v0, v1, :cond_0

    .line 36
    .line 37
    move v0, v2

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v0, v3

    .line 40
    :goto_0
    and-int/2addr p2, v2

    .line 41
    move-object v9, p1

    .line 42
    check-cast v9, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-eqz p1, :cond_2

    .line 49
    .line 50
    iget-object p0, p0, Li91/n4;->e:Landroidx/datastore/preferences/protobuf/k;

    .line 51
    .line 52
    iget p1, p0, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 53
    .line 54
    invoke-static {p1, v3, v9}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/k;->b()Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-eqz p0, :cond_1

    .line 63
    .line 64
    const p0, -0x75c37c54

    .line 65
    .line 66
    .line 67
    invoke-virtual {v9, p0}, Ll2/t;->Y(I)V

    .line 68
    .line 69
    .line 70
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 71
    .line 72
    invoke-virtual {v9, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    check-cast p0, Lj91/e;

    .line 77
    .line 78
    invoke-virtual {p0}, Lj91/e;->q()J

    .line 79
    .line 80
    .line 81
    move-result-wide p0

    .line 82
    :goto_1
    invoke-virtual {v9, v3}, Ll2/t;->q(Z)V

    .line 83
    .line 84
    .line 85
    move-wide v7, p0

    .line 86
    goto :goto_2

    .line 87
    :cond_1
    const p0, -0x75c37811

    .line 88
    .line 89
    .line 90
    invoke-virtual {v9, p0}, Ll2/t;->Y(I)V

    .line 91
    .line 92
    .line 93
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {v9, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lj91/e;

    .line 100
    .line 101
    invoke-virtual {p0}, Lj91/e;->r()J

    .line 102
    .line 103
    .line 104
    move-result-wide p0

    .line 105
    goto :goto_1

    .line 106
    :goto_2
    const/16 v10, 0x30

    .line 107
    .line 108
    const/4 v11, 0x4

    .line 109
    const/4 v5, 0x0

    .line 110
    const/4 v6, 0x0

    .line 111
    invoke-static/range {v4 .. v11}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_2
    invoke-virtual {v9}, Ll2/t;->R()V

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    and-int/lit8 v0, p2, 0x3

    .line 126
    .line 127
    const/4 v1, 0x2

    .line 128
    const/4 v2, 0x0

    .line 129
    const/4 v3, 0x1

    .line 130
    if-eq v0, v1, :cond_3

    .line 131
    .line 132
    move v0, v3

    .line 133
    goto :goto_4

    .line 134
    :cond_3
    move v0, v2

    .line 135
    :goto_4
    and-int/2addr p2, v3

    .line 136
    check-cast p1, Ll2/t;

    .line 137
    .line 138
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    if-eqz p2, :cond_4

    .line 143
    .line 144
    iget-object p0, p0, Li91/n4;->e:Landroidx/datastore/preferences/protobuf/k;

    .line 145
    .line 146
    invoke-static {p0, p1, v2}, Li91/o4;->c(Landroidx/datastore/preferences/protobuf/k;Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    goto :goto_5

    .line 150
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 151
    .line 152
    .line 153
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    return-object p0

    .line 156
    nop

    .line 157
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
