.class public final synthetic Lk1/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;II)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lk1/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk1/f1;->g:Ljava/lang/Object;

    iput-object p2, p0, Lk1/f1;->h:Ljava/lang/Object;

    iput-object p3, p0, Lk1/f1;->i:Ljava/lang/Object;

    iput p4, p0, Lk1/f1;->e:I

    iput p5, p0, Lk1/f1;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Lk1/t1;ILt3/e1;ILt3/s0;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lk1/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk1/f1;->g:Ljava/lang/Object;

    iput p2, p0, Lk1/f1;->e:I

    iput-object p3, p0, Lk1/f1;->h:Ljava/lang/Object;

    iput p4, p0, Lk1/f1;->f:I

    iput-object p5, p0, Lk1/f1;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>([Lt3/e1;Lk1/g1;II[I)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Lk1/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk1/f1;->g:Ljava/lang/Object;

    iput-object p2, p0, Lk1/f1;->h:Ljava/lang/Object;

    iput p3, p0, Lk1/f1;->e:I

    iput p4, p0, Lk1/f1;->f:I

    iput-object p5, p0, Lk1/f1;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lk1/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk1/f1;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object v0, p0, Lk1/f1;->h:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Landroid/content/Context;

    .line 15
    .line 16
    iget-object v0, p0, Lk1/f1;->i:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v3, v0

    .line 19
    check-cast v3, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 20
    .line 21
    iget v5, p0, Lk1/f1;->f:I

    .line 22
    .line 23
    move-object v6, p1

    .line 24
    check-cast v6, Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 25
    .line 26
    iget v4, p0, Lk1/f1;->e:I

    .line 27
    .line 28
    invoke-static/range {v1 .. v6}, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->c(Ljava/util/ArrayList;Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/GenXDispatcher;)Ltechnology/cariad/cat/genx/ClientManager;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget-object v0, p0, Lk1/f1;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lk1/t1;

    .line 36
    .line 37
    iget-object v1, p0, Lk1/f1;->h:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Lt3/e1;

    .line 40
    .line 41
    iget-object v2, p0, Lk1/f1;->i:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v2, Lt3/s0;

    .line 44
    .line 45
    check-cast p1, Lt3/d1;

    .line 46
    .line 47
    iget-object v0, v0, Lk1/t1;->t:Lay0/n;

    .line 48
    .line 49
    iget v3, v1, Lt3/e1;->d:I

    .line 50
    .line 51
    iget v4, p0, Lk1/f1;->e:I

    .line 52
    .line 53
    sub-int/2addr v4, v3

    .line 54
    iget v3, v1, Lt3/e1;->e:I

    .line 55
    .line 56
    iget p0, p0, Lk1/f1;->f:I

    .line 57
    .line 58
    sub-int/2addr p0, v3

    .line 59
    int-to-long v3, v4

    .line 60
    const/16 v5, 0x20

    .line 61
    .line 62
    shl-long/2addr v3, v5

    .line 63
    int-to-long v5, p0

    .line 64
    const-wide v7, 0xffffffffL

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    and-long/2addr v5, v7

    .line 70
    or-long/2addr v3, v5

    .line 71
    new-instance p0, Lt4/l;

    .line 72
    .line 73
    invoke-direct {p0, v3, v4}, Lt4/l;-><init>(J)V

    .line 74
    .line 75
    .line 76
    invoke-interface {v2}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-interface {v0, p0, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    check-cast p0, Lt4/j;

    .line 85
    .line 86
    iget-wide v2, p0, Lt4/j;->a:J

    .line 87
    .line 88
    invoke-static {p1, v1, v2, v3}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 89
    .line 90
    .line 91
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_1
    iget-object v0, p0, Lk1/f1;->g:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, [Lt3/e1;

    .line 97
    .line 98
    iget-object v1, p0, Lk1/f1;->h:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v1, Lk1/g1;

    .line 101
    .line 102
    iget-object v2, p0, Lk1/f1;->i:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v2, [I

    .line 105
    .line 106
    check-cast p1, Lt3/d1;

    .line 107
    .line 108
    array-length v3, v0

    .line 109
    const/4 v4, 0x0

    .line 110
    move v5, v4

    .line 111
    move v6, v5

    .line 112
    :goto_0
    if-ge v5, v3, :cond_3

    .line 113
    .line 114
    aget-object v7, v0, v5

    .line 115
    .line 116
    add-int/lit8 v8, v6, 0x1

    .line 117
    .line 118
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v7}, Lt3/e1;->l()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v9

    .line 125
    instance-of v10, v9, Lk1/d1;

    .line 126
    .line 127
    const/4 v11, 0x0

    .line 128
    if-eqz v10, :cond_0

    .line 129
    .line 130
    check-cast v9, Lk1/d1;

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_0
    move-object v9, v11

    .line 134
    :goto_1
    if-eqz v9, :cond_1

    .line 135
    .line 136
    iget-object v11, v9, Lk1/d1;->c:Lk1/d;

    .line 137
    .line 138
    :cond_1
    iget v9, p0, Lk1/f1;->e:I

    .line 139
    .line 140
    if-eqz v11, :cond_2

    .line 141
    .line 142
    iget v10, v7, Lt3/e1;->e:I

    .line 143
    .line 144
    sub-int/2addr v9, v10

    .line 145
    sget-object v10, Lt4/m;->d:Lt4/m;

    .line 146
    .line 147
    iget v12, p0, Lk1/f1;->f:I

    .line 148
    .line 149
    invoke-virtual {v11, v9, v10, v7, v12}, Lk1/d;->e(ILt4/m;Lt3/e1;I)I

    .line 150
    .line 151
    .line 152
    move-result v9

    .line 153
    goto :goto_2

    .line 154
    :cond_2
    iget-object v10, v1, Lk1/g1;->b:Lx2/i;

    .line 155
    .line 156
    iget v11, v7, Lt3/e1;->e:I

    .line 157
    .line 158
    sub-int/2addr v9, v11

    .line 159
    invoke-virtual {v10, v4, v9}, Lx2/i;->a(II)I

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    :goto_2
    aget v6, v2, v6

    .line 164
    .line 165
    invoke-static {p1, v7, v6, v9}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 166
    .line 167
    .line 168
    add-int/lit8 v5, v5, 0x1

    .line 169
    .line 170
    move v6, v8

    .line 171
    goto :goto_0

    .line 172
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
