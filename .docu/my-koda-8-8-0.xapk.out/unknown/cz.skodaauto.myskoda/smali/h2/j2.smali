.class public final synthetic Lh2/j2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p6, p0, Lh2/j2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/j2;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/j2;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/j2;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/j2;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lh2/j2;->i:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lh2/j2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/j2;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 9
    .line 10
    iget-object v1, p0, Lh2/j2;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 13
    .line 14
    iget-object v2, p0, Lh2/j2;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, [B

    .line 17
    .line 18
    iget-object v3, p0, Lh2/j2;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;

    .line 21
    .line 22
    iget-object p0, p0, Lh2/j2;->i:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Landroid/bluetooth/BluetoothDevice;

    .line 25
    .line 26
    invoke-static {v0, v1, v2, v3, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->l(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;[BLtechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;Landroid/bluetooth/BluetoothDevice;)Llx0/b0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object v0, p0, Lh2/j2;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, [B

    .line 34
    .line 35
    iget-object v1, p0, Lh2/j2;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Landroid/bluetooth/le/ScanResult;

    .line 38
    .line 39
    iget-object v2, p0, Lh2/j2;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v2, Landroid/bluetooth/BluetoothDevice;

    .line 42
    .line 43
    iget-object v3, p0, Lh2/j2;->h:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v3, Ltechnology/cariad/cat/genx/Antenna;

    .line 46
    .line 47
    iget-object p0, p0, Lh2/j2;->i:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Ljava/time/Instant;

    .line 50
    .line 51
    invoke-static {v0, v1, v2, v3, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager$scanCallback$1;->j([BLandroid/bluetooth/le/ScanResult;Landroid/bluetooth/BluetoothDevice;Ltechnology/cariad/cat/genx/Antenna;Ljava/time/Instant;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object v0, p0, Lh2/j2;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Ll2/b1;

    .line 59
    .line 60
    iget-object v1, p0, Lh2/j2;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Lym/g;

    .line 63
    .line 64
    iget-object v2, p0, Lh2/j2;->g:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v2, Ll2/b1;

    .line 67
    .line 68
    iget-object v3, p0, Lh2/j2;->h:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v3, Lym/g;

    .line 71
    .line 72
    iget-object p0, p0, Lh2/j2;->i:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lym/g;

    .line 75
    .line 76
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    check-cast v0, Ljava/lang/Boolean;

    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_0

    .line 87
    .line 88
    invoke-virtual {v1}, Lym/g;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ljava/lang/Number;

    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    goto :goto_0

    .line 99
    :cond_0
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    check-cast v0, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-eqz v0, :cond_1

    .line 110
    .line 111
    invoke-virtual {v3}, Lym/g;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Ljava/lang/Number;

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    goto :goto_0

    .line 122
    :cond_1
    invoke-virtual {p0}, Lym/g;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, Ljava/lang/Number;

    .line 127
    .line 128
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    :goto_0
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0

    .line 137
    :pswitch_2
    iget-object v0, p0, Lh2/j2;->e:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v2, v0

    .line 140
    check-cast v2, Ljava/lang/Long;

    .line 141
    .line 142
    iget-object v0, p0, Lh2/j2;->f:Ljava/lang/Object;

    .line 143
    .line 144
    move-object v3, v0

    .line 145
    check-cast v3, Ljava/lang/Long;

    .line 146
    .line 147
    iget-object v0, p0, Lh2/j2;->g:Ljava/lang/Object;

    .line 148
    .line 149
    move-object v4, v0

    .line 150
    check-cast v4, Lgy0/j;

    .line 151
    .line 152
    iget-object v0, p0, Lh2/j2;->h:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v6, v0

    .line 155
    check-cast v6, Lh2/e8;

    .line 156
    .line 157
    iget-object p0, p0, Lh2/j2;->i:Ljava/lang/Object;

    .line 158
    .line 159
    move-object v7, p0

    .line 160
    check-cast v7, Ljava/util/Locale;

    .line 161
    .line 162
    new-instance v1, Lh2/o3;

    .line 163
    .line 164
    const/4 v5, 0x0

    .line 165
    invoke-direct/range {v1 .. v7}, Lh2/o3;-><init>(Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V

    .line 166
    .line 167
    .line 168
    return-object v1

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
