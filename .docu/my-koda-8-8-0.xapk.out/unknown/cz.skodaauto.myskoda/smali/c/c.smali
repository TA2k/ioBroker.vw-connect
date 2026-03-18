.class public final synthetic Lc/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, Lc/c;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lc/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lvn0/a;

    .line 9
    .line 10
    check-cast p1, Ljava/util/Map;

    .line 11
    .line 12
    const-string v0, "permissionResults"

    .line 13
    .line 14
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/4 v1, 0x0

    .line 30
    if-eqz v0, :cond_6

    .line 31
    .line 32
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Ljava/util/Map$Entry;

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Ljava/lang/String;

    .line 43
    .line 44
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Ljava/lang/Boolean;

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    sparse-switch v3, :sswitch_data_0

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :sswitch_0
    const-string v3, "android.permission.BLUETOOTH_SCAN"

    .line 62
    .line 63
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-nez v2, :cond_3

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :sswitch_1
    const-string v3, "android.permission.CAMERA"

    .line 71
    .line 72
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-nez v2, :cond_1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    sget-object v2, Lun0/a;->d:Lun0/a;

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :sswitch_2
    const-string v3, "android.permission.ACCESS_COARSE_LOCATION"

    .line 83
    .line 84
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-nez v2, :cond_2

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    sget-object v2, Lun0/a;->e:Lun0/a;

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :sswitch_3
    const-string v3, "android.permission.BLUETOOTH_CONNECT"

    .line 95
    .line 96
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-nez v2, :cond_3

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_3
    sget-object v2, Lun0/a;->f:Lun0/a;

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :sswitch_4
    const-string v3, "android.permission.ACCESS_FINE_LOCATION"

    .line 107
    .line 108
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :sswitch_5
    const-string v3, "android.permission.POST_NOTIFICATIONS"

    .line 113
    .line 114
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    if-nez v2, :cond_4

    .line 119
    .line 120
    :goto_0
    move-object v2, v1

    .line 121
    goto :goto_1

    .line 122
    :cond_4
    sget-object v2, Lun0/a;->g:Lun0/a;

    .line 123
    .line 124
    :goto_1
    if-eqz v2, :cond_5

    .line 125
    .line 126
    new-instance v1, Llx0/l;

    .line 127
    .line 128
    invoke-direct {v1, v2, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :cond_5
    if-eqz v1, :cond_0

    .line 132
    .line 133
    :cond_6
    if-eqz v1, :cond_7

    .line 134
    .line 135
    iget-object p1, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p1, Lun0/a;

    .line 138
    .line 139
    iget-object v0, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, Ljava/lang/Boolean;

    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    invoke-virtual {p0, p1, v0}, Lvn0/a;->a(Lun0/a;Z)V

    .line 148
    .line 149
    .line 150
    :cond_7
    return-void

    .line 151
    :pswitch_0
    check-cast p0, Lfd0/b;

    .line 152
    .line 153
    check-cast p1, Le/a;

    .line 154
    .line 155
    const-string v0, "it"

    .line 156
    .line 157
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    iget-object p0, p0, Lfd0/b;->b:Lzc0/b;

    .line 161
    .line 162
    new-instance p1, Lne0/e;

    .line 163
    .line 164
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    invoke-direct {p1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    iget-object p0, p0, Lzc0/b;->c:Lyy0/q1;

    .line 170
    .line 171
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    return-void

    .line 175
    :pswitch_1
    check-cast p0, Ll2/b1;

    .line 176
    .line 177
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    check-cast p0, Lay0/k;

    .line 182
    .line 183
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    return-void

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 188
    .line 189
    .line 190
    .line 191
    .line 192
    .line 193
    .line 194
    .line 195
    :sswitch_data_0
    .sparse-switch
        -0x72ca2557 -> :sswitch_5
        -0x70918bc1 -> :sswitch_4
        -0x2f9abb27 -> :sswitch_3
        -0x3c1ac56 -> :sswitch_2
        0x1b9efa65 -> :sswitch_1
        0x7aed10ce -> :sswitch_0
    .end sparse-switch
.end method
