.class public final Lip/s;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lip/s;->f:I

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-direct {p0, p1}, Lap0/o;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final t(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget p0, p0, Lip/s;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llp/gg;

    .line 7
    .line 8
    new-instance p0, Llp/lg;

    .line 9
    .line 10
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    new-instance v1, Llp/ig;

    .line 15
    .line 16
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-virtual {v2}, Lfv/f;->b()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    invoke-direct {v1, v2, p1}, Llp/ig;-><init>(Landroid/content/Context;Llp/gg;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p1, Llp/gg;->a:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {v0}, Lfv/f;->b()Landroid/content/Context;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    const-class v3, Lfv/i;

    .line 34
    .line 35
    invoke-virtual {v0, v3}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lfv/i;

    .line 40
    .line 41
    invoke-direct {p0, v2, v0, v1, p1}, Llp/lg;-><init>(Landroid/content/Context;Lfv/i;Llp/ig;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_0
    check-cast p1, Lkp/ia;

    .line 46
    .line 47
    new-instance p0, Lkp/la;

    .line 48
    .line 49
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    new-instance v1, Lkp/ka;

    .line 54
    .line 55
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v2}, Lfv/f;->b()Landroid/content/Context;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-direct {v1, v2, p1}, Lkp/ka;-><init>(Landroid/content/Context;Lkp/ia;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Lfv/f;->b()Landroid/content/Context;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    const-class v2, Lfv/i;

    .line 71
    .line 72
    invoke-virtual {v0, v2}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Lfv/i;

    .line 77
    .line 78
    invoke-direct {p0, p1, v0, v1}, Lkp/la;-><init>(Landroid/content/Context;Lfv/i;Lkp/ka;)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_1
    check-cast p1, Ljp/rg;

    .line 83
    .line 84
    new-instance p0, Ljp/vg;

    .line 85
    .line 86
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    new-instance v1, Ljp/tg;

    .line 91
    .line 92
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-virtual {v2}, Lfv/f;->b()Landroid/content/Context;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    invoke-direct {v1, v2, p1}, Ljp/tg;-><init>(Landroid/content/Context;Ljp/rg;)V

    .line 101
    .line 102
    .line 103
    iget-object p1, p1, Ljp/rg;->a:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {v0}, Lfv/f;->b()Landroid/content/Context;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const-class v3, Lfv/i;

    .line 110
    .line 111
    invoke-virtual {v0, v3}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    check-cast v0, Lfv/i;

    .line 116
    .line 117
    invoke-direct {p0, v2, v0, v1, p1}, Ljp/vg;-><init>(Landroid/content/Context;Lfv/i;Ljp/tg;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_2
    check-cast p1, Lip/o;

    .line 122
    .line 123
    new-instance p0, Lip/r;

    .line 124
    .line 125
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-virtual {v1}, Lfv/f;->b()Landroid/content/Context;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    new-instance v2, Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    new-instance p1, Lpy/a;

    .line 146
    .line 147
    const/4 v3, 0x7

    .line 148
    invoke-direct {p1, v3}, Lpy/a;-><init>(I)V

    .line 149
    .line 150
    .line 151
    sget-object v3, Lpn/a;->e:Lpn/a;

    .line 152
    .line 153
    invoke-static {v1}, Lrn/r;->b(Landroid/content/Context;)V

    .line 154
    .line 155
    .line 156
    invoke-static {}, Lrn/r;->a()Lrn/r;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    invoke-virtual {v1, v3}, Lrn/r;->c(Lrn/l;)Lrn/p;

    .line 161
    .line 162
    .line 163
    sget-object v1, Lpn/a;->d:Ljava/util/Set;

    .line 164
    .line 165
    new-instance v3, Lon/c;

    .line 166
    .line 167
    const-string v4, "json"

    .line 168
    .line 169
    invoke-direct {v3, v4}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    invoke-interface {v1, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    invoke-virtual {v0}, Lfv/f;->b()Landroid/content/Context;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    const-class v1, Lfv/i;

    .line 183
    .line 184
    invoke-virtual {v0, v1}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    check-cast v0, Lfv/i;

    .line 189
    .line 190
    invoke-direct {p0, p1, v0}, Lip/r;-><init>(Landroid/content/Context;Lfv/i;)V

    .line 191
    .line 192
    .line 193
    return-object p0

    .line 194
    nop

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
