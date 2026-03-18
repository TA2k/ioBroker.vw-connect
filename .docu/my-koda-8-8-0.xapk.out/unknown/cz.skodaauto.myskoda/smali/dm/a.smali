.class public final Ldm/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm/f;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ldm/a;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lmm/n;Lyl/r;)Ldm/g;
    .locals 6

    .line 1
    iget p0, p0, Ldm/a;->a:I

    .line 2
    .line 3
    const/4 p3, 0x0

    .line 4
    const/4 v0, 0x1

    .line 5
    const/4 v1, 0x2

    .line 6
    const/4 v2, 0x3

    .line 7
    const-string v3, "android_asset"

    .line 8
    .line 9
    const-string v4, "file"

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    packed-switch p0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p1, Lyl/t;

    .line 16
    .line 17
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 18
    .line 19
    const-string p3, "android.resource"

    .line 20
    .line 21
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v5, Ldm/b;

    .line 29
    .line 30
    const/4 p0, 0x5

    .line 31
    invoke-direct {v5, p1, p2, p0}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    return-object v5

    .line 35
    :pswitch_0
    check-cast p1, Lyl/t;

    .line 36
    .line 37
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 38
    .line 39
    const-string p3, "jar:file"

    .line 40
    .line 41
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    new-instance v5, Ldm/b;

    .line 49
    .line 50
    const/4 p0, 0x4

    .line 51
    invoke-direct {v5, p1, p2, p0}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 52
    .line 53
    .line 54
    :goto_1
    return-object v5

    .line 55
    :pswitch_1
    check-cast p1, Lyl/t;

    .line 56
    .line 57
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 58
    .line 59
    if-eqz p0, :cond_2

    .line 60
    .line 61
    invoke-virtual {p0, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_4

    .line 66
    .line 67
    :cond_2
    iget-object p0, p1, Lyl/t;->e:Ljava/lang/String;

    .line 68
    .line 69
    if-eqz p0, :cond_4

    .line 70
    .line 71
    sget-object p0, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 72
    .line 73
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_3

    .line 80
    .line 81
    invoke-static {p1}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-static {p0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_3

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_3
    new-instance v5, Ldm/b;

    .line 97
    .line 98
    invoke-direct {v5, p1, p2, v2}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 99
    .line 100
    .line 101
    :cond_4
    :goto_2
    return-object v5

    .line 102
    :pswitch_2
    check-cast p1, Landroid/graphics/drawable/Drawable;

    .line 103
    .line 104
    new-instance p0, Ldm/c;

    .line 105
    .line 106
    invoke-direct {p0, p1, p2, v2}, Ldm/c;-><init>(Ljava/lang/Object;Lmm/n;I)V

    .line 107
    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_3
    check-cast p1, Lyl/t;

    .line 111
    .line 112
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 113
    .line 114
    const-string p3, "data"

    .line 115
    .line 116
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    if-nez p0, :cond_5

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :cond_5
    new-instance v5, Ldm/b;

    .line 124
    .line 125
    invoke-direct {v5, p1, p2, v1}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 126
    .line 127
    .line 128
    :goto_3
    return-object v5

    .line 129
    :pswitch_4
    check-cast p1, Lyl/t;

    .line 130
    .line 131
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 132
    .line 133
    const-string p3, "content"

    .line 134
    .line 135
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-nez p0, :cond_6

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_6
    new-instance v5, Ldm/b;

    .line 143
    .line 144
    invoke-direct {v5, p1, p2, v0}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 145
    .line 146
    .line 147
    :goto_4
    return-object v5

    .line 148
    :pswitch_5
    check-cast p1, Ljava/nio/ByteBuffer;

    .line 149
    .line 150
    new-instance p0, Ldm/c;

    .line 151
    .line 152
    invoke-direct {p0, p1, p2, v1}, Ldm/c;-><init>(Ljava/lang/Object;Lmm/n;I)V

    .line 153
    .line 154
    .line 155
    return-object p0

    .line 156
    :pswitch_6
    check-cast p1, [B

    .line 157
    .line 158
    new-instance p0, Ldm/c;

    .line 159
    .line 160
    invoke-direct {p0, p1, p2, v0}, Ldm/c;-><init>(Ljava/lang/Object;Lmm/n;I)V

    .line 161
    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_7
    check-cast p1, Landroid/graphics/Bitmap;

    .line 165
    .line 166
    new-instance p0, Ldm/c;

    .line 167
    .line 168
    invoke-direct {p0, p1, p2, p3}, Ldm/c;-><init>(Ljava/lang/Object;Lmm/n;I)V

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :pswitch_8
    check-cast p1, Lyl/t;

    .line 173
    .line 174
    sget-object p0, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 175
    .line 176
    iget-object p0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    if-eqz p0, :cond_7

    .line 183
    .line 184
    invoke-static {p1}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    invoke-static {p0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    if-eqz p0, :cond_7

    .line 197
    .line 198
    new-instance v5, Ldm/b;

    .line 199
    .line 200
    invoke-direct {v5, p1, p2, p3}, Ldm/b;-><init>(Lyl/t;Lmm/n;I)V

    .line 201
    .line 202
    .line 203
    :cond_7
    return-object v5

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
