.class public final synthetic Lkv0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Liv0/f;


# direct methods
.method public synthetic constructor <init>(Liv0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lkv0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lkv0/a;->e:Liv0/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lkv0/a;->d:I

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
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_2

    .line 32
    .line 33
    sget-object p2, Liv0/a;->a:Liv0/a;

    .line 34
    .line 35
    iget-object p0, p0, Lkv0/a;->e:Liv0/f;

    .line 36
    .line 37
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_1

    .line 42
    .line 43
    const p0, -0x57e7ba1b

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 47
    .line 48
    .line 49
    const-string p0, "maps_section_map"

    .line 50
    .line 51
    const/4 p2, 0x6

    .line 52
    invoke-static {p0, p1, p2}, Lxk0/e0;->b(Ljava/lang/String;Ll2/o;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    const p0, 0x5af1cf9d

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 70
    .line 71
    .line 72
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 76
    .line 77
    const/4 v1, 0x2

    .line 78
    const/4 v2, 0x1

    .line 79
    const/4 v3, 0x0

    .line 80
    if-eq v0, v1, :cond_3

    .line 81
    .line 82
    move v0, v2

    .line 83
    goto :goto_2

    .line 84
    :cond_3
    move v0, v3

    .line 85
    :goto_2
    and-int/2addr p2, v2

    .line 86
    check-cast p1, Ll2/t;

    .line 87
    .line 88
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    if-eqz p2, :cond_8

    .line 93
    .line 94
    sget-object p2, Liv0/j;->a:Liv0/j;

    .line 95
    .line 96
    iget-object p0, p0, Lkv0/a;->e:Liv0/f;

    .line 97
    .line 98
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    const/4 v0, 0x6

    .line 103
    const-string v1, "maps_section_map"

    .line 104
    .line 105
    if-nez p2, :cond_7

    .line 106
    .line 107
    sget-object p2, Liv0/c;->a:Liv0/c;

    .line 108
    .line 109
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    if-eqz p2, :cond_4

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_4
    sget-object p2, Liv0/h;->a:Liv0/h;

    .line 117
    .line 118
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    if-nez p2, :cond_6

    .line 123
    .line 124
    sget-object p2, Liv0/i;->a:Liv0/i;

    .line 125
    .line 126
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-eqz p0, :cond_5

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_5
    const p0, 0x5f9a3d5c

    .line 134
    .line 135
    .line 136
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 140
    .line 141
    .line 142
    goto :goto_5

    .line 143
    :cond_6
    :goto_3
    const p0, 0x1bdba446

    .line 144
    .line 145
    .line 146
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    invoke-static {v1, p1, v0}, Lxk0/h;->e0(Ljava/lang/String;Ll2/o;I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_7
    :goto_4
    const p0, 0x1bdb94e6

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 160
    .line 161
    .line 162
    invoke-static {v1, p1, v0}, Lxk0/h;->d0(Ljava/lang/String;Ll2/o;I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 166
    .line 167
    .line 168
    goto :goto_5

    .line 169
    :cond_8
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 170
    .line 171
    .line 172
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    return-object p0

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
