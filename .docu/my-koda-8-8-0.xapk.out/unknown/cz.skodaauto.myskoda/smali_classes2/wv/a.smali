.class public final Lwv/a;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# static fields
.field public static final g:Lwv/a;

.field public static final h:Lwv/a;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lwv/a;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lwv/a;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwv/a;->g:Lwv/a;

    .line 9
    .line 10
    new-instance v0, Lwv/a;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lwv/a;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lwv/a;->h:Lwv/a;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lwv/a;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lwv/a;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le3/s;

    .line 7
    .line 8
    iget-wide p0, p1, Le3/s;->a:J

    .line 9
    .line 10
    check-cast p2, Lay0/n;

    .line 11
    .line 12
    check-cast p3, Ll2/o;

    .line 13
    .line 14
    check-cast p4, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p4

    .line 20
    const-string v0, "content"

    .line 21
    .line 22
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    and-int/lit8 v0, p4, 0xe

    .line 26
    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    move-object v0, p3

    .line 30
    check-cast v0, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {v0, p0, p1}, Ll2/t;->f(J)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    const/4 v0, 0x4

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v0, 0x2

    .line 41
    :goto_0
    or-int/2addr v0, p4

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v0, p4

    .line 44
    :goto_1
    and-int/lit8 p4, p4, 0x70

    .line 45
    .line 46
    if-nez p4, :cond_3

    .line 47
    .line 48
    move-object p4, p3

    .line 49
    check-cast p4, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {p4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p4

    .line 55
    if-eqz p4, :cond_2

    .line 56
    .line 57
    const/16 p4, 0x20

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/16 p4, 0x10

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, p4

    .line 63
    :cond_3
    and-int/lit16 p4, v0, 0x2db

    .line 64
    .line 65
    const/16 v0, 0x92

    .line 66
    .line 67
    if-ne p4, v0, :cond_5

    .line 68
    .line 69
    move-object p4, p3

    .line 70
    check-cast p4, Ll2/t;

    .line 71
    .line 72
    invoke-virtual {p4}, Ll2/t;->A()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-nez v0, :cond_4

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 80
    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    :goto_3
    sget-object p4, Lh2/p1;->a:Ll2/e0;

    .line 84
    .line 85
    invoke-static {p0, p1, p4}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    new-instance p1, Lvv/m;

    .line 90
    .line 91
    const/4 p4, 0x2

    .line 92
    invoke-direct {p1, p4, p2}, Lvv/m;-><init>(ILay0/n;)V

    .line 93
    .line 94
    .line 95
    const p2, -0x15add53f

    .line 96
    .line 97
    .line 98
    invoke-static {p2, p3, p1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    const/16 p2, 0x38

    .line 103
    .line 104
    invoke-static {p0, p1, p3, p2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_0
    check-cast p1, Lg4/p0;

    .line 111
    .line 112
    check-cast p2, Lay0/n;

    .line 113
    .line 114
    check-cast p3, Ll2/o;

    .line 115
    .line 116
    check-cast p4, Ljava/lang/Number;

    .line 117
    .line 118
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    const-string p4, "textStyle"

    .line 123
    .line 124
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    const-string p4, "content"

    .line 128
    .line 129
    invoke-static {p2, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    and-int/lit8 p4, p0, 0xe

    .line 133
    .line 134
    if-nez p4, :cond_7

    .line 135
    .line 136
    move-object p4, p3

    .line 137
    check-cast p4, Ll2/t;

    .line 138
    .line 139
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result p4

    .line 143
    if-eqz p4, :cond_6

    .line 144
    .line 145
    const/4 p4, 0x4

    .line 146
    goto :goto_5

    .line 147
    :cond_6
    const/4 p4, 0x2

    .line 148
    :goto_5
    or-int/2addr p4, p0

    .line 149
    goto :goto_6

    .line 150
    :cond_7
    move p4, p0

    .line 151
    :goto_6
    and-int/lit8 p0, p0, 0x70

    .line 152
    .line 153
    if-nez p0, :cond_9

    .line 154
    .line 155
    move-object p0, p3

    .line 156
    check-cast p0, Ll2/t;

    .line 157
    .line 158
    invoke-virtual {p0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    if-eqz p0, :cond_8

    .line 163
    .line 164
    const/16 p0, 0x20

    .line 165
    .line 166
    goto :goto_7

    .line 167
    :cond_8
    const/16 p0, 0x10

    .line 168
    .line 169
    :goto_7
    or-int/2addr p4, p0

    .line 170
    :cond_9
    and-int/lit16 p0, p4, 0x2db

    .line 171
    .line 172
    const/16 v0, 0x92

    .line 173
    .line 174
    if-ne p0, v0, :cond_b

    .line 175
    .line 176
    move-object p0, p3

    .line 177
    check-cast p0, Ll2/t;

    .line 178
    .line 179
    invoke-virtual {p0}, Ll2/t;->A()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-nez v0, :cond_a

    .line 184
    .line 185
    goto :goto_8

    .line 186
    :cond_a
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 187
    .line 188
    .line 189
    goto :goto_9

    .line 190
    :cond_b
    :goto_8
    and-int/lit8 p0, p4, 0x7e

    .line 191
    .line 192
    invoke-static {p1, p2, p3, p0}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object p0

    .line 198
    nop

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
