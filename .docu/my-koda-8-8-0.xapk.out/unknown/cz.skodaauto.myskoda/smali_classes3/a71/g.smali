.class public final synthetic La71/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lt2/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, La71/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/g;->e:Lt2/b;

    iput-object p2, p0, La71/g;->f:Lt2/b;

    return-void
.end method

.method public synthetic constructor <init>(Lt2/b;Lt2/b;II)V
    .locals 0

    .line 2
    iput p4, p0, La71/g;->d:I

    iput-object p1, p0, La71/g;->e:Lt2/b;

    iput-object p2, p0, La71/g;->f:Lt2/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, La71/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x37

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, La71/g;->e:Lt2/b;

    .line 20
    .line 21
    iget-object p0, p0, La71/g;->f:Lt2/b;

    .line 22
    .line 23
    invoke-static {v0, p0, p1, p2}, Li91/u3;->c(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    check-cast p1, Lt3/p1;

    .line 30
    .line 31
    check-cast p2, Lt4/a;

    .line 32
    .line 33
    const-string v0, "$this$SubcomposeLayout"

    .line 34
    .line 35
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v0, "viewToMeasure"

    .line 39
    .line 40
    iget-object v1, p0, La71/g;->e:Lt2/b;

    .line 41
    .line 42
    invoke-interface {p1, v0, v1}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const/4 v1, 0x0

    .line 47
    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Lt3/p0;

    .line 52
    .line 53
    const/16 v2, 0xf

    .line 54
    .line 55
    invoke-static {v1, v1, v2}, Lt4/b;->b(III)J

    .line 56
    .line 57
    .line 58
    move-result-wide v2

    .line 59
    invoke-interface {v0, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    iget v0, v0, Lt3/e1;->d:I

    .line 64
    .line 65
    invoke-interface {p1, v0}, Lt4/c;->n0(I)F

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    new-instance v2, Lh2/x;

    .line 70
    .line 71
    const/4 v3, 0x1

    .line 72
    iget-object p0, p0, La71/g;->f:Lt2/b;

    .line 73
    .line 74
    invoke-direct {v2, p0, v0, v3}, Lh2/x;-><init>(Ljava/lang/Object;FI)V

    .line 75
    .line 76
    .line 77
    new-instance p0, Lt2/b;

    .line 78
    .line 79
    const/4 v0, 0x1

    .line 80
    const v3, 0x26ea66b4

    .line 81
    .line 82
    .line 83
    invoke-direct {p0, v2, v0, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 84
    .line 85
    .line 86
    const-string v0, "content"

    .line 87
    .line 88
    invoke-interface {p1, v0, p0}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Lt3/p0;

    .line 97
    .line 98
    iget-wide v0, p2, Lt4/a;->a:J

    .line 99
    .line 100
    invoke-interface {p0, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    iget p2, p0, Lt3/e1;->d:I

    .line 105
    .line 106
    iget v0, p0, Lt3/e1;->e:I

    .line 107
    .line 108
    new-instance v1, Lam/a;

    .line 109
    .line 110
    const/16 v2, 0xa

    .line 111
    .line 112
    invoke-direct {v1, p0, v2}, Lam/a;-><init>(Lt3/e1;I)V

    .line 113
    .line 114
    .line 115
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 116
    .line 117
    invoke-interface {p1, p2, v0, p0, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0

    .line 122
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 123
    .line 124
    check-cast p2, Ljava/lang/Integer;

    .line 125
    .line 126
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    const/16 p2, 0x37

    .line 130
    .line 131
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 132
    .line 133
    .line 134
    move-result p2

    .line 135
    iget-object v0, p0, La71/g;->e:Lt2/b;

    .line 136
    .line 137
    iget-object p0, p0, La71/g;->f:Lt2/b;

    .line 138
    .line 139
    invoke-static {v0, p0, p1, p2}, Lbl/a;->b(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 140
    .line 141
    .line 142
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 146
    .line 147
    check-cast p2, Ljava/lang/Integer;

    .line 148
    .line 149
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    const/16 p2, 0x37

    .line 153
    .line 154
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    iget-object v0, p0, La71/g;->e:Lt2/b;

    .line 159
    .line 160
    iget-object p0, p0, La71/g;->f:Lt2/b;

    .line 161
    .line 162
    invoke-static {v0, p0, p1, p2}, Lal/a;->l(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 163
    .line 164
    .line 165
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object p0

    .line 168
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 169
    .line 170
    check-cast p2, Ljava/lang/Integer;

    .line 171
    .line 172
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    const/16 p2, 0x31

    .line 176
    .line 177
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    iget-object v0, p0, La71/g;->e:Lt2/b;

    .line 182
    .line 183
    iget-object p0, p0, La71/g;->f:Lt2/b;

    .line 184
    .line 185
    invoke-static {v0, p0, p1, p2}, La71/b;->r(Lt2/b;Lt2/b;Ll2/o;I)V

    .line 186
    .line 187
    .line 188
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
