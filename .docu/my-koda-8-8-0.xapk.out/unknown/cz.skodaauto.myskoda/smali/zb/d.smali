.class public final synthetic Lzb/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lzb/d;->d:I

    iput-object p2, p0, Lzb/d;->e:Ljava/lang/Object;

    iput-object p3, p0, Lzb/d;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lxj0/f;Lx2/s;I)V
    .locals 0

    .line 2
    const/4 p3, 0x2

    iput p3, p0, Lzb/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lzb/d;->e:Ljava/lang/Object;

    iput-object p2, p0, Lzb/d;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lzb/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lzb/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lxj0/r;

    .line 9
    .line 10
    iget-object p0, p0, Lzb/d;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lyl/l;

    .line 13
    .line 14
    check-cast p1, Ll2/o;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    and-int/lit8 v1, p2, 0x3

    .line 23
    .line 24
    const/4 v2, 0x2

    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x1

    .line 27
    if-eq v1, v2, :cond_0

    .line 28
    .line 29
    move v1, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v1, v3

    .line 32
    :goto_0
    and-int/2addr p2, v4

    .line 33
    check-cast p1, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {p1, p2, v1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    if-eqz p2, :cond_1

    .line 40
    .line 41
    invoke-static {v0, p0, p1, v3}, Lzj0/j;->i(Lxj0/r;Lyl/l;Ll2/o;I)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 46
    .line 47
    .line 48
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    iget-object v0, p0, Lzb/d;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lxj0/f;

    .line 54
    .line 55
    iget-object p0, p0, Lzb/d;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Lx2/s;

    .line 58
    .line 59
    check-cast p1, Ll2/o;

    .line 60
    .line 61
    check-cast p2, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    const/4 p2, 0x1

    .line 67
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    invoke-static {v0, p0, p1, p2}, Lzj0/b;->a(Lxj0/f;Lx2/s;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_1
    iget-object v0, p0, Lzb/d;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Lzb/v0;

    .line 80
    .line 81
    iget-object p0, p0, Lzb/d;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Lay0/o;

    .line 84
    .line 85
    const-string v1, "p1"

    .line 86
    .line 87
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    new-instance v1, Lxc/b;

    .line 91
    .line 92
    const/4 v2, 0x6

    .line 93
    invoke-direct {v1, p0, p1, p2, v2}, Lxc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0, v1}, Lzb/v0;->g(Lay0/k;)V

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :pswitch_2
    iget-object v0, p0, Lzb/d;->e:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Lt2/b;

    .line 103
    .line 104
    iget-object p0, p0, Lzb/d;->f:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p0, Lzb/f;

    .line 107
    .line 108
    check-cast p1, Ll2/o;

    .line 109
    .line 110
    check-cast p2, Ljava/lang/Integer;

    .line 111
    .line 112
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 113
    .line 114
    .line 115
    move-result p2

    .line 116
    and-int/lit8 v1, p2, 0x3

    .line 117
    .line 118
    const/4 v2, 0x2

    .line 119
    const/4 v3, 0x1

    .line 120
    const/4 v4, 0x0

    .line 121
    if-eq v1, v2, :cond_2

    .line 122
    .line 123
    move v1, v3

    .line 124
    goto :goto_3

    .line 125
    :cond_2
    move v1, v4

    .line 126
    :goto_3
    and-int/2addr p2, v3

    .line 127
    check-cast p1, Ll2/t;

    .line 128
    .line 129
    invoke-virtual {p1, p2, v1}, Ll2/t;->O(IZ)Z

    .line 130
    .line 131
    .line 132
    move-result p2

    .line 133
    if-eqz p2, :cond_3

    .line 134
    .line 135
    const p2, -0xe62bd6e

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    invoke-virtual {v0, p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object p0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
