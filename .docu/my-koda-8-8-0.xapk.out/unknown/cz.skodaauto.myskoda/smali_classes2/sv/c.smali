.class public final Lsv/c;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lsv/c;->f:I

    iput-object p3, p0, Lsv/c;->h:Ljava/lang/Object;

    iput-object p4, p0, Lsv/c;->i:Ljava/lang/Object;

    iput-object p5, p0, Lsv/c;->j:Ljava/lang/Object;

    iput p1, p0, Lsv/c;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lt2/b;Lvv/m0;Ljava/util/List;I)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lsv/c;->f:I

    .line 2
    iput-object p1, p0, Lsv/c;->i:Ljava/lang/Object;

    iput-object p2, p0, Lsv/c;->h:Ljava/lang/Object;

    iput-object p3, p0, Lsv/c;->j:Ljava/lang/Object;

    iput p4, p0, Lsv/c;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lsv/c;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    iget-object p2, p0, Lsv/c;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p2, Lay0/a;

    .line 16
    .line 17
    iget-object v0, p0, Lsv/c;->i:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lx4/p;

    .line 20
    .line 21
    iget-object v1, p0, Lsv/c;->j:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lt2/b;

    .line 24
    .line 25
    iget p0, p0, Lsv/c;->g:I

    .line 26
    .line 27
    or-int/lit8 p0, p0, 0x1

    .line 28
    .line 29
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-static {p2, v0, v1, p1, p0}, Llp/ge;->a(Lay0/a;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Number;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    and-int/lit8 p2, p2, 0xb

    .line 48
    .line 49
    const/4 v0, 0x2

    .line 50
    if-ne p2, v0, :cond_1

    .line 51
    .line 52
    move-object p2, p1

    .line 53
    check-cast p2, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-nez v0, :cond_0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    :goto_0
    iget-object p2, p0, Lsv/c;->i:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p2, Lt2/b;

    .line 69
    .line 70
    iget-object v0, p0, Lsv/c;->h:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Lvv/m0;

    .line 73
    .line 74
    iget-object v1, p0, Lsv/c;->j:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Ljava/util/List;

    .line 77
    .line 78
    iget p0, p0, Lsv/c;->g:I

    .line 79
    .line 80
    invoke-interface {v1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    const/4 v1, 0x0

    .line 85
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-virtual {p2, v0, p0, p1, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 96
    .line 97
    check-cast p2, Ljava/lang/Number;

    .line 98
    .line 99
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 100
    .line 101
    .line 102
    iget-object p2, p0, Lsv/c;->h:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p2, Lt3/o1;

    .line 105
    .line 106
    iget-object v0, p0, Lsv/c;->i:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Lx2/s;

    .line 109
    .line 110
    iget-object v1, p0, Lsv/c;->j:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v1, Lay0/n;

    .line 113
    .line 114
    iget p0, p0, Lsv/c;->g:I

    .line 115
    .line 116
    or-int/lit8 p0, p0, 0x1

    .line 117
    .line 118
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    invoke-static {p2, v0, v1, p1, p0}, Lt3/k1;->b(Lt3/o1;Lx2/s;Lay0/n;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 129
    .line 130
    check-cast p2, Ljava/lang/Number;

    .line 131
    .line 132
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 133
    .line 134
    .line 135
    iget-object p2, p0, Lsv/c;->h:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p2, Lvv/m0;

    .line 138
    .line 139
    iget-object v0, p0, Lsv/c;->i:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, Ljava/lang/String;

    .line 142
    .line 143
    iget-object v1, p0, Lsv/c;->j:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v1, Lsv/d;

    .line 146
    .line 147
    iget p0, p0, Lsv/c;->g:I

    .line 148
    .line 149
    or-int/lit8 p0, p0, 0x1

    .line 150
    .line 151
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    invoke-static {p2, v0, v1, p1, p0}, Lkp/s8;->a(Lvv/m0;Ljava/lang/String;Lsv/d;Ll2/o;I)V

    .line 156
    .line 157
    .line 158
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
