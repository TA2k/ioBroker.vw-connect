.class public final synthetic Lt10/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls10/x;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ls10/x;Lay0/a;I)V
    .locals 0

    .line 1
    const/4 p3, 0x1

    iput p3, p0, Lt10/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lt10/g;->e:Ls10/x;

    iput-object p2, p0, Lt10/g;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Ls10/x;Lay0/a;IB)V
    .locals 0

    .line 2
    iput p3, p0, Lt10/g;->d:I

    iput-object p1, p0, Lt10/g;->e:Ls10/x;

    iput-object p2, p0, Lt10/g;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lt10/g;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v5, p1

    .line 25
    check-cast v5, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    new-instance p1, Lt10/h;

    .line 34
    .line 35
    const/4 p2, 0x1

    .line 36
    iget-object v0, p0, Lt10/g;->e:Ls10/x;

    .line 37
    .line 38
    iget-object p0, p0, Lt10/g;->f:Lay0/a;

    .line 39
    .line 40
    invoke-direct {p1, v0, p0, p2}, Lt10/h;-><init>(Ls10/x;Lay0/a;I)V

    .line 41
    .line 42
    .line 43
    const p0, -0x4c0dbcab

    .line 44
    .line 45
    .line 46
    invoke-static {p0, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    const/16 v6, 0x180

    .line 51
    .line 52
    const/4 v7, 0x3

    .line 53
    const/4 v1, 0x0

    .line 54
    const-wide/16 v2, 0x0

    .line 55
    .line 56
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 61
    .line 62
    .line 63
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const/4 p2, 0x1

    .line 70
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    iget-object v0, p0, Lt10/g;->e:Ls10/x;

    .line 75
    .line 76
    iget-object p0, p0, Lt10/g;->f:Lay0/a;

    .line 77
    .line 78
    invoke-static {v0, p0, p1, p2}, Lt10/a;->m(Ls10/x;Lay0/a;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    and-int/lit8 v0, p2, 0x3

    .line 89
    .line 90
    const/4 v1, 0x2

    .line 91
    const/4 v2, 0x1

    .line 92
    if-eq v0, v1, :cond_2

    .line 93
    .line 94
    move v0, v2

    .line 95
    goto :goto_2

    .line 96
    :cond_2
    const/4 v0, 0x0

    .line 97
    :goto_2
    and-int/2addr p2, v2

    .line 98
    move-object v8, p1

    .line 99
    check-cast v8, Ll2/t;

    .line 100
    .line 101
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_3

    .line 106
    .line 107
    iget-object p1, p0, Lt10/g;->e:Ls10/x;

    .line 108
    .line 109
    iget-object v2, p1, Ls10/x;->b:Ljava/lang/String;

    .line 110
    .line 111
    new-instance v4, Li91/w2;

    .line 112
    .line 113
    iget-object p0, p0, Lt10/g;->f:Lay0/a;

    .line 114
    .line 115
    const/4 p1, 0x3

    .line 116
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 117
    .line 118
    .line 119
    const/4 v9, 0x0

    .line 120
    const/16 v10, 0x3bd

    .line 121
    .line 122
    const/4 v1, 0x0

    .line 123
    const/4 v3, 0x0

    .line 124
    const/4 v5, 0x0

    .line 125
    const/4 v6, 0x0

    .line 126
    const/4 v7, 0x0

    .line 127
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 128
    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
