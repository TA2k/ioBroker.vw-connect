.class public final synthetic Lsm0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrm0/b;


# direct methods
.method public synthetic constructor <init>(Lrm0/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lsm0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lsm0/c;->e:Lrm0/b;

    return-void
.end method

.method public synthetic constructor <init>(Lrm0/b;I)V
    .locals 0

    .line 2
    const/4 p2, 0x1

    iput p2, p0, Lsm0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lsm0/c;->e:Lrm0/b;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lsm0/c;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    iget-object p0, p0, Lsm0/c;->e:Lrm0/b;

    .line 21
    .line 22
    invoke-static {p0, p1, p2}, Lsm0/a;->d(Lrm0/b;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    return-object v1

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    and-int/lit8 v0, p2, 0x3

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    const/4 v4, 0x2

    .line 34
    if-eq v0, v4, :cond_0

    .line 35
    .line 36
    move v0, v2

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v0, v3

    .line 39
    :goto_0
    and-int/2addr p2, v2

    .line 40
    move-object v11, p1

    .line 41
    check-cast v11, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v11, p2, v0}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_5

    .line 48
    .line 49
    const/4 p1, 0x3

    .line 50
    new-array p1, p1, [Lay0/n;

    .line 51
    .line 52
    sget-object p2, Lsm0/a;->a:Lt2/b;

    .line 53
    .line 54
    aput-object p2, p1, v3

    .line 55
    .line 56
    sget-object p2, Lsm0/a;->b:Lt2/b;

    .line 57
    .line 58
    aput-object p2, p1, v2

    .line 59
    .line 60
    sget-object p2, Lsm0/a;->c:Lt2/b;

    .line 61
    .line 62
    aput-object p2, p1, v4

    .line 63
    .line 64
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 73
    .line 74
    if-ne p1, p2, :cond_1

    .line 75
    .line 76
    new-instance p1, Lz81/g;

    .line 77
    .line 78
    invoke-direct {p1, v4}, Lz81/g;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v11, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    move-object v7, p1

    .line 85
    check-cast v7, Lay0/a;

    .line 86
    .line 87
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, p2, :cond_2

    .line 92
    .line 93
    new-instance p1, Lz81/g;

    .line 94
    .line 95
    invoke-direct {p1, v4}, Lz81/g;-><init>(I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v11, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    :cond_2
    move-object v8, p1

    .line 102
    check-cast v8, Lay0/a;

    .line 103
    .line 104
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, p2, :cond_3

    .line 109
    .line 110
    new-instance p1, Lz81/g;

    .line 111
    .line 112
    invoke-direct {p1, v4}, Lz81/g;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v11, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_3
    move-object v9, p1

    .line 119
    check-cast v9, Lay0/a;

    .line 120
    .line 121
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-ne p1, p2, :cond_4

    .line 126
    .line 127
    new-instance p1, Lsb/a;

    .line 128
    .line 129
    const/16 p2, 0x19

    .line 130
    .line 131
    invoke-direct {p1, p2}, Lsb/a;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v11, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    :cond_4
    move-object v10, p1

    .line 138
    check-cast v10, Lay0/k;

    .line 139
    .line 140
    const v12, 0x36db0

    .line 141
    .line 142
    .line 143
    iget-object v5, p0, Lsm0/c;->e:Lrm0/b;

    .line 144
    .line 145
    invoke-static/range {v5 .. v12}, Lsm0/a;->c(Lrm0/b;Ljava/util/List;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_5
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    :goto_1
    return-object v1

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
