.class public final synthetic Lz20/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lj2/p;

.field public final synthetic f:Ly20/h;


# direct methods
.method public synthetic constructor <init>(Lj2/p;Ly20/h;I)V
    .locals 0

    .line 1
    iput p3, p0, Lz20/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz20/b;->e:Lj2/p;

    .line 4
    .line 5
    iput-object p2, p0, Lz20/b;->f:Ly20/h;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lz20/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/q;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$PullToRefreshBox"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, p3, 0x6

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    move-object v0, p2

    .line 26
    check-cast v0, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr p3, v0

    .line 38
    :cond_1
    and-int/lit8 v0, p3, 0x13

    .line 39
    .line 40
    const/16 v1, 0x12

    .line 41
    .line 42
    if-eq v0, v1, :cond_2

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    const/4 v0, 0x0

    .line 47
    :goto_1
    and-int/lit8 v1, p3, 0x1

    .line 48
    .line 49
    check-cast p2, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    iget-object v0, p0, Lz20/b;->f:Ly20/h;

    .line 58
    .line 59
    iget-boolean v0, v0, Ly20/h;->e:Z

    .line 60
    .line 61
    and-int/lit8 p3, p3, 0xe

    .line 62
    .line 63
    iget-object p0, p0, Lz20/b;->e:Lj2/p;

    .line 64
    .line 65
    invoke-static {p1, p0, v0, p2, p3}, Lxf0/y1;->j(Lk1/q;Lj2/p;ZLl2/o;I)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 70
    .line 71
    .line 72
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_0
    const-string v0, "$this$PullToRefreshBox"

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    and-int/lit8 v0, p3, 0x6

    .line 81
    .line 82
    if-nez v0, :cond_5

    .line 83
    .line 84
    move-object v0, p2

    .line 85
    check-cast v0, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_4

    .line 92
    .line 93
    const/4 v0, 0x4

    .line 94
    goto :goto_3

    .line 95
    :cond_4
    const/4 v0, 0x2

    .line 96
    :goto_3
    or-int/2addr p3, v0

    .line 97
    :cond_5
    and-int/lit8 v0, p3, 0x13

    .line 98
    .line 99
    const/16 v1, 0x12

    .line 100
    .line 101
    if-eq v0, v1, :cond_6

    .line 102
    .line 103
    const/4 v0, 0x1

    .line 104
    goto :goto_4

    .line 105
    :cond_6
    const/4 v0, 0x0

    .line 106
    :goto_4
    and-int/lit8 v1, p3, 0x1

    .line 107
    .line 108
    check-cast p2, Ll2/t;

    .line 109
    .line 110
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-eqz v0, :cond_7

    .line 115
    .line 116
    iget-object v0, p0, Lz20/b;->f:Ly20/h;

    .line 117
    .line 118
    iget-boolean v0, v0, Ly20/h;->e:Z

    .line 119
    .line 120
    and-int/lit8 p3, p3, 0xe

    .line 121
    .line 122
    iget-object p0, p0, Lz20/b;->e:Lj2/p;

    .line 123
    .line 124
    invoke-static {p1, p0, v0, p2, p3}, Lxf0/y1;->j(Lk1/q;Lj2/p;ZLl2/o;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_5

    .line 128
    :cond_7
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 129
    .line 130
    .line 131
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    nop

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
