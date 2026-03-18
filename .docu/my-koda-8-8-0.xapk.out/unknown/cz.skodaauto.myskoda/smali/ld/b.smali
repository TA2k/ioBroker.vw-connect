.class public final synthetic Lld/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lxh/e;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lyj/b;

.field public final synthetic i:Lxh/e;

.field public final synthetic j:Lbd/a;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lld/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lld/b;->e:Ljava/util/List;

    iput-object p2, p0, Lld/b;->f:Lxh/e;

    iput-object p3, p0, Lld/b;->g:Lay0/k;

    iput-object p4, p0, Lld/b;->h:Lyj/b;

    iput-object p5, p0, Lld/b;->i:Lxh/e;

    iput-object p6, p0, Lld/b;->j:Lbd/a;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;II)V
    .locals 0

    .line 2
    iput p8, p0, Lld/b;->d:I

    iput-object p1, p0, Lld/b;->e:Ljava/util/List;

    iput-object p2, p0, Lld/b;->f:Lxh/e;

    iput-object p3, p0, Lld/b;->g:Lay0/k;

    iput-object p4, p0, Lld/b;->h:Lyj/b;

    iput-object p5, p0, Lld/b;->i:Lxh/e;

    iput-object p6, p0, Lld/b;->j:Lbd/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lld/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v8

    .line 19
    iget-object v1, p0, Lld/b;->e:Ljava/util/List;

    .line 20
    .line 21
    iget-object v2, p0, Lld/b;->f:Lxh/e;

    .line 22
    .line 23
    iget-object v3, p0, Lld/b;->g:Lay0/k;

    .line 24
    .line 25
    iget-object v4, p0, Lld/b;->h:Lyj/b;

    .line 26
    .line 27
    iget-object v5, p0, Lld/b;->i:Lxh/e;

    .line 28
    .line 29
    iget-object v6, p0, Lld/b;->j:Lbd/a;

    .line 30
    .line 31
    invoke-static/range {v1 .. v8}, Llp/kf;->b(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    move-object v6, p1

    .line 38
    check-cast v6, Ll2/o;

    .line 39
    .line 40
    check-cast p2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    const/16 p1, 0x181

    .line 46
    .line 47
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    iget-object v0, p0, Lld/b;->e:Ljava/util/List;

    .line 52
    .line 53
    iget-object v1, p0, Lld/b;->f:Lxh/e;

    .line 54
    .line 55
    iget-object v2, p0, Lld/b;->g:Lay0/k;

    .line 56
    .line 57
    iget-object v3, p0, Lld/b;->h:Lyj/b;

    .line 58
    .line 59
    iget-object v4, p0, Lld/b;->i:Lxh/e;

    .line 60
    .line 61
    iget-object v5, p0, Lld/b;->j:Lbd/a;

    .line 62
    .line 63
    invoke-static/range {v0 .. v7}, Llp/kf;->a(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 68
    .line 69
    check-cast p2, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    and-int/lit8 v0, p2, 0x3

    .line 76
    .line 77
    const/4 v1, 0x1

    .line 78
    const/4 v2, 0x0

    .line 79
    const/4 v3, 0x2

    .line 80
    if-eq v0, v3, :cond_0

    .line 81
    .line 82
    move v0, v1

    .line 83
    goto :goto_1

    .line 84
    :cond_0
    move v0, v2

    .line 85
    :goto_1
    and-int/2addr p2, v1

    .line 86
    move-object v9, p1

    .line 87
    check-cast v9, Ll2/t;

    .line 88
    .line 89
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    if-eqz p1, :cond_2

    .line 94
    .line 95
    iget-object v4, p0, Lld/b;->e:Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    iget-object v5, p0, Lld/b;->f:Lxh/e;

    .line 102
    .line 103
    iget-object v6, p0, Lld/b;->g:Lay0/k;

    .line 104
    .line 105
    iget-object v7, p0, Lld/b;->h:Lyj/b;

    .line 106
    .line 107
    iget-object v8, p0, Lld/b;->i:Lxh/e;

    .line 108
    .line 109
    if-ne p1, v3, :cond_1

    .line 110
    .line 111
    const p1, -0x390ffcd9

    .line 112
    .line 113
    .line 114
    invoke-virtual {v9, p1}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    const/4 v11, 0x0

    .line 118
    iget-object p0, p0, Lld/b;->j:Lbd/a;

    .line 119
    .line 120
    move-object v10, v9

    .line 121
    move-object v9, p0

    .line 122
    invoke-static/range {v4 .. v11}, Llp/kf;->b(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    move-object v9, v10

    .line 126
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_1
    const p0, -0x390deef0

    .line 131
    .line 132
    .line 133
    invoke-virtual {v9, p0}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    const/4 v10, 0x0

    .line 137
    invoke-static/range {v4 .. v10}, Llp/kf;->c(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_2
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 145
    .line 146
    .line 147
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object p0

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
