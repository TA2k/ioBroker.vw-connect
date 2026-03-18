.class public final synthetic Lh2/d2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lt2/b;Lx2/s;Le3/n0;FLh2/z1;Lx4/p;Lt2/b;I)V
    .locals 0

    .line 1
    const/4 p9, 0x0

    iput p9, p0, Lh2/d2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/d2;->f:Lay0/a;

    iput-object p2, p0, Lh2/d2;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh2/d2;->i:Ljava/lang/Object;

    iput-object p4, p0, Lh2/d2;->j:Ljava/lang/Object;

    iput p5, p0, Lh2/d2;->e:F

    iput-object p6, p0, Lh2/d2;->k:Ljava/lang/Object;

    iput-object p7, p0, Lh2/d2;->l:Ljava/lang/Object;

    iput-object p8, p0, Lh2/d2;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/s;Lm70/p;Li91/r2;FLl2/b1;Lk1/z0;Lay0/a;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lh2/d2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/d2;->g:Ljava/lang/Object;

    iput-object p2, p0, Lh2/d2;->h:Ljava/lang/Object;

    iput-object p3, p0, Lh2/d2;->i:Ljava/lang/Object;

    iput p4, p0, Lh2/d2;->e:F

    iput-object p5, p0, Lh2/d2;->j:Ljava/lang/Object;

    iput-object p6, p0, Lh2/d2;->k:Ljava/lang/Object;

    iput-object p7, p0, Lh2/d2;->f:Lay0/a;

    iput-object p8, p0, Lh2/d2;->l:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lh2/d2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/d2;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lm70/s;

    .line 9
    .line 10
    iget-object v1, p0, Lh2/d2;->h:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v2, v1

    .line 13
    check-cast v2, Lm70/p;

    .line 14
    .line 15
    iget-object v1, p0, Lh2/d2;->i:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v4, v1

    .line 18
    check-cast v4, Li91/r2;

    .line 19
    .line 20
    iget-object v1, p0, Lh2/d2;->j:Ljava/lang/Object;

    .line 21
    .line 22
    move-object v6, v1

    .line 23
    check-cast v6, Ll2/b1;

    .line 24
    .line 25
    iget-object v1, p0, Lh2/d2;->k:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v7, v1

    .line 28
    check-cast v7, Lk1/z0;

    .line 29
    .line 30
    iget-object v1, p0, Lh2/d2;->l:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v10, v1

    .line 33
    check-cast v10, Lay0/k;

    .line 34
    .line 35
    check-cast p1, Ll2/o;

    .line 36
    .line 37
    check-cast p2, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    and-int/lit8 v1, p2, 0x3

    .line 44
    .line 45
    const/4 v3, 0x2

    .line 46
    const/4 v5, 0x1

    .line 47
    if-eq v1, v3, :cond_0

    .line 48
    .line 49
    move v1, v5

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/4 v1, 0x0

    .line 52
    :goto_0
    and-int/2addr p2, v5

    .line 53
    move-object v11, p1

    .line 54
    check-cast v11, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v11, p2, v1}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_1

    .line 61
    .line 62
    iget-object v3, v0, Lm70/s;->d:Lxj0/j;

    .line 63
    .line 64
    iget-object v8, v0, Lm70/s;->e:Lm70/r;

    .line 65
    .line 66
    const/16 v12, 0x6e00

    .line 67
    .line 68
    iget v5, p0, Lh2/d2;->e:F

    .line 69
    .line 70
    iget-object v9, p0, Lh2/d2;->f:Lay0/a;

    .line 71
    .line 72
    invoke-static/range {v2 .. v12}, Ln70/m;->d(Lm70/p;Lxj0/j;Li91/r2;FLl2/b1;Lk1/z0;Lm70/r;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 77
    .line 78
    .line 79
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_0
    iget-object v0, p0, Lh2/d2;->g:Ljava/lang/Object;

    .line 83
    .line 84
    move-object v2, v0

    .line 85
    check-cast v2, Lt2/b;

    .line 86
    .line 87
    iget-object v0, p0, Lh2/d2;->i:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v3, v0

    .line 90
    check-cast v3, Lx2/s;

    .line 91
    .line 92
    iget-object v0, p0, Lh2/d2;->j:Ljava/lang/Object;

    .line 93
    .line 94
    move-object v4, v0

    .line 95
    check-cast v4, Le3/n0;

    .line 96
    .line 97
    iget-object v0, p0, Lh2/d2;->k:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v6, v0

    .line 100
    check-cast v6, Lh2/z1;

    .line 101
    .line 102
    iget-object v0, p0, Lh2/d2;->l:Ljava/lang/Object;

    .line 103
    .line 104
    move-object v7, v0

    .line 105
    check-cast v7, Lx4/p;

    .line 106
    .line 107
    iget-object v0, p0, Lh2/d2;->h:Ljava/lang/Object;

    .line 108
    .line 109
    move-object v8, v0

    .line 110
    check-cast v8, Lt2/b;

    .line 111
    .line 112
    move-object v9, p1

    .line 113
    check-cast v9, Ll2/o;

    .line 114
    .line 115
    check-cast p2, Ljava/lang/Integer;

    .line 116
    .line 117
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    const p1, 0x6000031

    .line 121
    .line 122
    .line 123
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 124
    .line 125
    .line 126
    move-result v10

    .line 127
    iget-object v1, p0, Lh2/d2;->f:Lay0/a;

    .line 128
    .line 129
    iget v5, p0, Lh2/d2;->e:F

    .line 130
    .line 131
    invoke-static/range {v1 .. v10}, Lh2/f2;->a(Lay0/a;Lt2/b;Lx2/s;Le3/n0;FLh2/z1;Lx4/p;Lt2/b;Ll2/o;I)V

    .line 132
    .line 133
    .line 134
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
