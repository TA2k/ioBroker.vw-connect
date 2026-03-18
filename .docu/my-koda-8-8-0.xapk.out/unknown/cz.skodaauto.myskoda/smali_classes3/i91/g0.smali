.class public final synthetic Li91/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:F

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Li91/c2;Lx2/s;FII)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li91/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g0;->i:Ljava/lang/Object;

    iput-object p2, p0, Li91/g0;->e:Ljava/lang/Object;

    iput p3, p0, Li91/g0;->f:F

    iput p4, p0, Li91/g0;->g:I

    iput p5, p0, Li91/g0;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lug/d;ILjava/lang/String;FI)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Li91/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g0;->e:Ljava/lang/Object;

    iput p2, p0, Li91/g0;->g:I

    iput-object p3, p0, Li91/g0;->i:Ljava/lang/Object;

    iput p4, p0, Li91/g0;->f:F

    iput p5, p0, Li91/g0;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;FLt2/b;II)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Li91/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g0;->e:Ljava/lang/Object;

    iput p2, p0, Li91/g0;->f:F

    iput-object p3, p0, Li91/g0;->i:Ljava/lang/Object;

    iput p4, p0, Li91/g0;->g:I

    iput p5, p0, Li91/g0;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Landroid/net/Uri;FII)V
    .locals 1

    .line 4
    const/4 v0, 0x3

    iput v0, p0, Li91/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g0;->e:Ljava/lang/Object;

    iput-object p2, p0, Li91/g0;->i:Ljava/lang/Object;

    iput p3, p0, Li91/g0;->f:F

    iput p4, p0, Li91/g0;->g:I

    iput p5, p0, Li91/g0;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Li91/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/g0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lx2/s;

    .line 10
    .line 11
    iget-object v0, p0, Li91/g0;->i:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Landroid/net/Uri;

    .line 15
    .line 16
    move-object v4, p1

    .line 17
    check-cast v4, Ll2/o;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget p1, p0, Li91/g0;->g:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    iget v3, p0, Li91/g0;->f:F

    .line 33
    .line 34
    iget v6, p0, Li91/g0;->h:I

    .line 35
    .line 36
    invoke-static/range {v1 .. v6}, Lxk0/h;->R(Lx2/s;Landroid/net/Uri;FLl2/o;II)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    iget-object v0, p0, Li91/g0;->e:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v1, v0

    .line 45
    check-cast v1, Lug/d;

    .line 46
    .line 47
    iget-object v0, p0, Li91/g0;->i:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v3, v0

    .line 50
    check-cast v3, Ljava/lang/String;

    .line 51
    .line 52
    move-object v5, p1

    .line 53
    check-cast v5, Ll2/o;

    .line 54
    .line 55
    check-cast p2, Ljava/lang/Integer;

    .line 56
    .line 57
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    iget p1, p0, Li91/g0;->h:I

    .line 61
    .line 62
    or-int/lit8 p1, p1, 0x1

    .line 63
    .line 64
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    iget v2, p0, Li91/g0;->g:I

    .line 69
    .line 70
    iget v4, p0, Li91/g0;->f:F

    .line 71
    .line 72
    invoke-static/range {v1 .. v6}, Lkp/d8;->b(Lug/d;ILjava/lang/String;FLl2/o;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :pswitch_1
    iget-object v0, p0, Li91/g0;->i:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v1, v0

    .line 79
    check-cast v1, Li91/c2;

    .line 80
    .line 81
    iget-object v0, p0, Li91/g0;->e:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v2, v0

    .line 84
    check-cast v2, Lx2/s;

    .line 85
    .line 86
    move-object v4, p1

    .line 87
    check-cast v4, Ll2/o;

    .line 88
    .line 89
    check-cast p2, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    iget p1, p0, Li91/g0;->g:I

    .line 95
    .line 96
    or-int/lit8 p1, p1, 0x1

    .line 97
    .line 98
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    iget v3, p0, Li91/g0;->f:F

    .line 103
    .line 104
    iget v6, p0, Li91/g0;->h:I

    .line 105
    .line 106
    invoke-static/range {v1 .. v6}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_2
    iget-object v0, p0, Li91/g0;->e:Ljava/lang/Object;

    .line 111
    .line 112
    move-object v1, v0

    .line 113
    check-cast v1, Lx2/s;

    .line 114
    .line 115
    iget-object v0, p0, Li91/g0;->i:Ljava/lang/Object;

    .line 116
    .line 117
    move-object v3, v0

    .line 118
    check-cast v3, Lt2/b;

    .line 119
    .line 120
    move-object v4, p1

    .line 121
    check-cast v4, Ll2/o;

    .line 122
    .line 123
    check-cast p2, Ljava/lang/Integer;

    .line 124
    .line 125
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    iget p1, p0, Li91/g0;->g:I

    .line 129
    .line 130
    or-int/lit8 p1, p1, 0x1

    .line 131
    .line 132
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    iget v2, p0, Li91/g0;->f:F

    .line 137
    .line 138
    iget v6, p0, Li91/g0;->h:I

    .line 139
    .line 140
    invoke-static/range {v1 .. v6}, Li91/h0;->c(Lx2/s;FLt2/b;Ll2/o;II)V

    .line 141
    .line 142
    .line 143
    goto :goto_0

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
