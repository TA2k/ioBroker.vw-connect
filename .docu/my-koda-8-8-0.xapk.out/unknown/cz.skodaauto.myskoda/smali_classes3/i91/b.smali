.class public final synthetic Li91/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lt2/b;Lay0/n;FFI)V
    .locals 0

    .line 1
    const/4 p5, 0x0

    iput p5, p0, Li91/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/b;->g:Ljava/lang/Object;

    iput-object p2, p0, Li91/b;->h:Ljava/lang/Object;

    iput p3, p0, Li91/b;->e:F

    iput p4, p0, Li91/b;->f:F

    return-void
.end method

.method public synthetic constructor <init>(Ly6/s;FFLza0/q;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Li91/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/b;->g:Ljava/lang/Object;

    iput p2, p0, Li91/b;->e:F

    iput p3, p0, Li91/b;->f:F

    iput-object p4, p0, Li91/b;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li91/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ly6/s;

    .line 10
    .line 11
    iget-object v0, p0, Li91/b;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lza0/q;

    .line 14
    .line 15
    check-cast p1, Ll2/o;

    .line 16
    .line 17
    check-cast p2, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    and-int/lit8 v2, p2, 0x3

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    const/4 v4, 0x1

    .line 27
    if-eq v2, v3, :cond_0

    .line 28
    .line 29
    move v2, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v2, 0x0

    .line 32
    :goto_0
    and-int/2addr p2, v4

    .line 33
    move-object v5, p1

    .line 34
    check-cast v5, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v5, p2, v2}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    if-eqz p1, :cond_1

    .line 41
    .line 42
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 43
    .line 44
    invoke-static {p1}, Lkp/p7;->b(Ly6/q;)Ly6/q;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    const/4 v2, 0x0

    .line 49
    const/16 v3, 0x9

    .line 50
    .line 51
    iget v4, p0, Li91/b;->e:F

    .line 52
    .line 53
    iget p0, p0, Li91/b;->f:F

    .line 54
    .line 55
    invoke-static {p2, v2, v4, p0, v3}, Lkp/n7;->c(Ly6/q;FFFI)Ly6/q;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    const/16 v6, 0x30

    .line 60
    .line 61
    const/16 v7, 0x18

    .line 62
    .line 63
    const/4 v3, 0x0

    .line 64
    const/4 v4, 0x0

    .line 65
    invoke-static/range {v1 .. v7}, Llp/ag;->a(Ly6/s;Ly6/q;ILy6/g;Ll2/o;II)V

    .line 66
    .line 67
    .line 68
    invoke-static {p1}, Lkp/p7;->e(Ly6/q;)Ly6/q;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-static {p0}, Lkp/p7;->f(Ly6/q;)Ly6/q;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const/16 p1, 0x40

    .line 77
    .line 78
    invoke-virtual {v0, p0, v5, p1}, Lza0/q;->g(Ly6/q;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 83
    .line 84
    .line 85
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    :pswitch_0
    iget-object v0, p0, Li91/b;->g:Ljava/lang/Object;

    .line 89
    .line 90
    move-object v1, v0

    .line 91
    check-cast v1, Lt2/b;

    .line 92
    .line 93
    iget-object v0, p0, Li91/b;->h:Ljava/lang/Object;

    .line 94
    .line 95
    move-object v2, v0

    .line 96
    check-cast v2, Lay0/n;

    .line 97
    .line 98
    move-object v5, p1

    .line 99
    check-cast v5, Ll2/o;

    .line 100
    .line 101
    check-cast p2, Ljava/lang/Integer;

    .line 102
    .line 103
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    const/4 p1, 0x1

    .line 107
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    iget v3, p0, Li91/b;->e:F

    .line 112
    .line 113
    iget v4, p0, Li91/b;->f:F

    .line 114
    .line 115
    invoke-static/range {v1 .. v6}, Li91/j0;->m(Lt2/b;Lay0/n;FFLl2/o;I)V

    .line 116
    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
