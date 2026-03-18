.class public final synthetic Ly1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly1/f;

.field public final synthetic f:La2/k;


# direct methods
.method public synthetic constructor <init>(Ly1/f;La2/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly1/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly1/b;->e:Ly1/f;

    .line 4
    .line 5
    iput-object p2, p0, Ly1/b;->f:La2/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Ly1/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ly1/b;->e:Ly1/f;

    .line 7
    .line 8
    iget-object v0, v0, Ly1/f;->c:Lay0/a;

    .line 9
    .line 10
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lt3/y;

    .line 15
    .line 16
    iget-object p0, p0, Ly1/b;->f:La2/k;

    .line 17
    .line 18
    invoke-interface {p0, v0}, La2/k;->p(Lt3/y;)Ld3/c;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-wide/16 v1, 0x0

    .line 23
    .line 24
    invoke-interface {v0, v1, v2}, Lt3/y;->R(J)J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    invoke-virtual {p0, v0, v1}, Ld3/c;->i(J)Ld3/c;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget-object v0, p0, Ly1/b;->e:Ly1/f;

    .line 34
    .line 35
    iget-object v1, v0, Ly1/f;->g:Ly1/a;

    .line 36
    .line 37
    new-instance v2, Ly1/b;

    .line 38
    .line 39
    const/4 v3, 0x2

    .line 40
    iget-object p0, p0, Ly1/b;->f:La2/k;

    .line 41
    .line 42
    invoke-direct {v2, v0, p0, v3}, Ly1/b;-><init>(Ly1/f;La2/k;I)V

    .line 43
    .line 44
    .line 45
    new-instance p0, Lkotlin/jvm/internal/f0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 48
    .line 49
    .line 50
    iget-object v0, v0, Ly1/f;->e:Lv2/r;

    .line 51
    .line 52
    new-instance v3, Lvu/d;

    .line 53
    .line 54
    const/16 v4, 0x14

    .line 55
    .line 56
    invoke-direct {v3, v4, p0, v2}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    const-string v2, "positioner"

    .line 60
    .line 61
    invoke-virtual {v0, v2, v1, v3}, Lv2/r;->d(Ljava/lang/Object;Lay0/k;Lay0/a;)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 65
    .line 66
    if-eqz p0, :cond_0

    .line 67
    .line 68
    check-cast p0, Ld3/c;

    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_0
    const-string p0, "result"

    .line 72
    .line 73
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    throw p0

    .line 78
    :pswitch_1
    iget-object v0, p0, Ly1/b;->e:Ly1/f;

    .line 79
    .line 80
    iget-object v1, v0, Ly1/f;->f:Ly1/a;

    .line 81
    .line 82
    new-instance v2, Lu2/a;

    .line 83
    .line 84
    const/16 v3, 0x1d

    .line 85
    .line 86
    iget-object p0, p0, Ly1/b;->f:La2/k;

    .line 87
    .line 88
    invoke-direct {v2, p0, v3}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    new-instance p0, Lkotlin/jvm/internal/f0;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 94
    .line 95
    .line 96
    iget-object v0, v0, Ly1/f;->e:Lv2/r;

    .line 97
    .line 98
    new-instance v3, Lvu/d;

    .line 99
    .line 100
    const/16 v4, 0x14

    .line 101
    .line 102
    invoke-direct {v3, v4, p0, v2}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    const-string v2, "dataBuilder"

    .line 106
    .line 107
    invoke-virtual {v0, v2, v1, v3}, Lv2/r;->d(Ljava/lang/Object;Lay0/k;Lay0/a;)V

    .line 108
    .line 109
    .line 110
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 111
    .line 112
    if-eqz p0, :cond_1

    .line 113
    .line 114
    check-cast p0, Lw1/c;

    .line 115
    .line 116
    return-object p0

    .line 117
    :cond_1
    const-string p0, "result"

    .line 118
    .line 119
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const/4 p0, 0x0

    .line 123
    throw p0

    .line 124
    nop

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
