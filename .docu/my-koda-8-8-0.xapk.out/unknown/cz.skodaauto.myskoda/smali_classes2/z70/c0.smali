.class public final synthetic Lz70/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ly70/q1;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Ly70/q1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lz70/c0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz70/c0;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p2, p0, Lz70/c0;->f:Ly70/q1;

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
    .locals 9

    .line 1
    iget v0, p0, Lz70/c0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb1/a0;

    .line 7
    .line 8
    move-object v4, p2

    .line 9
    check-cast v4, Ll2/o;

    .line 10
    .line 11
    check-cast p3, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-string p2, "$this$AnimatedVisibility"

    .line 17
    .line 18
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Lz70/c0;

    .line 22
    .line 23
    const/4 p2, 0x0

    .line 24
    iget-object p3, p0, Lz70/c0;->e:Lay0/a;

    .line 25
    .line 26
    iget-object p0, p0, Lz70/c0;->f:Ly70/q1;

    .line 27
    .line 28
    invoke-direct {p1, p3, p0, p2}, Lz70/c0;-><init>(Lay0/a;Ly70/q1;I)V

    .line 29
    .line 30
    .line 31
    const p0, -0x3015d608

    .line 32
    .line 33
    .line 34
    invoke-static {p0, v4, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    const/16 v5, 0x180

    .line 39
    .line 40
    const/4 v6, 0x3

    .line 41
    const/4 v0, 0x0

    .line 42
    const-wide/16 v1, 0x0

    .line 43
    .line 44
    invoke-static/range {v0 .. v6}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    check-cast p1, Lk1/q;

    .line 51
    .line 52
    check-cast p2, Ll2/o;

    .line 53
    .line 54
    check-cast p3, Ljava/lang/Integer;

    .line 55
    .line 56
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 57
    .line 58
    .line 59
    move-result p3

    .line 60
    const-string v0, "$this$GradientBox"

    .line 61
    .line 62
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    and-int/lit8 p1, p3, 0x11

    .line 66
    .line 67
    const/16 v0, 0x10

    .line 68
    .line 69
    const/4 v1, 0x1

    .line 70
    if-eq p1, v0, :cond_0

    .line 71
    .line 72
    move p1, v1

    .line 73
    goto :goto_0

    .line 74
    :cond_0
    const/4 p1, 0x0

    .line 75
    :goto_0
    and-int/2addr p3, v1

    .line 76
    move-object v5, p2

    .line 77
    check-cast v5, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {v5, p3, p1}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_1

    .line 84
    .line 85
    const p1, 0x7f1211c6

    .line 86
    .line 87
    .line 88
    invoke-static {v5, p1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 93
    .line 94
    invoke-static {p2, p1}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    iget-object p1, p0, Lz70/c0;->f:Ly70/q1;

    .line 99
    .line 100
    iget-boolean v7, p1, Ly70/q1;->r:Z

    .line 101
    .line 102
    const/4 v0, 0x0

    .line 103
    const/16 v1, 0x28

    .line 104
    .line 105
    iget-object v2, p0, Lz70/c0;->e:Lay0/a;

    .line 106
    .line 107
    const/4 v3, 0x0

    .line 108
    const/4 v8, 0x0

    .line 109
    invoke-static/range {v0 .. v8}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 114
    .line 115
    .line 116
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
