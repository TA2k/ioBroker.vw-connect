.class public final synthetic Ln70/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/b;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Lm70/b;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    iput p1, p0, Ln70/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Ln70/b;->e:Lm70/b;

    iput-object p2, p0, Ln70/b;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/b;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Ln70/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ln70/b;->e:Lm70/b;

    iput-object p2, p0, Ln70/b;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Ln70/b;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Ln70/b;->e:Lm70/b;

    .line 19
    .line 20
    iget-object p0, p0, Ln70/b;->f:Lay0/k;

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Ln70/a;->T(Lm70/b;Lay0/k;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    and-int/lit8 v0, p2, 0x3

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    const/4 v2, 0x1

    .line 36
    if-eq v0, v1, :cond_0

    .line 37
    .line 38
    move v0, v2

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v0, 0x0

    .line 41
    :goto_0
    and-int/2addr p2, v2

    .line 42
    move-object v5, p1

    .line 43
    check-cast v5, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-eqz p1, :cond_2

    .line 50
    .line 51
    iget-object p1, p0, Ln70/b;->e:Lm70/b;

    .line 52
    .line 53
    iget-boolean p2, p1, Lm70/b;->r:Z

    .line 54
    .line 55
    if-eqz p2, :cond_1

    .line 56
    .line 57
    const p2, 0x7f12038d

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    const p2, 0x7f120222

    .line 62
    .line 63
    .line 64
    :goto_1
    new-instance v0, Li50/u;

    .line 65
    .line 66
    iget-object p0, p0, Ln70/b;->f:Lay0/k;

    .line 67
    .line 68
    invoke-direct {v0, p2, p0, p1}, Li50/u;-><init>(ILay0/k;Lm70/b;)V

    .line 69
    .line 70
    .line 71
    const p0, 0x5bb74e0b

    .line 72
    .line 73
    .line 74
    invoke-static {p0, v5, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    const/16 v6, 0x180

    .line 79
    .line 80
    const/4 v7, 0x3

    .line 81
    const/4 v1, 0x0

    .line 82
    const-wide/16 v2, 0x0

    .line 83
    .line 84
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_2
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
