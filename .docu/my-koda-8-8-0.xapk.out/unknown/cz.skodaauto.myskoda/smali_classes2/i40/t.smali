.class public final synthetic Li40/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(Lay0/a;ZZ)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/t;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Li40/t;->e:Z

    iput-object p1, p0, Li40/t;->f:Lay0/a;

    iput-boolean p3, p0, Li40/t;->g:Z

    return-void
.end method

.method public synthetic constructor <init>(ZZLay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Li40/t;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li40/t;->e:Z

    iput-boolean p2, p0, Li40/t;->g:Z

    iput-object p3, p0, Li40/t;->f:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li40/t;->d:I

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
    move-object v6, p1

    .line 25
    check-cast v6, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 34
    .line 35
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    check-cast p2, Lj91/c;

    .line 40
    .line 41
    iget p2, p2, Lj91/c;->m:F

    .line 42
    .line 43
    invoke-virtual {v6, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lj91/c;

    .line 48
    .line 49
    iget p1, p1, Lj91/c;->m:F

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    const/16 v1, 0xc

    .line 53
    .line 54
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {v2, p2, p1, v0, v1}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    const/4 v7, 0x0

    .line 61
    const/16 v8, 0x10

    .line 62
    .line 63
    iget-boolean v1, p0, Li40/t;->e:Z

    .line 64
    .line 65
    iget-object v2, p0, Li40/t;->f:Lay0/a;

    .line 66
    .line 67
    iget-boolean v3, p0, Li40/t;->g:Z

    .line 68
    .line 69
    const/4 v5, 0x0

    .line 70
    invoke-static/range {v1 .. v8}, Li91/j0;->l0(ZLay0/a;ZLx2/s;Li1/l;Ll2/o;II)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 75
    .line 76
    .line 77
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    const/4 p2, 0x1

    .line 84
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    iget-boolean v0, p0, Li40/t;->e:Z

    .line 89
    .line 90
    iget-boolean v1, p0, Li40/t;->g:Z

    .line 91
    .line 92
    iget-object p0, p0, Li40/t;->f:Lay0/a;

    .line 93
    .line 94
    invoke-static {v0, v1, p0, p1, p2}, Li40/q;->f(ZZLay0/a;Ll2/o;I)V

    .line 95
    .line 96
    .line 97
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object p0

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
