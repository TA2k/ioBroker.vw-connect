.class public final synthetic Li40/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/u1;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/u1;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li40/j1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/j1;->e:Lh40/u1;

    iput-object p2, p0, Li40/j1;->f:Lay0/a;

    iput-object p3, p0, Li40/j1;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/u1;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Li40/j1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/j1;->e:Lh40/u1;

    iput-object p2, p0, Li40/j1;->f:Lay0/a;

    iput-object p3, p0, Li40/j1;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Li40/j1;->d:I

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
    iget-object v0, p0, Li40/j1;->e:Lh40/u1;

    .line 19
    .line 20
    iget-object v1, p0, Li40/j1;->f:Lay0/a;

    .line 21
    .line 22
    iget-object p0, p0, Li40/j1;->g:Lay0/a;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Li40/l1;->a(Lh40/u1;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    and-int/lit8 v0, p2, 0x3

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    const/4 v2, 0x1

    .line 38
    if-eq v0, v1, :cond_0

    .line 39
    .line 40
    move v0, v2

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v0, 0x0

    .line 43
    :goto_0
    and-int/2addr p2, v2

    .line 44
    move-object v5, p1

    .line 45
    check-cast v5, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    if-eqz p1, :cond_1

    .line 52
    .line 53
    new-instance p1, La71/a1;

    .line 54
    .line 55
    const/16 p2, 0x1a

    .line 56
    .line 57
    iget-object v0, p0, Li40/j1;->e:Lh40/u1;

    .line 58
    .line 59
    iget-object v1, p0, Li40/j1;->f:Lay0/a;

    .line 60
    .line 61
    iget-object p0, p0, Li40/j1;->g:Lay0/a;

    .line 62
    .line 63
    invoke-direct {p1, v0, v1, p0, p2}, La71/a1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 64
    .line 65
    .line 66
    const p0, -0x1f041bbe

    .line 67
    .line 68
    .line 69
    invoke-static {p0, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    const/16 v6, 0x180

    .line 74
    .line 75
    const/4 v7, 0x3

    .line 76
    const/4 v1, 0x0

    .line 77
    const-wide/16 v2, 0x0

    .line 78
    .line 79
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 84
    .line 85
    .line 86
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
