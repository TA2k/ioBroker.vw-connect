.class public final synthetic Li40/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/q1;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/f1;->e:Lh40/q1;

    iput-object p2, p0, Li40/f1;->f:Lay0/a;

    iput-object p3, p0, Li40/f1;->g:Lay0/a;

    iput-object p4, p0, Li40/f1;->h:Lay0/a;

    iput-object p5, p0, Li40/f1;->i:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p6, 0x0

    iput p6, p0, Li40/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/f1;->e:Lh40/q1;

    iput-object p2, p0, Li40/f1;->f:Lay0/a;

    iput-object p3, p0, Li40/f1;->g:Lay0/a;

    iput-object p4, p0, Li40/f1;->h:Lay0/a;

    iput-object p5, p0, Li40/f1;->i:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Li40/f1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

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
    move-object v5, p1

    .line 25
    check-cast v5, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    new-instance v6, Lb50/d;

    .line 34
    .line 35
    const/16 v12, 0x8

    .line 36
    .line 37
    iget-object v7, p0, Li40/f1;->e:Lh40/q1;

    .line 38
    .line 39
    iget-object v8, p0, Li40/f1;->f:Lay0/a;

    .line 40
    .line 41
    iget-object v9, p0, Li40/f1;->g:Lay0/a;

    .line 42
    .line 43
    iget-object v10, p0, Li40/f1;->h:Lay0/a;

    .line 44
    .line 45
    iget-object v11, p0, Li40/f1;->i:Lay0/a;

    .line 46
    .line 47
    invoke-direct/range {v6 .. v12}, Lb50/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 48
    .line 49
    .line 50
    const p0, 0xa47277

    .line 51
    .line 52
    .line 53
    invoke-static {p0, v5, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    const/16 v6, 0x180

    .line 58
    .line 59
    const/4 v7, 0x3

    .line 60
    const/4 v1, 0x0

    .line 61
    const-wide/16 v2, 0x0

    .line 62
    .line 63
    invoke-static/range {v1 .. v7}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 68
    .line 69
    .line 70
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0

    .line 73
    :pswitch_0
    move-object v5, p1

    .line 74
    check-cast v5, Ll2/o;

    .line 75
    .line 76
    check-cast p2, Ljava/lang/Integer;

    .line 77
    .line 78
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    const/4 p1, 0x1

    .line 82
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 83
    .line 84
    .line 85
    move-result v6

    .line 86
    iget-object v0, p0, Li40/f1;->e:Lh40/q1;

    .line 87
    .line 88
    iget-object v1, p0, Li40/f1;->f:Lay0/a;

    .line 89
    .line 90
    iget-object v2, p0, Li40/f1;->g:Lay0/a;

    .line 91
    .line 92
    iget-object v3, p0, Li40/f1;->h:Lay0/a;

    .line 93
    .line 94
    iget-object v4, p0, Li40/f1;->i:Lay0/a;

    .line 95
    .line 96
    invoke-static/range {v0 .. v6}, Li40/q;->b(Lh40/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
