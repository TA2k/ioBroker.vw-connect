.class public final synthetic Luz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ltz/e;ZZII)V
    .locals 0

    .line 1
    const/4 p4, 0x0

    iput p4, p0, Luz/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luz/c;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Luz/c;->e:Z

    iput-boolean p3, p0, Luz/c;->g:Z

    iput p5, p0, Luz/c;->f:I

    return-void
.end method

.method public synthetic constructor <init>(ZIZLl2/t2;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Luz/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Luz/c;->e:Z

    iput p2, p0, Luz/c;->f:I

    iput-boolean p3, p0, Luz/c;->g:Z

    iput-object p4, p0, Luz/c;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Luz/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luz/c;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ll2/t2;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    and-int/lit8 v1, p2, 0x3

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    const/4 v3, 0x1

    .line 22
    if-eq v1, v2, :cond_0

    .line 23
    .line 24
    move v1, v3

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v1, 0x0

    .line 27
    :goto_0
    and-int/2addr p2, v3

    .line 28
    move-object v7, p1

    .line 29
    check-cast v7, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v7, p2, v1}, Ll2/t;->O(IZ)Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    iget-boolean p1, p0, Luz/c;->e:Z

    .line 38
    .line 39
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    new-instance p1, Li91/u;

    .line 44
    .line 45
    iget p2, p0, Luz/c;->f:I

    .line 46
    .line 47
    iget-boolean p0, p0, Luz/c;->g:Z

    .line 48
    .line 49
    invoke-direct {p1, p2, p0, v0}, Li91/u;-><init>(IZLl2/t2;)V

    .line 50
    .line 51
    .line 52
    const p0, -0x2f1a5a6

    .line 53
    .line 54
    .line 55
    invoke-static {p0, v7, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 56
    .line 57
    .line 58
    move-result-object v6

    .line 59
    const/16 v8, 0x6c00

    .line 60
    .line 61
    const/4 v9, 0x6

    .line 62
    const/4 v3, 0x0

    .line 63
    const/4 v4, 0x0

    .line 64
    const-string v5, "starIcon"

    .line 65
    .line 66
    invoke-static/range {v2 .. v9}, Ljp/w1;->b(Ljava/lang/Object;Lx2/s;Lc1/a0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    return-object p0

    .line 76
    :pswitch_0
    iget-object v0, p0, Luz/c;->h:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v1, v0

    .line 79
    check-cast v1, Ltz/e;

    .line 80
    .line 81
    move-object v4, p1

    .line 82
    check-cast v4, Ll2/o;

    .line 83
    .line 84
    check-cast p2, Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    const/4 p1, 0x1

    .line 90
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    iget-boolean v2, p0, Luz/c;->e:Z

    .line 95
    .line 96
    iget-boolean v3, p0, Luz/c;->g:Z

    .line 97
    .line 98
    iget v6, p0, Luz/c;->f:I

    .line 99
    .line 100
    invoke-static/range {v1 .. v6}, Luz/g;->d(Ltz/e;ZZLl2/o;II)V

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
