.class public final Lf7/r;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Lay0/n;


# direct methods
.method public constructor <init>(IILt2/b;Lvv/m0;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lf7/r;->f:I

    .line 1
    iput-object p4, p0, Lf7/r;->i:Ljava/lang/Object;

    iput p1, p0, Lf7/r;->g:I

    iput-object p3, p0, Lf7/r;->j:Lay0/n;

    iput p2, p0, Lf7/r;->h:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lx2/s;Lay0/n;II)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf7/r;->f:I

    .line 2
    iput-object p1, p0, Lf7/r;->i:Ljava/lang/Object;

    iput-object p2, p0, Lf7/r;->j:Lay0/n;

    iput p3, p0, Lf7/r;->g:I

    iput p4, p0, Lf7/r;->h:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Ly6/q;ILt2/b;II)V
    .locals 0

    const/4 p4, 0x0

    iput p4, p0, Lf7/r;->f:I

    .line 3
    iput-object p1, p0, Lf7/r;->i:Ljava/lang/Object;

    iput p2, p0, Lf7/r;->g:I

    iput-object p3, p0, Lf7/r;->j:Lay0/n;

    iput p5, p0, Lf7/r;->h:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lf7/r;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    iget-object p2, p0, Lf7/r;->i:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p2, Lvv/m0;

    .line 16
    .line 17
    iget-object v0, p0, Lf7/r;->j:Lay0/n;

    .line 18
    .line 19
    check-cast v0, Lt2/b;

    .line 20
    .line 21
    iget v1, p0, Lf7/r;->h:I

    .line 22
    .line 23
    or-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    iget p0, p0, Lf7/r;->g:I

    .line 30
    .line 31
    invoke-static {p2, p0, v0, p1, v1}, Llp/fc;->a(Lvv/m0;ILt2/b;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 42
    .line 43
    .line 44
    iget-object p2, p0, Lf7/r;->i:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p2, Lx2/s;

    .line 47
    .line 48
    iget v0, p0, Lf7/r;->g:I

    .line 49
    .line 50
    or-int/lit8 v0, v0, 0x1

    .line 51
    .line 52
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget v1, p0, Lf7/r;->h:I

    .line 57
    .line 58
    iget-object p0, p0, Lf7/r;->j:Lay0/n;

    .line 59
    .line 60
    invoke-static {p2, p0, p1, v0, v1}, Lt3/k1;->c(Lx2/s;Lay0/n;Ll2/o;II)V

    .line 61
    .line 62
    .line 63
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_1
    move-object v3, p1

    .line 67
    check-cast v3, Ll2/o;

    .line 68
    .line 69
    check-cast p2, Ljava/lang/Number;

    .line 70
    .line 71
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 72
    .line 73
    .line 74
    iget-object p1, p0, Lf7/r;->i:Ljava/lang/Object;

    .line 75
    .line 76
    move-object v0, p1

    .line 77
    check-cast v0, Ly6/q;

    .line 78
    .line 79
    iget-object p1, p0, Lf7/r;->j:Lay0/n;

    .line 80
    .line 81
    move-object v2, p1

    .line 82
    check-cast v2, Lt2/b;

    .line 83
    .line 84
    const/16 v4, 0xc01

    .line 85
    .line 86
    iget v5, p0, Lf7/r;->h:I

    .line 87
    .line 88
    iget v1, p0, Lf7/r;->g:I

    .line 89
    .line 90
    invoke-static/range {v0 .. v5}, Lkp/o7;->a(Ly6/q;ILt2/b;Ll2/o;II)V

    .line 91
    .line 92
    .line 93
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
