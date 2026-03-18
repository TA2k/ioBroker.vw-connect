.class public final Lb1/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lc1/w1;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:Lt2/b;

.field public final synthetic k:I

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lc1/w1;Lay0/k;Lx2/s;Lb1/t0;Lb1/u0;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb1/j;->f:I

    .line 1
    iput-object p1, p0, Lb1/j;->g:Lc1/w1;

    iput-object p2, p0, Lb1/j;->h:Lay0/k;

    iput-object p3, p0, Lb1/j;->i:Lx2/s;

    iput-object p4, p0, Lb1/j;->l:Ljava/lang/Object;

    iput-object p5, p0, Lb1/j;->m:Ljava/lang/Object;

    iput-object p6, p0, Lb1/j;->j:Lt2/b;

    iput p7, p0, Lb1/j;->k:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lc1/w1;Lx2/s;Lay0/k;Lx2/e;Lay0/k;Lt2/b;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb1/j;->f:I

    .line 2
    iput-object p1, p0, Lb1/j;->g:Lc1/w1;

    iput-object p2, p0, Lb1/j;->i:Lx2/s;

    iput-object p3, p0, Lb1/j;->h:Lay0/k;

    iput-object p4, p0, Lb1/j;->m:Ljava/lang/Object;

    iput-object p5, p0, Lb1/j;->l:Ljava/lang/Object;

    iput-object p6, p0, Lb1/j;->j:Lt2/b;

    iput p7, p0, Lb1/j;->k:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lb1/j;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lb1/j;->l:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v4, p1

    .line 17
    check-cast v4, Lb1/t0;

    .line 18
    .line 19
    iget-object p1, p0, Lb1/j;->m:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v5, p1

    .line 22
    check-cast v5, Lb1/u0;

    .line 23
    .line 24
    iget p1, p0, Lb1/j;->k:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    iget-object v1, p0, Lb1/j;->g:Lc1/w1;

    .line 33
    .line 34
    iget-object v2, p0, Lb1/j;->h:Lay0/k;

    .line 35
    .line 36
    iget-object v3, p0, Lb1/j;->i:Lx2/s;

    .line 37
    .line 38
    iget-object v6, p0, Lb1/j;->j:Lt2/b;

    .line 39
    .line 40
    invoke-static/range {v1 .. v8}, Landroidx/compose/animation/b;->f(Lc1/w1;Lay0/k;Lx2/s;Lb1/t0;Lb1/u0;Lt2/b;Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_0
    move-object v6, p1

    .line 47
    check-cast v6, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Number;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lb1/j;->m:Ljava/lang/Object;

    .line 55
    .line 56
    move-object v3, p1

    .line 57
    check-cast v3, Lx2/e;

    .line 58
    .line 59
    iget-object p1, p0, Lb1/j;->l:Ljava/lang/Object;

    .line 60
    .line 61
    move-object v4, p1

    .line 62
    check-cast v4, Lay0/k;

    .line 63
    .line 64
    iget p1, p0, Lb1/j;->k:I

    .line 65
    .line 66
    or-int/lit8 p1, p1, 0x1

    .line 67
    .line 68
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 69
    .line 70
    .line 71
    move-result v7

    .line 72
    iget-object v0, p0, Lb1/j;->g:Lc1/w1;

    .line 73
    .line 74
    iget-object v1, p0, Lb1/j;->i:Lx2/s;

    .line 75
    .line 76
    iget-object v2, p0, Lb1/j;->h:Lay0/k;

    .line 77
    .line 78
    iget-object v5, p0, Lb1/j;->j:Lt2/b;

    .line 79
    .line 80
    invoke-static/range {v0 .. v7}, Landroidx/compose/animation/a;->a(Lc1/w1;Lx2/s;Lay0/k;Lx2/e;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
