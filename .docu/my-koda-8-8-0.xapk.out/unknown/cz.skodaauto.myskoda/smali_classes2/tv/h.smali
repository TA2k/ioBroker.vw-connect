.class public final Ltv/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public constructor <init>(IILay0/k;Lay0/k;Lx2/s;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ltv/h;->f:I

    .line 1
    iput-object p3, p0, Ltv/h;->j:Ljava/lang/Object;

    iput-object p5, p0, Ltv/h;->g:Lx2/s;

    iput-object p4, p0, Ltv/h;->k:Ljava/lang/Object;

    iput p1, p0, Ltv/h;->h:I

    iput p2, p0, Ltv/h;->i:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvv/m0;Luv/q;Lx2/s;II)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ltv/h;->f:I

    .line 2
    iput-object p1, p0, Ltv/h;->j:Ljava/lang/Object;

    iput-object p2, p0, Ltv/h;->k:Ljava/lang/Object;

    iput-object p3, p0, Ltv/h;->g:Lx2/s;

    iput p4, p0, Ltv/h;->h:I

    iput p5, p0, Ltv/h;->i:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ltv/h;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Ltv/h;->j:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v3, p1

    .line 17
    check-cast v3, Lay0/k;

    .line 18
    .line 19
    iget-object p1, p0, Ltv/h;->k:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v4, p1

    .line 22
    check-cast v4, Lay0/k;

    .line 23
    .line 24
    iget p1, p0, Ltv/h;->h:I

    .line 25
    .line 26
    or-int/lit8 p1, p1, 0x1

    .line 27
    .line 28
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    iget v2, p0, Ltv/h;->i:I

    .line 33
    .line 34
    iget-object v6, p0, Ltv/h;->g:Lx2/s;

    .line 35
    .line 36
    invoke-static/range {v1 .. v6}, Landroidx/compose/ui/viewinterop/a;->a(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    move-object v3, p1

    .line 43
    check-cast v3, Ll2/o;

    .line 44
    .line 45
    check-cast p2, Ljava/lang/Number;

    .line 46
    .line 47
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 48
    .line 49
    .line 50
    iget-object p1, p0, Ltv/h;->j:Ljava/lang/Object;

    .line 51
    .line 52
    move-object v0, p1

    .line 53
    check-cast v0, Lvv/m0;

    .line 54
    .line 55
    iget-object p1, p0, Ltv/h;->k:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v1, p1

    .line 58
    check-cast v1, Luv/q;

    .line 59
    .line 60
    iget p1, p0, Ltv/h;->h:I

    .line 61
    .line 62
    or-int/lit8 p1, p1, 0x1

    .line 63
    .line 64
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    iget v5, p0, Ltv/h;->i:I

    .line 69
    .line 70
    iget-object v2, p0, Ltv/h;->g:Lx2/s;

    .line 71
    .line 72
    invoke-static/range {v0 .. v5}, Llp/k0;->a(Lvv/m0;Luv/q;Lx2/s;Ll2/o;II)V

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
