.class public final Lvv/u0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:F

.field public final synthetic j:Lx2/s;

.field public final synthetic k:I


# direct methods
.method public constructor <init>(ILjava/util/List;Lay0/k;FLx2/s;I)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/u0;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lvv/u0;->g:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/u0;->h:Lay0/k;

    .line 6
    .line 7
    iput p4, p0, Lvv/u0;->i:F

    .line 8
    .line 9
    iput-object p5, p0, Lvv/u0;->j:Lx2/s;

    .line 10
    .line 11
    iput p6, p0, Lvv/u0;->k:I

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lvv/u0;->k:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v6

    .line 17
    iget v0, p0, Lvv/u0;->f:I

    .line 18
    .line 19
    iget-object v1, p0, Lvv/u0;->g:Ljava/util/List;

    .line 20
    .line 21
    iget-object v2, p0, Lvv/u0;->h:Lay0/k;

    .line 22
    .line 23
    iget v3, p0, Lvv/u0;->i:F

    .line 24
    .line 25
    iget-object v4, p0, Lvv/u0;->j:Lx2/s;

    .line 26
    .line 27
    invoke-static/range {v0 .. v6}, Llp/ic;->a(ILjava/util/List;Lay0/k;FLx2/s;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
