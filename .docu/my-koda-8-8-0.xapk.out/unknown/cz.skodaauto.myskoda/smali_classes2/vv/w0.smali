.class public final Lvv/w0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lvv/m0;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:I


# direct methods
.method public constructor <init>(Lvv/m0;Lx2/s;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/w0;->f:Lvv/m0;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/w0;->g:Lx2/s;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/w0;->h:Lay0/k;

    .line 6
    .line 7
    iput-object p4, p0, Lvv/w0;->i:Lay0/k;

    .line 8
    .line 9
    iput p5, p0, Lvv/w0;->j:I

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lvv/w0;->j:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    iget-object v0, p0, Lvv/w0;->f:Lvv/m0;

    .line 18
    .line 19
    iget-object v1, p0, Lvv/w0;->g:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Lvv/w0;->h:Lay0/k;

    .line 22
    .line 23
    iget-object v3, p0, Lvv/w0;->i:Lay0/k;

    .line 24
    .line 25
    invoke-static/range {v0 .. v5}, Lvv/z0;->a(Lvv/m0;Lx2/s;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
