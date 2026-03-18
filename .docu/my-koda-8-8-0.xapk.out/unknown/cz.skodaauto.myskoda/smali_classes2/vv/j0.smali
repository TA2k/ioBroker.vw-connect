.class public final Lvv/j0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lvv/m0;

.field public final synthetic g:Lg4/g;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Ljava/util/Map;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lkotlin/jvm/internal/n;

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public constructor <init>(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;II)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/j0;->f:Lvv/m0;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/j0;->g:Lg4/g;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/j0;->h:Lx2/s;

    .line 6
    .line 7
    iput-object p4, p0, Lvv/j0;->i:Lay0/k;

    .line 8
    .line 9
    iput-object p5, p0, Lvv/j0;->j:Ljava/util/Map;

    .line 10
    .line 11
    iput-object p6, p0, Lvv/j0;->k:Lay0/k;

    .line 12
    .line 13
    check-cast p7, Lkotlin/jvm/internal/n;

    .line 14
    .line 15
    iput-object p7, p0, Lvv/j0;->l:Lkotlin/jvm/internal/n;

    .line 16
    .line 17
    iput p8, p0, Lvv/j0;->m:I

    .line 18
    .line 19
    iput p9, p0, Lvv/j0;->n:I

    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lvv/j0;->m:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v8

    .line 17
    iget v9, p0, Lvv/j0;->n:I

    .line 18
    .line 19
    iget-object v0, p0, Lvv/j0;->f:Lvv/m0;

    .line 20
    .line 21
    iget-object v1, p0, Lvv/j0;->g:Lg4/g;

    .line 22
    .line 23
    iget-object v2, p0, Lvv/j0;->h:Lx2/s;

    .line 24
    .line 25
    iget-object v3, p0, Lvv/j0;->i:Lay0/k;

    .line 26
    .line 27
    iget-object v4, p0, Lvv/j0;->j:Ljava/util/Map;

    .line 28
    .line 29
    iget-object v5, p0, Lvv/j0;->k:Lay0/k;

    .line 30
    .line 31
    iget-object v6, p0, Lvv/j0;->l:Lkotlin/jvm/internal/n;

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Lvv/l0;->a(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
