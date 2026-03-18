.class public final Lxv/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lvv/m0;

.field public final synthetic g:Lxv/o;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Z

.field public final synthetic k:I

.field public final synthetic l:I

.field public final synthetic m:I

.field public final synthetic n:I


# direct methods
.method public constructor <init>(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIIII)V
    .locals 0

    .line 1
    iput-object p1, p0, Lxv/s;->f:Lvv/m0;

    .line 2
    .line 3
    iput-object p2, p0, Lxv/s;->g:Lxv/o;

    .line 4
    .line 5
    iput-object p3, p0, Lxv/s;->h:Lx2/s;

    .line 6
    .line 7
    iput-object p4, p0, Lxv/s;->i:Lay0/k;

    .line 8
    .line 9
    iput-boolean p5, p0, Lxv/s;->j:Z

    .line 10
    .line 11
    iput p6, p0, Lxv/s;->k:I

    .line 12
    .line 13
    iput p7, p0, Lxv/s;->l:I

    .line 14
    .line 15
    iput p8, p0, Lxv/s;->m:I

    .line 16
    .line 17
    iput p9, p0, Lxv/s;->n:I

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
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
    iget p1, p0, Lxv/s;->m:I

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
    iget v9, p0, Lxv/s;->n:I

    .line 18
    .line 19
    iget-object v0, p0, Lxv/s;->f:Lvv/m0;

    .line 20
    .line 21
    iget-object v1, p0, Lxv/s;->g:Lxv/o;

    .line 22
    .line 23
    iget-object v2, p0, Lxv/s;->h:Lx2/s;

    .line 24
    .line 25
    iget-object v3, p0, Lxv/s;->i:Lay0/k;

    .line 26
    .line 27
    iget-boolean v4, p0, Lxv/s;->j:Z

    .line 28
    .line 29
    iget v5, p0, Lxv/s;->k:I

    .line 30
    .line 31
    iget v6, p0, Lxv/s;->l:I

    .line 32
    .line 33
    invoke-static/range {v0 .. v9}, Llp/ff;->a(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIILl2/o;II)V

    .line 34
    .line 35
    .line 36
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0
.end method
