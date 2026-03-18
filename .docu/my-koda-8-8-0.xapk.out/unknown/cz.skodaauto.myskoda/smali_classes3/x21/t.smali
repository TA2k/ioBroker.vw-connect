.class public final Lx21/t;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Landroidx/compose/foundation/lazy/a;

.field public final synthetic g:Lx21/y;

.field public final synthetic h:Ljava/lang/Integer;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:Z

.field public final synthetic k:Lx2/s;

.field public final synthetic l:Lt2/b;

.field public final synthetic m:I


# direct methods
.method public constructor <init>(Landroidx/compose/foundation/lazy/a;Lx21/y;Ljava/lang/Integer;Lx2/s;ZLx2/s;Lt2/b;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx21/t;->f:Landroidx/compose/foundation/lazy/a;

    .line 2
    .line 3
    iput-object p2, p0, Lx21/t;->g:Lx21/y;

    .line 4
    .line 5
    iput-object p3, p0, Lx21/t;->h:Ljava/lang/Integer;

    .line 6
    .line 7
    iput-object p4, p0, Lx21/t;->i:Lx2/s;

    .line 8
    .line 9
    iput-boolean p5, p0, Lx21/t;->j:Z

    .line 10
    .line 11
    iput-object p6, p0, Lx21/t;->k:Lx2/s;

    .line 12
    .line 13
    iput-object p7, p0, Lx21/t;->l:Lt2/b;

    .line 14
    .line 15
    iput p8, p0, Lx21/t;->m:I

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

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
    iget p1, p0, Lx21/t;->m:I

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
    iget-object v0, p0, Lx21/t;->f:Landroidx/compose/foundation/lazy/a;

    .line 18
    .line 19
    iget-object v1, p0, Lx21/t;->g:Lx21/y;

    .line 20
    .line 21
    iget-object v2, p0, Lx21/t;->h:Ljava/lang/Integer;

    .line 22
    .line 23
    iget-object v3, p0, Lx21/t;->i:Lx2/s;

    .line 24
    .line 25
    iget-boolean v4, p0, Lx21/t;->j:Z

    .line 26
    .line 27
    iget-object v5, p0, Lx21/t;->k:Lx2/s;

    .line 28
    .line 29
    iget-object v6, p0, Lx21/t;->l:Lt2/b;

    .line 30
    .line 31
    invoke-static/range {v0 .. v8}, Llp/de;->a(Landroidx/compose/foundation/lazy/a;Lx21/y;Ljava/lang/Integer;Lx2/s;ZLx2/s;Lt2/b;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0
.end method
