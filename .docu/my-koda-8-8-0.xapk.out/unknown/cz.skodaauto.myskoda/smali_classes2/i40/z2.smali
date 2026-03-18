.class public final synthetic Li40/z2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lg4/p0;

.field public final synthetic g:Lg4/p0;

.field public final synthetic h:I

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(ILx2/s;Lg4/p0;Lg4/p0;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li40/z2;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Li40/z2;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Li40/z2;->f:Lg4/p0;

    .line 9
    .line 10
    iput-object p4, p0, Li40/z2;->g:Lg4/p0;

    .line 11
    .line 12
    iput p5, p0, Li40/z2;->h:I

    .line 13
    .line 14
    iput p6, p0, Li40/z2;->i:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li40/z2;->h:I

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
    iget v0, p0, Li40/z2;->d:I

    .line 18
    .line 19
    iget-object v1, p0, Li40/z2;->e:Lx2/s;

    .line 20
    .line 21
    iget-object v2, p0, Li40/z2;->f:Lg4/p0;

    .line 22
    .line 23
    iget-object v3, p0, Li40/z2;->g:Lg4/p0;

    .line 24
    .line 25
    iget v6, p0, Li40/z2;->i:I

    .line 26
    .line 27
    invoke-static/range {v0 .. v6}, Li40/l1;->b0(ILx2/s;Lg4/p0;Lg4/p0;Ll2/o;II)V

    .line 28
    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0
.end method
