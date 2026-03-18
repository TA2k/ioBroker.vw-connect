.class public final synthetic Li91/z2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lx2/s;

.field public final synthetic g:I

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(IIIILx2/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li91/z2;->d:I

    .line 5
    .line 6
    iput p2, p0, Li91/z2;->e:I

    .line 7
    .line 8
    iput-object p5, p0, Li91/z2;->f:Lx2/s;

    .line 9
    .line 10
    iput p3, p0, Li91/z2;->g:I

    .line 11
    .line 12
    iput p4, p0, Li91/z2;->h:I

    .line 13
    .line 14
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
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget p1, p0, Li91/z2;->g:I

    .line 10
    .line 11
    or-int/lit8 p1, p1, 0x1

    .line 12
    .line 13
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    iget v0, p0, Li91/z2;->d:I

    .line 18
    .line 19
    iget v1, p0, Li91/z2;->e:I

    .line 20
    .line 21
    iget v3, p0, Li91/z2;->h:I

    .line 22
    .line 23
    iget-object v5, p0, Li91/z2;->f:Lx2/s;

    .line 24
    .line 25
    invoke-static/range {v0 .. v5}, Li91/a3;->a(IIIILl2/o;Lx2/s;)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
