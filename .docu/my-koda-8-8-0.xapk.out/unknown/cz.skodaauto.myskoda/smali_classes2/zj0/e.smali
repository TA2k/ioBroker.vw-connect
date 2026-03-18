.class public final synthetic Lzj0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Luu/g;

.field public final synthetic e:F

.field public final synthetic f:Lxj0/y;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Luu/g;FLxj0/y;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzj0/e;->d:Luu/g;

    .line 5
    .line 6
    iput p2, p0, Lzj0/e;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lzj0/e;->f:Lxj0/y;

    .line 9
    .line 10
    iput-object p4, p0, Lzj0/e;->g:Lay0/a;

    .line 11
    .line 12
    iput p5, p0, Lzj0/e;->h:I

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 7
    .line 8
    .line 9
    iget p1, p0, Lzj0/e;->h:I

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
    iget-object v0, p0, Lzj0/e;->d:Luu/g;

    .line 18
    .line 19
    iget v1, p0, Lzj0/e;->e:F

    .line 20
    .line 21
    iget-object v2, p0, Lzj0/e;->f:Lxj0/y;

    .line 22
    .line 23
    iget-object v3, p0, Lzj0/e;->g:Lay0/a;

    .line 24
    .line 25
    invoke-static/range {v0 .. v5}, Lzj0/j;->m(Luu/g;FLxj0/y;Lay0/a;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0
.end method
