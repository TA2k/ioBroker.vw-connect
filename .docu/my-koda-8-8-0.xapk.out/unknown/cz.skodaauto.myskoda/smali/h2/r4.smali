.class public final synthetic Lh2/r4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:F

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(Lx2/s;FJI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/r4;->d:Lx2/s;

    .line 5
    .line 6
    iput p2, p0, Lh2/r4;->e:F

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/r4;->f:J

    .line 9
    .line 10
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
    const/16 p1, 0x31

    .line 10
    .line 11
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    iget-object v0, p0, Lh2/r4;->d:Lx2/s;

    .line 16
    .line 17
    iget v1, p0, Lh2/r4;->e:F

    .line 18
    .line 19
    iget-wide v2, p0, Lh2/r4;->f:J

    .line 20
    .line 21
    invoke-static/range {v0 .. v5}, Lh2/r;->g(Lx2/s;FJLl2/o;I)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method
