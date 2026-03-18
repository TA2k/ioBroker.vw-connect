.class public final synthetic Li40/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Lx2/s;


# direct methods
.method public synthetic constructor <init>(JLx2/s;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p4, p0, Li40/h;->d:I

    .line 5
    .line 6
    iput-wide p1, p0, Li40/h;->e:J

    .line 7
    .line 8
    iput-object p3, p0, Li40/h;->f:Lx2/s;

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
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    iget v0, p0, Li40/h;->d:I

    .line 15
    .line 16
    iget-wide v2, p0, Li40/h;->e:J

    .line 17
    .line 18
    iget-object v5, p0, Li40/h;->f:Lx2/s;

    .line 19
    .line 20
    invoke-static/range {v0 .. v5}, Li40/i;->b(IIJLl2/o;Lx2/s;)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0
.end method
