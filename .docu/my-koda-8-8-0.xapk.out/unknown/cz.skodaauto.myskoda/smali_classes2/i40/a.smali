.class public final synthetic Li40/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lay0/a;II)V
    .locals 0

    .line 1
    iput p4, p0, Li40/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/a;->e:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Li40/a;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li40/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x7

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Li40/a;->f:Lay0/a;

    .line 19
    .line 20
    iget-object p0, p0, Li40/a;->e:Lx2/s;

    .line 21
    .line 22
    invoke-static {p2, v0, p1, p0}, Lp61/a;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    const/4 p2, 0x1

    .line 29
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    iget-object v0, p0, Li40/a;->f:Lay0/a;

    .line 34
    .line 35
    iget-object p0, p0, Li40/a;->e:Lx2/s;

    .line 36
    .line 37
    invoke-static {p2, v0, p1, p0}, Li40/q;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
