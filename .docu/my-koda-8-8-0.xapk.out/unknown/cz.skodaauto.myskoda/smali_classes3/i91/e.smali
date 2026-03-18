.class public final synthetic Li91/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lt2/b;FLe1/n1;I)V
    .locals 0

    .line 1
    const/4 p4, 0x1

    iput p4, p0, Li91/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/e;->f:Ljava/lang/Object;

    iput p2, p0, Li91/e;->e:F

    iput-object p3, p0, Li91/e;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/util/ArrayList;FI)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Li91/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/e;->f:Ljava/lang/Object;

    iput-object p2, p0, Li91/e;->g:Ljava/lang/Object;

    iput p3, p0, Li91/e;->e:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Li91/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li91/e;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lt2/b;

    .line 9
    .line 10
    iget-object v1, p0, Li91/e;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Le1/n1;

    .line 13
    .line 14
    check-cast p1, Ll2/o;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    const/4 p2, 0x7

    .line 22
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    iget p0, p0, Li91/e;->e:F

    .line 27
    .line 28
    invoke-static {v0, p0, v1, p1, p2}, Lxf0/g0;->a(Lt2/b;FLe1/n1;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    iget-object v0, p0, Li91/e;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lx2/s;

    .line 37
    .line 38
    iget-object v1, p0, Li91/e;->g:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Ljava/util/ArrayList;

    .line 41
    .line 42
    check-cast p1, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const/16 p2, 0xc01

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget p0, p0, Li91/e;->e:F

    .line 56
    .line 57
    invoke-static {v0, v1, p0, p1, p2}, Li91/j0;->k(Lx2/s;Ljava/util/ArrayList;FLl2/o;I)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
