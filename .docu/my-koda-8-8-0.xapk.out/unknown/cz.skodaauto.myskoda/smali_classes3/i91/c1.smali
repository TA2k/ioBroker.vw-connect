.class public final synthetic Li91/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F


# direct methods
.method public synthetic constructor <init>(F)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/c1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li91/c1;->e:F

    return-void
.end method

.method public synthetic constructor <init>(IF)V
    .locals 0

    .line 2
    const/4 p1, 0x1

    iput p1, p0, Li91/c1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Li91/c1;->e:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li91/c1;->d:I

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
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget p0, p0, Li91/c1;->e:F

    .line 19
    .line 20
    invoke-static {p0, p2, p1}, Lxk0/x;->b(FILl2/o;)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    check-cast p1, Ll2/t;

    .line 27
    .line 28
    const p2, 0x64cf40cb

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    const/4 p2, 0x0

    .line 35
    invoke-virtual {p1, p2}, Ll2/t;->q(Z)V

    .line 36
    .line 37
    .line 38
    new-instance p1, Lt4/f;

    .line 39
    .line 40
    iget p0, p0, Li91/c1;->e:F

    .line 41
    .line 42
    invoke-direct {p1, p0}, Lt4/f;-><init>(F)V

    .line 43
    .line 44
    .line 45
    return-object p1

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
