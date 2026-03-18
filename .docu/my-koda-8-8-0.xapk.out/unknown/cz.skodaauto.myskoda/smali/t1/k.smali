.class public final synthetic Lt1/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt1/k1;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lt1/k1;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lt1/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt1/k;->e:Lt1/k1;

    .line 4
    .line 5
    iput-object p2, p0, Lt1/k;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt1/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    iget-object p1, p0, Lt1/k;->e:Lt1/k1;

    .line 9
    .line 10
    iget-object v0, p1, Lt1/k1;->c:Lv2/o;

    .line 11
    .line 12
    iget-object p0, p0, Lt1/k;->f:Lay0/k;

    .line 13
    .line 14
    invoke-virtual {v0, p0}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    new-instance v0, Laa/t;

    .line 18
    .line 19
    const/16 v1, 0x10

    .line 20
    .line 21
    invoke-direct {v0, v1, p1, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :pswitch_0
    check-cast p1, Lg4/l0;

    .line 26
    .line 27
    iget-object v0, p0, Lt1/k;->e:Lt1/k1;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    iget-object v0, v0, Lt1/k1;->a:Ll2/j1;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    iget-object p0, p0, Lt1/k;->f:Lay0/k;

    .line 37
    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
