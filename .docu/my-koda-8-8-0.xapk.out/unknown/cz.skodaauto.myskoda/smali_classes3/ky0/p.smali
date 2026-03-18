.class public final Lky0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lky0/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lky0/p;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget v0, p0, Lky0/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/collection/d1;

    .line 7
    .line 8
    iget-object p0, p0, Lky0/p;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Luz0/x;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Landroidx/collection/d1;-><init>(Luz0/x;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Lky0/b;

    .line 17
    .line 18
    iget-object p0, p0, Lky0/p;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lay0/a;

    .line 21
    .line 22
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Ljava/util/Iterator;

    .line 27
    .line 28
    invoke-direct {v0, p0}, Lky0/b;-><init>(Ljava/util/Iterator;)V

    .line 29
    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    iget-object p0, p0, Lky0/p;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, [Ljava/lang/Object;

    .line 35
    .line 36
    invoke-static {p0}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_2
    iget-object p0, p0, Lky0/p;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lky0/j;

    .line 44
    .line 45
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
